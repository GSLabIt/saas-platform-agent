"""WebSocket connection to the control plane's gateway.

Protocol:
  Agent connects outbound: wss://<platform>/agent/ws
  Token sent as HTTP header on the upgrade request:
    Authorization: Bearer <TOKEN>

  Gateway → Agent (standard):
    {"type": "hello", "server_id": N, "version": "1.0"}
    {"type": "ping"}
    {"type": "request", "id": "uuid", "method": "...", "params": {...}}

  Agent → Gateway (standard):
    {"type": "ready", "docker_version": "27.x"}
    {"type": "pong"}
    {"type": "response", "id": "uuid", "result": {...}}
    {"type": "response", "id": "uuid", "error": {"code": -1, "message": "..."}}

  PTY streaming extension:
    Gateway → Agent:
      {"type": "request", ..., "method": "docker.container.exec_pty",
       "params": {"name_or_id": "...", "stream_id": "...",
                  "cols": N, "rows": N}}
      {"type": "stream_stdin",  "stream_id": "...", "data": "<b64>"}
      {"type": "stream_resize", "stream_id": "...", "cols": N, "rows": N}
      {"type": "stream_close",  "stream_id": "..."}

    Agent → Gateway:
      {"type": "response", "id": "uuid", "result": {"ok": true}}  ← ack
      {"type": "stream_data",   "stream_id": "...", "data": "<base64>"}
      {"type": "stream_closed", "stream_id": "...", "exit_code": N}

  Host shell PTY extension (berth-platform's server-level terminal for
  agent-connected servers — routers/terminal.py::server_terminal): same
  stream_id-keyed queue/dispatch machinery and message shapes as the
  container PTY above (stream_stdin/stream_resize/stream_close/stream_data/
  stream_closed, verbatim), only the start method differs — no
  name_or_id, since it isn't scoped to any container:
      {"type": "request", ..., "method": "saas.host.exec_pty",
       "params": {"stream_id": "...", "cols": N, "rows": N}}

  TCP tunnel extension (DB tunnel — berth-platform's db_tunnel_manager.py):
    same stream_id-keyed queue/dispatch machinery as PTY above, reusing
    stream_stdin/stream_close/stream_data/stream_closed verbatim — no PTY
    semantics (no resize), plus two new control messages for flow control
    (a dropped chunk desyncs a wire protocol permanently, unlike PTY output
    where it's just a cosmetic glitch — see agent_registry.py's
    _STREAM_HIGH_WATERMARK on the control-plane side for why):
    Gateway → Agent:
      {"type": "request", ..., "method": "tcp.tunnel.open",
       "params": {"target_host": "...", "target_port": N, "stream_id": "..."}}
      {"type": "stream_pause",  "stream_id": "..."}  ← stop reading target_host
      {"type": "stream_resume", "stream_id": "..."}  ← resume reading
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import functools
import json
import logging
import queue
import threading
from contextlib import suppress

import websockets
import websockets.exceptions

from agent.executor import Executor
from agent.security import redact as _redact

logger = logging.getLogger(__name__)

# Short commands (docker.*, fs.*, saas.*) run here. PTY / host-shell
# sessions get their own pool so a handful of long-lived interactive
# sessions can't starve command dispatch (each PTY holds a worker for its
# whole lifetime).
_THREAD_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="agent-cmd"
)
_PTY_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=16, thread_name_prefix="agent-pty"
)

# Admission limits per connection — a burst of requests can't create
# unbounded asyncio tasks / streams / subprocesses.
_MAX_CONCURRENT_COMMANDS = 32
_MAX_ACTIVE_STREAMS = 64
_POSTGRES_RECREATE_TIMEOUT = 360.0
# Ceiling on WS->target bytes buffered for one tcp.tunnel stream while the
# target is draining slower than the control plane pushes. Legit traffic
# (a \copy burst) never sits this deep; a stuck/hostile peer gets the
# stream closed cleanly instead of OOMing the agent. Closing (not
# dropping) keeps the wire protocol from desyncing.
_TUNNEL_MAX_BUFFERED_BYTES = 4 * 1024 * 1024
_SESSION_MAX_BUFFERED_BYTES = 16 * 1024 * 1024
_PTY_START_TIMEOUT = 10.0


async def run(
    gateway_url: str,
    token: str,
    executor: Executor,
    max_backoff: int = 60,
    command_timeout: float = 120.0,
    ssl_verify: bool = True,
) -> None:
    """Connect to the gateway and handle messages, reconnecting on failure."""
    import ssl as _ssl

    backoff = 2

    ssl_ctx: _ssl.SSLContext | bool | None = None
    if gateway_url.startswith("wss://"):
        if ssl_verify:
            ssl_ctx = _ssl.create_default_context()
        else:
            ssl_ctx = _ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = _ssl.CERT_NONE

    while True:
        try:
            logger.info("Connecting to gateway: %s", gateway_url)
            async with websockets.connect(
                gateway_url,
                ssl=ssl_ctx,
                max_size=16 * 1024 * 1024,
                ping_interval=30,
                ping_timeout=10,
                additional_headers={"Authorization": f"Bearer {token}"},
            ) as ws:
                backoff = 2
                await _handle_session(ws, executor, command_timeout)

        except websockets.exceptions.InvalidStatus as exc:
            code = exc.response.status_code
            if code in (4401, 4409):
                logger.error(
                    "Gateway rejected connection (code %s) — check your token",
                    code,
                )
                await asyncio.sleep(backoff)
            else:
                logger.warning(
                    "Gateway returned HTTP %s, retrying in %ds", code, backoff
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

        except (
            websockets.exceptions.ConnectionClosed,
            ConnectionRefusedError,
            OSError,
        ) as exc:
            logger.warning(
                "Disconnected (%s), reconnecting in %ds...",
                _redact(str(exc)),
                backoff,
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

        except Exception as exc:
            logger.error(
                "Unexpected error (%s): %s — retrying in %ds",
                type(exc).__name__,
                _redact(str(exc)),
                backoff,
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)


class _Session:
    """Per-connection state. Everything spawned here is tracked so it can be
    torn down when the WebSocket closes — otherwise PTYs, tunnels and their
    threads/subprocesses outlive the authenticated session and pile up
    across reconnects."""

    def __init__(self) -> None:
        # stream_id → asyncio.Queue of control tuples (stdin/resize/pause/
        # resume/close), payload-agnostic (see module docstring).
        self.streams: dict[str, asyncio.Queue] = {}
        # stream_id → threading.Event shared with a PTY's blocking thread so
        # the session finally can actually stop it (cancelling the awaiting
        # asyncio task does NOT interrupt run_in_executor).
        self.stop_events: dict[str, threading.Event] = {}
        # stream_id → bytes currently buffered WS→target (tcp.tunnel only in
        # practice; harmless for PTY stdin, which never gets near the cap).
        self.stream_bytes: dict[str, int] = {}
        self.total_stream_bytes = 0
        self.tasks: set[asyncio.Task] = set()
        # Submitted command executor futures, including work whose protocol
        # response has timed out. Checked before submission so the executor's
        # own unbounded queue remains bounded in practice.
        self.pending_commands = 0
        # Streams past their buffered-byte ceiling — later frames for them
        # are dropped instead of piling more onto the queue.
        self.closing_streams: set[str] = set()

    def spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def close(self) -> None:
        for event in list(self.stop_events.values()):
            event.set()
        for q in list(self.streams.values()):
            with suppress(asyncio.QueueFull):
                q.put_nowait(("close",))
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)


async def _handle_session(
    ws: websockets.WebSocketClientProtocol,
    executor: Executor,
    command_timeout: float,
) -> None:
    """Handle a single connected session until the WebSocket closes."""
    sess = _Session()
    try:
        async for raw in ws:
            try:
                await _dispatch_message(
                    ws, executor, command_timeout, sess, raw
                )
            except Exception as exc:
                # A malformed frame must never take down the session — one
                # bad message from the control plane would otherwise force
                # a full reconnect and orphan every in-flight stream.
                logger.error(
                    "Error handling message (%s): %s; session continues",
                    type(exc).__name__,
                    _redact(str(exc)),
                )
    finally:
        await sess.close()


def _stream_ctrl(sess: _Session, message: dict, item: tuple) -> None:
    stream_id = message.get("stream_id", "")
    q = sess.streams.get(stream_id)
    if q is None or stream_id in sess.closing_streams:
        return
    if item and item[0] == "data":
        n = len(item[1])
        buffered = sess.stream_bytes.get(stream_id, 0) + n
        total_buffered = sess.total_stream_bytes + n
        if (
            buffered > _TUNNEL_MAX_BUFFERED_BYTES
            or total_buffered > _SESSION_MAX_BUFFERED_BYTES
        ):
            logger.warning(
                "Stream %s exceeded buffered-byte cap — closing", stream_id
            )
            # Enqueue the close once, then stop accepting frames for this
            # stream entirely — otherwise every later stream_stdin frame
            # would append another close tuple and the queue grows
            # unbounded despite the byte ceiling.
            sess.closing_streams.add(stream_id)
            with suppress(asyncio.QueueFull):
                q.put_nowait(("close",))
            return
        try:
            q.put_nowait(item)
        except asyncio.QueueFull:
            return
        sess.stream_bytes[stream_id] = buffered
        sess.total_stream_bytes = total_buffered
        return
    with suppress(asyncio.QueueFull):
        q.put_nowait(item)


def _drain_stream_bytes(sess: _Session, stream_id: str, count: int) -> None:
    drained = min(count, sess.stream_bytes.get(stream_id, 0))
    if stream_id in sess.stream_bytes:
        sess.stream_bytes[stream_id] -= drained
    sess.total_stream_bytes = max(0, sess.total_stream_bytes - drained)


async def _dispatch_message(
    ws: websockets.WebSocketClientProtocol,
    executor: Executor,
    command_timeout: float,
    sess: _Session,
    raw: str | bytes,
) -> None:
    try:
        message = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Received non-JSON message, ignoring")
        return
    if not isinstance(message, dict):
        logger.warning("Received non-object JSON message, ignoring")
        return

    msg_type = message.get("type")

    if msg_type == "hello":
        server_id = message.get("server_id")
        logger.info("Connected to gateway (server_id=%s)", server_id)
        await ws.send(
            _json(
                {
                    "type": "ready",
                    "docker_version": executor.docker_version(),
                }
            )
        )

    elif msg_type == "ping":
        await ws.send(_json({"type": "pong"}))

    elif msg_type == "stream_stdin":
        try:
            data = base64.b64decode(message.get("data", ""), validate=True)
        except Exception:
            logger.warning("stream_stdin with invalid base64, ignoring")
            return
        _stream_ctrl(sess, message, ("data", data))

    elif msg_type == "stream_resize":
        _stream_ctrl(
            sess,
            message,
            (
                "resize",
                int(message.get("cols", 80) or 80),
                int(message.get("rows", 24) or 24),
            ),
        )

    elif msg_type == "stream_pause":
        _stream_ctrl(sess, message, ("pause",))

    elif msg_type == "stream_resume":
        _stream_ctrl(sess, message, ("resume",))

    elif msg_type == "stream_close":
        _stream_ctrl(sess, message, ("close",))

    elif msg_type == "request":
        request_id = message.get("id", "")
        method = message.get("method", "")
        params = message.get("params", {})
        # The control plane sends a per-command timeout (AgentHttpProxy /
        # AgentConnection.send_command). Honour it when it exceeds the
        # session default — a fresh-server saas.instance.provision does a
        # multi-GB image pull that never fits in 120s. Clamped to 30 min.
        try:
            _req_t = float(message.get("timeout") or 0)
        except (TypeError, ValueError):
            _req_t = 0.0
        effective_timeout = min(max(command_timeout, _req_t), 1800.0)
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            await ws.send(
                _json(
                    {
                        "type": "response",
                        "id": request_id,
                        "error": {
                            "code": -32602,
                            "message": "params must be an object",
                        },
                    }
                )
            )
            return

        stream_queue: asyncio.Queue | None = None
        if method in {
            "docker.container.exec_pty",
            "saas.host.exec_pty",
            "tcp.tunnel.open",
        }:
            stream_id = params.get("stream_id", "")
            stream_queue = asyncio.Queue(
                maxsize=0 if method == "tcp.tunnel.open" else 256
            )
            err = _claim_stream(sess, stream_id, stream_queue)
            if err:
                await ws.send(
                    _json(
                        {
                            "type": "response",
                            "id": request_id,
                            "error": {"code": -32602, "message": err},
                        }
                    )
                )
                return

        if method == "docker.container.exec_pty":
            assert stream_queue is not None
            sess.spawn(
                _handle_pty_session(
                    ws,
                    executor,
                    request_id,
                    params,
                    sess,
                    stream_queue,
                )
            )
        elif method == "saas.host.exec_pty":
            assert stream_queue is not None
            sess.spawn(
                _handle_host_pty_session(
                    ws,
                    executor,
                    request_id,
                    params,
                    sess,
                    stream_queue,
                )
            )
        elif method == "tcp.tunnel.open":
            assert stream_queue is not None
            sess.spawn(
                _handle_tcp_tunnel_session(
                    ws, executor, request_id, params, sess, stream_queue
                )
            )
        elif sess.pending_commands >= _MAX_CONCURRENT_COMMANDS:
            await ws.send(
                _json(
                    {
                        "type": "response",
                        "id": request_id,
                        "error": {
                            "code": -32000,
                            "message": "too many concurrent commands",
                        },
                    }
                )
            )
        else:
            sess.pending_commands += 1
            try:
                command_future = _THREAD_POOL.submit(
                    executor.dispatch, method, params
                )
            except Exception:
                sess.pending_commands -= 1
                raise
            loop = asyncio.get_running_loop()

            def _release_command_slot(_future) -> None:
                def _decrement() -> None:
                    sess.pending_commands = max(0, sess.pending_commands - 1)

                with suppress(RuntimeError):
                    loop.call_soon_threadsafe(_decrement)

            command_future.add_done_callback(_release_command_slot)
            sess.spawn(
                _execute_and_reply(
                    ws,
                    executor,
                    request_id,
                    method,
                    params,
                    max(effective_timeout, _POSTGRES_RECREATE_TIMEOUT)
                    if method
                    in {
                        "saas.postgres.enable_pitr",
                        "saas.postgres.retune",
                    }
                    else effective_timeout,
                    command_future,
                )
            )

    else:
        logger.debug("Unknown message type %r, ignoring", msg_type)


def _claim_stream(
    sess: _Session, stream_id: str, ctrl_q: asyncio.Queue
) -> str | None:
    """Register *ctrl_q* under *stream_id*. Returns an error string if the
    id is empty or already in use (a collision would silently cross-wire
    two sessions' input), else None."""
    if not stream_id or not isinstance(stream_id, str):
        return "missing or invalid stream_id"
    if stream_id in sess.streams:
        return f"stream_id {stream_id!r} already in use"
    if len(sess.streams) >= _MAX_ACTIVE_STREAMS:
        return "too many active streams"
    sess.streams[stream_id] = ctrl_q
    sess.stream_bytes[stream_id] = 0
    return None


def _release_stream(
    sess: _Session, stream_id: str, ctrl_q: asyncio.Queue
) -> None:
    # Only remove our own mapping — a late duplicate could have replaced it.
    if sess.streams.get(stream_id) is ctrl_q:
        sess.streams.pop(stream_id, None)
        remaining = sess.stream_bytes.pop(stream_id, 0)
        sess.total_stream_bytes = max(0, sess.total_stream_bytes - remaining)
    sess.stop_events.pop(stream_id, None)
    sess.closing_streams.discard(stream_id)


def _offer(q: queue.Queue, item: tuple) -> bool:
    """Non-blocking put onto a PTY thread queue — never blocks the event
    loop (the old thread_q.put() did, indefinitely, once the queue filled).
    Drops data/resize on a full queue (same accepted tradeoff as ctrl_q's
    own maxsize=256); force-makes room for a close sentinel so teardown
    still propagates."""
    try:
        q.put_nowait(item)
        return True
    except queue.Full:
        if item and item[0] == "close":
            with suppress(queue.Empty):
                q.get_nowait()
            with suppress(queue.Full):
                q.put_nowait(("close",))
                return True
    return False


async def _run_pty_stream(
    ws: websockets.WebSocketClientProtocol,
    request_id: str,
    stream_id: str,
    sess: _Session,
    ctrl_q: asyncio.Queue,
    run_blocking,
    validate=None,
) -> None:
    """Shared machinery for both PTY kinds (container exec / host shell):
    use the stream id claimed by the dispatcher before task creation,
    bridge ctrl_q → the blocking thread,
    ack, run, and always tear down (thread stopped via the shared
    stop_event, not left to outlive the session).

    *validate* is an optional async callable run after the stream is
    claimed and before the ack — returns an error string to abort."""
    err = None
    if validate is not None:
        err = await validate()
        if err:
            _release_stream(sess, stream_id, ctrl_q)
    if err:
        await ws.send(
            _json(
                {
                    "type": "response",
                    "id": request_id,
                    "error": {"code": -32602, "message": err},
                }
            )
        )
        return

    thread_q: queue.Queue = queue.Queue(maxsize=256)
    stop_event = threading.Event()
    sess.stop_events[stream_id] = stop_event
    loop = asyncio.get_event_loop()

    async def _bridge() -> None:
        try:
            while True:
                item = await ctrl_q.get()
                offered = _offer(thread_q, item)
                if item and item[0] == "data" and not offered:
                    _drain_stream_bytes(sess, stream_id, len(item[1]))
                if item and item[0] == "close":
                    break
        except asyncio.CancelledError:
            _offer(thread_q, ("close",))

    async def _send_data(chunk: bytes) -> None:
        with suppress(Exception):
            await ws.send(
                _json(
                    {
                        "type": "stream_data",
                        "stream_id": stream_id,
                        "data": base64.b64encode(chunk).decode(),
                    }
                )
            )

    started = loop.create_future()

    def _started() -> None:
        loop.call_soon_threadsafe(
            lambda: None if started.done() else started.set_result(None)
        )

    def _data_drained(count: int) -> None:
        with suppress(RuntimeError):
            loop.call_soon_threadsafe(
                _drain_stream_bytes, sess, stream_id, count
            )

    worker = _PTY_POOL.submit(
        run_blocking,
        thread_q,
        loop,
        _send_data,
        stop_event,
        _started,
        _data_drained,
    )
    async_worker = asyncio.wrap_future(worker)
    try:
        done, _ = await asyncio.wait(
            {started, async_worker},
            timeout=_PTY_START_TIMEOUT,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if started not in done:
            if async_worker in done:
                async_worker.result()
                raise RuntimeError("PTY worker exited before startup")
            raise TimeoutError("PTY startup timed out")
    except asyncio.CancelledError:
        stop_event.set()
        _release_stream(sess, stream_id, ctrl_q)
        async_worker.add_done_callback(
            lambda future: None if future.cancelled() else future.exception()
        )
        raise
    except Exception as exc:
        stop_event.set()
        _release_stream(sess, stream_id, ctrl_q)
        if not async_worker.done():
            async_worker.add_done_callback(
                lambda future: (
                    None if future.cancelled() else future.exception()
                )
            )
        logger.error(
            "PTY startup failed for stream %s (%s): %s",
            stream_id,
            type(exc).__name__,
            _redact(str(exc)),
        )
        await ws.send(
            _json(
                {
                    "type": "response",
                    "id": request_id,
                    "error": {
                        "code": -32002,
                        "message": _redact(str(exc)),
                    },
                }
            )
        )
        return

    bridge_task: asyncio.Task | None = None
    acknowledged = False
    exit_code = 0
    try:
        await ws.send(
            _json(
                {
                    "type": "response",
                    "id": request_id,
                    "result": {"ok": True},
                }
            )
        )
        acknowledged = True
        bridge_task = asyncio.create_task(_bridge())
        exit_code = await async_worker
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "PTY session error for stream %s (%s): %s",
            stream_id,
            type(exc).__name__,
            _redact(str(exc)),
        )
        # A failed startup must not look like a clean exit(0).
        exit_code = exit_code or -1
    finally:
        stop_event.set()
        if bridge_task is not None:
            bridge_task.cancel()
            with suppress(asyncio.CancelledError):
                await bridge_task
        _release_stream(sess, stream_id, ctrl_q)
        if acknowledged:
            with suppress(Exception):
                await ws.send(
                    _json(
                        {
                            "type": "stream_closed",
                            "stream_id": stream_id,
                            "exit_code": exit_code,
                        }
                    )
                )


async def _handle_pty_session(
    ws: websockets.WebSocketClientProtocol,
    executor: Executor,
    request_id: str,
    params: dict,
    sess: _Session,
    ctrl_q: asyncio.Queue,
) -> None:
    """Start an interactive PTY session inside a container."""

    stream_id: str = params.get("stream_id", "")
    name_or_id: str = params.get("name_or_id", "")
    try:
        cols = int(params.get("cols", 220) or 220)
        rows = int(params.get("rows", 50) or 50)
    except (TypeError, ValueError) as exc:
        _release_stream(sess, stream_id, ctrl_q)
        await ws.send(
            _json(
                {
                    "type": "response",
                    "id": request_id,
                    "error": {
                        "code": -32602,
                        "message": f"Invalid PTY size: {exc}",
                    },
                }
            )
        )
        return
    loop = asyncio.get_event_loop()

    async def _validate() -> str | None:
        # Runs only after the stream is claimed (stream cap already
        # enforced) so a burst of exec_pty requests can't queue unbounded
        # container lookups in the command pool.
        exists = False
        if name_or_id:
            with suppress(Exception):
                exists = await loop.run_in_executor(
                    _THREAD_POOL, executor.container_exists, name_or_id
                )
        if not exists:
            return f"container {name_or_id!r} not found or not running"
        return None

    run_blocking = functools.partial(
        executor.run_pty_blocking, name_or_id, cols, rows
    )
    await _run_pty_stream(
        ws, request_id, stream_id, sess, ctrl_q, run_blocking, _validate
    )


async def _handle_host_pty_session(
    ws: websockets.WebSocketClientProtocol,
    executor: Executor,
    request_id: str,
    params: dict,
    sess: _Session,
    ctrl_q: asyncio.Queue,
) -> None:
    """Start a host-level shell session (not container-scoped, see
    agent/commands/host_shell.py)."""

    stream_id: str = params.get("stream_id", "")
    try:
        cols = int(params.get("cols", 220) or 220)
        rows = int(params.get("rows", 50) or 50)
    except (TypeError, ValueError) as exc:
        _release_stream(sess, stream_id, ctrl_q)
        await ws.send(
            _json(
                {
                    "type": "response",
                    "id": request_id,
                    "error": {
                        "code": -32602,
                        "message": f"Invalid PTY size: {exc}",
                    },
                }
            )
        )
        return

    run_blocking = functools.partial(executor.run_host_pty_blocking, cols, rows)
    await _run_pty_stream(ws, request_id, stream_id, sess, ctrl_q, run_blocking)


async def _handle_tcp_tunnel_session(
    ws: websockets.WebSocketClientProtocol,
    executor: Executor,
    request_id: str,
    params: dict,
    sess: _Session,
    ctrl_q: asyncio.Queue,
) -> None:
    """Open a raw TCP connection to target_host:target_port (reachable from
    this agent's own Docker host — for the DB tunnel feature this is always
    the local berth_postgres container) and relay bytes over the gateway WS.

    Unlike _handle_pty_session, this runs entirely on the event loop — no
    thread pool, no threading.Queue bridge — since asyncio.open_connection
    is natively async. Honors stream_pause/stream_resume (queued as
    ("pause",) / ("resume",) tuples, same ctrl_q as PTY's stdin/close) by
    gating the target->WS read loop on an asyncio.Event, so a slow WS
    consumer can throttle how fast we drain the target socket instead of
    us buffering unboundedly or silently dropping chunks.

    ctrl_q itself (the WS->target direction: client writes/COPY data) is
    not count-bounded — PTY's maxsize=256 silent-drop-on-full would desync a
    stateful wire protocol under a large write burst (e.g. \\copy of a big
    file), the exact failure the read-direction flow control avoids, and
    there is no pause/resume in this direction. Instead it is byte-bounded
    per stream and across the session (tracked in stream_bytes and
    total_stream_bytes): a peer that outruns the target's drain rate past a
    ceiling has its stream closed cleanly rather than being silently dropped
    (desync) or allowed to exhaust the agent's memory.
    """
    stream_id: str = params.get("stream_id", "")
    target_host: str = params.get("target_host", "")

    try:
        target_port = int(params.get("target_port", 0))
    except (TypeError, ValueError) as exc:
        _release_stream(sess, stream_id, ctrl_q)
        await ws.send(
            _json(
                {
                    "type": "response",
                    "id": request_id,
                    "error": {
                        "code": -32602,
                        "message": f"Invalid target_port: {exc}",
                    },
                }
            )
        )
        return

    try:
        reader, writer = await executor.open_tcp_tunnel_connection(
            target_host, target_port
        )
    except Exception as exc:
        _release_stream(sess, stream_id, ctrl_q)
        await ws.send(
            _json(
                {
                    "type": "response",
                    "id": request_id,
                    "error": {"code": -32002, "message": _redact(str(exc))},
                }
            )
        )
        return

    await ws.send(
        _json({"type": "response", "id": request_id, "result": {"ok": True}})
    )

    not_paused = asyncio.Event()
    not_paused.set()

    async def _read_target_to_ws() -> None:
        try:
            while True:
                await not_paused.wait()
                chunk = await reader.read(65536)
                if not chunk:
                    return
                # Gate again right before sending, not just before starting
                # the read: reader.read() can't be interrupted mid-flight,
                # so a read already in progress when "pause" arrives still
                # completes — without this second check that chunk would
                # ship anyway, defeating the pause. This bounds the worst
                # case to "one chunk (<=64KB) held in our own memory while
                # paused, never transmitted until resumed" instead of an
                # unbounded number of chunks leaking through.
                await not_paused.wait()
                await ws.send(
                    _json(
                        {
                            "type": "stream_data",
                            "stream_id": stream_id,
                            "data": base64.b64encode(chunk).decode(),
                        }
                    )
                )
        except Exception:
            return

    async def _consume_ctrl() -> None:
        while True:
            item = await ctrl_q.get()
            tag = item[0]
            if tag == "data":
                try:
                    writer.write(item[1])
                    await writer.drain()
                except Exception:
                    return
                finally:
                    _drain_stream_bytes(sess, stream_id, len(item[1]))
            elif tag == "pause":
                not_paused.clear()
            elif tag == "resume":
                not_paused.set()
            elif tag == "close":
                return

    read_task = asyncio.create_task(_read_target_to_ws())
    ctrl_task = asyncio.create_task(_consume_ctrl())
    try:
        await asyncio.wait(
            {read_task, ctrl_task}, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        read_task.cancel()
        ctrl_task.cancel()
        with suppress(asyncio.CancelledError):
            await read_task
        with suppress(asyncio.CancelledError):
            await ctrl_task
        with suppress(Exception):
            writer.close()
            await writer.wait_closed()
        _release_stream(sess, stream_id, ctrl_q)
        with suppress(Exception):
            await ws.send(
                _json(
                    {
                        "type": "stream_closed",
                        "stream_id": stream_id,
                        "exit_code": 0,
                    }
                )
            )


async def _execute_and_reply(
    ws: websockets.WebSocketClientProtocol,
    executor: Executor,
    request_id: str,
    method: str,
    params: dict,
    timeout: float,
    command_future: concurrent.futures.Future,
) -> None:
    """Run a command in the thread pool and send the response.

    The caller submits and accounts for the underlying concurrent future.
    Its slot is released by that future's completion callback, not by this
    asyncio wrapper: a protocol timeout does not stop executor work.
    """
    try:
        try:
            result = await asyncio.wait_for(
                asyncio.shield(asyncio.wrap_future(command_future)),
                timeout=timeout,
            )
            await ws.send(
                _json({"type": "response", "id": request_id, "result": result})
            )
        except asyncio.TimeoutError:
            logger.error("Command %r timed out after %ss", method, timeout)
            await ws.send(
                _json(
                    {
                        "type": "response",
                        "id": request_id,
                        "error": {
                            "code": -32000,
                            "message": f"Command timed out after {timeout}s",
                        },
                    }
                )
            )
        except Exception as exc:
            logger.error(
                "Command %r failed (%s): %s",
                method,
                type(exc).__name__,
                _redact(str(exc)),
            )
            await ws.send(
                _json(
                    {
                        "type": "response",
                        "id": request_id,
                        "error": {
                            "code": -32001,
                            "message": _redact(str(exc)),
                        },
                    }
                )
            )
    except asyncio.CancelledError:
        raise


def _json(obj: dict) -> str:
    return json.dumps(obj)
