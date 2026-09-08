"""High-level SaaS instance operations executed locally by the agent.

These commands encapsulate all local filesystem and Docker operations
required to provision/deprovision an Odoo instance, so the control plane
only needs to send a single high-level spec instead of many raw Docker calls.
"""

from __future__ import annotations

import logging
import pathlib
import re
from typing import Any

from agent.security import redact

logger = logging.getLogger(__name__)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# A tenant slug is only ever a lowercased identifier on the control-plane
# side (berth-platform routers/instances.py). Validating it here anyway:
# the slug is joined onto DATA_ROOT_PATH to build directories that get
# written to *and* bind-mounted into a container, so `../../etc` or an
# absolute value would escape the data root (pathlib drops the left side
# on an absolute join) — defense in depth against any control-plane bug
# that lets an unsanitized value through.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def _safe_slug(slug: object) -> str:
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        raise ValueError(f"Invalid instance slug: {slug!r}")
    return slug


class InstanceCommands:
    def __init__(self, docker_client: Any, data_root_path: str) -> None:
        self._docker = docker_client
        self._data_root = pathlib.Path(data_root_path)

    # ------------------------------------------------------------------
    # Provision
    # ------------------------------------------------------------------

    def provision(self, params: dict) -> dict:
        """Provision a full Odoo instance.

        Expected params (built by OdooDriver._provision_via_agent):
          slug, db_name, image, odoo_config_content, config_container_path,
          extra_addons_paths, docker_network, tunnel_token, platform,
          cpu_cores, ram_mb, hostname, tenant_base_domain, init_base
        """
        slug = _safe_slug(params["slug"])
        image = params["image"]
        platform = params.get("platform") or None
        network = params.get("docker_network", "berth_platform_proxy")
        domain = params.get("tenant_base_domain", "localhost")

        slug_dir = self._data_root / slug

        # 1. Create required directories
        for sub in ("filestore", "sessions", "addons", "conf"):
            (slug_dir / sub).mkdir(parents=True, exist_ok=True)
        logger.info("Directories created for %s", slug)

        # 2. Write odoo.conf
        config_content = params.get("odoo_config_content", "")
        conf_path = slug_dir / "conf" / "odoo.conf"
        conf_path.write_text(config_content, encoding="utf-8")
        logger.info("Config written: %s", conf_path)

        # 3. Ensure Docker network exists
        self._ensure_network(network)

        # 4. Pull image
        try:
            self._docker.images.get(image)
        except Exception:
            logger.info("Pulling image %s (platform=%s)", image, platform)
            pull_kwargs: dict = {"repository": image}
            if platform:
                pull_kwargs["platform"] = platform
            self._docker.api.pull(**pull_kwargs)

        # 5. Build volumes (relative paths resolved by ContainerCommands._resolve_volumes,
        #    but here we build absolute paths directly since we know data_root_path)
        host_base = str(self._data_root / slug)
        config_container_path = params.get(
            "config_container_path", "/etc/odoo/odoo.conf"
        )
        volumes: dict[str, dict[str, str]] = {
            f"{host_base}/filestore": {
                "bind": "/var/lib/odoo/filestore",
                "mode": "rw",
            },
            f"{host_base}/sessions": {
                "bind": "/var/lib/odoo/sessions",
                "mode": "rw",
            },
            f"{host_base}/addons": {"bind": "/mnt/extra-addons", "mode": "rw"},
            f"{host_base}/conf/odoo.conf": {
                "bind": config_container_path,
                "mode": "ro",
            },
        }

        # 6. Build labels (Traefik routing)
        container_name = f"saas_{slug}"
        labels = self._build_traefik_labels(
            slug, container_name, network, domain
        )

        # 7. Build environment
        extra_paths = params.get("extra_addons_paths") or []
        addons_path = (
            ",".join(extra_paths) if extra_paths else "/mnt/extra-addons"
        )
        env = {
            "ADDONS_PATH": addons_path,
        }
        # DB connection env (HOST/PORT/USER/PASSWORD) — the ooops OCB
        # entrypoint reads these to wait for and authenticate against the
        # external Postgres. Strings only; skip anything non-str/None.
        db_env = params.get("db_env")
        if isinstance(db_env, dict):
            for k, v in db_env.items():
                if isinstance(k, str) and isinstance(v, str):
                    env[k] = v

        # 8. Resource limits
        cpu_cores = params.get("cpu_cores")
        ram_mb = params.get("ram_mb")
        nano_cpus = int(cpu_cores * 1e9) if cpu_cores else None
        mem_limit = f"{ram_mb}m" if ram_mb else None

        # 9. Build the odoo command (same pattern as control plane
        #    docker_manager.spawn_instance). -d/--db-filter mirror what's
        #    already enforced in odoo.conf (db_name/dbfilter, written above);
        #    -i base has no config-file equivalent — it's CLI-only. Whether
        #    to pass it is decided once on the control plane
        #    (OdooDriver._provision_via_agent / _replace_container_via_agent,
        #    via backup_manager.is_base_module_installed) and trusted
        #    verbatim here — the agent never re-derives it locally. Passing
        #    -i base on every boot (not just a genuinely fresh database)
        #    unconditionally reapplies base's noupdate="1" data, silently
        #    resetting the admin password to Odoo's factory default "admin"
        #    on every restart. A missing/omitted init_base defaults to
        #    False (never re-init) rather than True, so an older control
        #    plane talking to a newer agent fails safe.
        db_name = params["db_name"]
        odoo_cmd = ["odoo", "-d", db_name]
        if params.get("init_base"):
            odoo_cmd += ["-i", "base"]
        odoo_cmd += ["--db-filter", f"^{db_name}$"]
        _wait = 'until pg_isready -h "$HOST" -p "$PORT" -U "$USER" 2>/dev/null; do sleep 2; done'
        import shlex

        command = [
            "sh",
            "-c",
            f"{_wait} && {' '.join(shlex.quote(a) for a in odoo_cmd)}",
        ]

        run_kwargs: dict[str, Any] = {
            "image": image,
            "name": container_name,
            "detach": True,
            "environment": env,
            "labels": labels,
            "volumes": volumes,
            "network": network,
            "command": command,
            "restart_policy": {"Name": "unless-stopped"},
            "hostname": params.get("hostname") or slug,
        }
        if platform:
            run_kwargs["platform"] = platform
        if nano_cpus:
            run_kwargs["nano_cpus"] = nano_cpus
        if mem_limit:
            run_kwargs["mem_limit"] = mem_limit

        # Idempotent re-provision: a stale container with this name (a prior
        # attempt that got far enough to create it, then failed/timed out)
        # would otherwise 409 forever.
        for stale in (container_name, f"{container_name}_cloudflared"):
            try:
                self._docker.containers.get(stale).remove(force=True)
                logger.info("Removed stale container %s before re-provision", stale)
            except Exception:  # noqa: BLE001 — NotFound or already gone
                pass

        container = self._docker.containers.run(**run_kwargs)
        logger.info(
            "Instance container started: %s (%s)",
            container.name,
            container.short_id,
        )

        # Cloudflare tunnel sidecar (if token provided) — provisioned separately
        cloudflared_id: str | None = None
        tunnel_token = params.get("tunnel_token")
        if tunnel_token:
            cloudflared_id = self._spawn_cloudflared(
                slug, tunnel_token, network
            )

        return {
            "container_id": container.id,
            "cloudflared_container_id": cloudflared_id,
        }

    # ------------------------------------------------------------------
    # Deprovision
    # ------------------------------------------------------------------

    def deprovision(self, params: dict) -> dict:
        for name_or_id in filter(
            None,
            [
                params.get("cloudflared_container_id"),
                params.get("container_id"),
            ],
        ):
            try:
                self._docker.containers.get(name_or_id).remove(force=True)
                logger.info("Removed container %s", name_or_id)
            except Exception as exc:
                logger.warning(
                    "Could not remove container %s: %s", name_or_id, exc
                )
        return {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_network(self, network: str) -> None:
        try:
            self._docker.networks.get(network)
        except Exception:
            self._docker.networks.create(network, driver="bridge")
            logger.info("Created Docker network: %s", network)

    def _build_traefik_labels(
        self, slug: str, container_name: str, network: str, domain: str
    ) -> dict:
        host = f"{slug}.{domain}"
        router = f"saas-{slug}"
        return {
            "traefik.enable": "true",
            f"traefik.http.routers.{router}.rule": f"Host(`{host}`)",
            f"traefik.http.routers.{router}.entrypoints": "websecure",
            f"traefik.http.routers.{router}.tls": "true",
            f"traefik.http.services.{router}.loadbalancer.server.port": "8069",
            "saas.instance": slug,
            "saas.managed": "true",
        }

    def _spawn_cloudflared(
        self, slug: str, tunnel_token: str, network: str
    ) -> str | None:
        try:
            cf_name = f"saas_{slug}_cloudflared"
            cf = self._docker.containers.run(
                "cloudflare/cloudflared:latest",
                name=cf_name,
                detach=True,
                network=network,
                command=[
                    "tunnel",
                    "--no-autoupdate",
                    "run",
                    "--token",
                    tunnel_token,
                ],
                restart_policy={"Name": "unless-stopped"},
                labels={"saas.instance": slug, "saas.role": "cloudflared"},
            )
            logger.info("Cloudflared sidecar started: %s", cf.short_id)
            return cf.id
        except Exception as exc:
            logger.warning(
                "Could not spawn cloudflared for %s: %s",
                slug,
                redact(str(exc)),
            )
            return None
