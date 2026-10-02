import asyncio
import socket
import sys
import time
from pathlib import Path
from typing import Any

import aiohttp
import yaml
from aiohttp import web
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from loguru import logger

from core.paths import base_dir
from core.builder import build_subscription
from core.fetcher import (
    expand_representatives,
    fetch_all,
    group_by_server_port,
)
from core.filter_rank import (
    build_profiles,
    ensure_unique_names,
    sort_alphabetically,
)
from core.cache import (
    filter_banned,
    load_cache,
    save_cache,
    update_after_run,
)
from core.service_check import get_service_concurrent, service_check_all
from core.singbox import set_anti_dpi
from core.speed_test import get_speed_concurrent, speed_test_all
from core.tcp_check import tcp_check_all


class PoolState:
    def __init__(self) -> None:
        self.profiles_yaml: dict[str, str] = {}
        self.profiles_count: dict[str, int] = {}
        self.last_updated: float = 0.0
        self.lock = asyncio.Lock()


state = PoolState()


async def run_pipeline(config: dict[str, Any]) -> None:
    if state.lock.locked():
        logger.warning("Pipeline уже идёт — пропуск итерации")
        return
    async with state.lock:
        logger.info("=" * 60)
        logger.info("Pipeline: старт")
        logger.info("=" * 60)
        t_start = time.time()

        try:
            proxies_all = await fetch_all(config["subscriptions"])
            logger.info(f"[1] После парсинга: {len(proxies_all)}")

            passthrough_types = set(config.get("passthrough_types", []))
            passthrough = [
                p for p in proxies_all if p.get("type") in passthrough_types
            ]
            russian = [
                p for p in proxies_all
                if p.get("_is_russian")
                and p.get("type") not in passthrough_types
            ]
            testable = [
                p for p in proxies_all
                if p.get("type") not in passthrough_types
                and not p.get("_is_russian")
            ]
            if passthrough_types:
                logger.info(
                    f"[1.5] Passthrough "
                    f"({','.join(sorted(passthrough_types))}): "
                    f"{len(passthrough)}, тестируемых: {len(testable)}, "
                    f"РФ: {len(russian)}"
                )

            russian_reps, _ = group_by_server_port(russian)

            representatives, expansion_map = group_by_server_port(testable)
            logger.info(
                f"[1.5] Уникальных (server, port): {len(representatives)}"
            )

            tcp_cfg = config.get("tcp_check", {})
            alive, _ = await tcp_check_all(
                representatives,
                concurrent=tcp_cfg.get("concurrent", 200),
                timeout=float(tcp_cfg.get("timeout_seconds", 3)),
            )
            max_ping = config["thresholds"]["max_ping_ms"]
            alive = [p for p in alive if p.get("_tcp_ping_ms", 1e9) <= max_ping]
            logger.info(f"[2] Живых и ≤ {max_ping} мс: {len(alive)}")

            st = config.get("speed_test", {})
            scfg = config.get("service_check", {})
            is_github = False
            svc_concurrent = get_service_concurrent(config, is_github)
            spd_concurrent = get_speed_concurrent(config, is_github)

            cache_cfg = config.get("cache", {}) or {}
            cache_enabled = bool(cache_cfg.get("enabled", False))
            cache_path = base_dir() / cache_cfg.get(
                "cache_file", "out/cache.json"
            )
            cache_data = load_cache(cache_path) if cache_enabled else {"servers": {}}

            if cache_enabled:
                alive = filter_banned(
                    alive,
                    cache_data,
                    float(cache_cfg.get("ban_duration_hours", 2)),
                )

            checked = await service_check_all(
                alive,
                config["services"],
                concurrent=svc_concurrent,
                scfg=scfg,
            )

            def _has_any_service(p: dict[str, Any]) -> bool:
                svc = p.get("_services", {})
                return any(v.get("ok") for v in svc.values())

            relevant = [p for p in checked if _has_any_service(p)]
            logger.info(
                f"[2.5] Прошли хотя бы один сервис: {len(relevant)} "
                f"из {len(checked)}"
            )

            test_urls = st.get("test_urls")
            if not test_urls:
                test_urls = [
                    st.get(
                        "test_url",
                        "https://speed.cloudflare.com/__down?bytes=2000000",
                    )
                ]
            timeout = float(st.get("timeout_seconds", 20))
            retest = int(st.get("retest_count", 2))
            retest_pause = float(st.get("retest_pause_seconds", 0))
            min_bytes = int(st.get("min_measure_bytes", 300000))
            peak_win = float(st.get("peak_window_seconds", 0.5))
            speed_results = await speed_test_all(
                relevant,
                test_urls=test_urls,
                timeout=timeout,
                concurrent=spd_concurrent,
                retest_count=retest,
                retest_pause_seconds=retest_pause,
                min_bytes=min_bytes,
                peak_window_sec=peak_win,
            )

            if cache_enabled:
                cache_data = update_after_run(
                    speed_results,
                    cache_data,
                    int(cache_cfg.get("ban_after_consecutive_failures", 3)),
                    float(cache_cfg.get("ban_duration_hours", 2)),
                )
                save_cache(cache_path, cache_data)

            min_speed = config["thresholds"]["min_speed_mbps"]

            profiles = config.get("subscription_profiles", [])
            if profiles:
                profile_selections = build_profiles(
                    speed_results, profiles, min_speed
                )
                new_profiles_yaml: dict[str, str] = {}
                new_profiles_count: dict[str, int] = {}
                for profile in profiles:
                    path = profile["path"]
                    name = profile["name"]
                    prefix = profile.get("group_prefix", name)
                    selected = profile_selections.get(path, [])
                    expanded = expand_representatives(selected, expansion_map)
                    include_russian = bool(
                        profile.get("allow_russian", False)
                    )
                    base_list = list(expanded) + passthrough
                    if include_russian:
                        base_list += russian_reps
                    final_list = sort_alphabetically(
                        ensure_unique_names(base_list)
                    )
                    if not final_list:
                        logger.warning(f"[profiles] '{path}' пуст — пропуск")
                        continue
                    yaml_content = build_subscription(
                        final_list, group_prefix=prefix
                    )
                    new_profiles_yaml[path] = yaml_content
                    new_profiles_count[path] = len(final_list)
                    filename = profile.get("filename", f"{path}.yaml")
                    out_path = base_dir() / "out" / filename
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(yaml_content, encoding="utf-8")
                    logger.info(
                        f"[profiles] '{path}': {len(final_list)} записей "
                        f"({len(selected)} уникальных) → {out_path.name}"
                    )
                state.profiles_yaml = new_profiles_yaml
                state.profiles_count = new_profiles_count

            state.last_updated = time.time()
            elapsed = time.time() - t_start
            logger.info(
                f"[4] Pipeline завершён за {elapsed:.0f} с. "
                f"{len(state.profiles_yaml)} профилей, "
                f"РФ-серверов в flashscore: {len(russian_reps)}"
            )

            local_ip = _get_local_ip()
            port = int(config["http_server"]["port"])
            logger.info("=" * 60)
            logger.info("ГОТОВЫЕ ССЫЛКИ ДЛЯ KARING:")
            for profile in config.get("subscription_profiles", []):
                path = profile["path"]
                if path in state.profiles_yaml:
                    count = state.profiles_count.get(path, 0)
                    logger.info(
                        f"  {profile['name']} ({count} серверов):"
                    )
                    logger.info(
                        f"    http://{local_ip}:{port}/sub/{path}"
                    )
            logger.info("=" * 60)
        except Exception as e:
            logger.exception(f"Ошибка pipeline: {e}")


async def handle_sub_profile(request: web.Request) -> web.Response:
    path = request.match_info["profile"]
    if path not in state.profiles_yaml:
        available = ", ".join(sorted(state.profiles_yaml.keys())) or "(none)"
        return web.Response(
            status=404,
            text=f"Profile '{path}' not found. Available: {available}",
        )
    return web.Response(
        text=state.profiles_yaml[path],
        content_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{path}.yaml"'},
    )


async def handle_status(request: web.Request) -> web.Response:
    if state.last_updated == 0:
        return web.Response(status=503, text="Not ready yet.")
    ago = int(time.time() - state.last_updated)
    lines = [
        "BlackFast Pool",
        f"Last updated: {ago} sec ago",
        "",
        "Profiles:",
    ]
    for path in sorted(state.profiles_yaml.keys()):
        lines.append(
            f"  /sub/{path}  →  {state.profiles_count.get(path, 0)} servers"
        )
    return web.Response(text="\n".join(lines))


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


async def main() -> None:
    (base_dir() / "logs").mkdir(exist_ok=True)
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add(
        base_dir() / "logs" / "app.log",
        level="DEBUG",
        rotation="10 MB",
        retention="7 days",
        encoding="utf-8",
    )

    with open(base_dir() / "config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    from core.singbox import set_anti_dpi
    set_anti_dpi(config.get("anti_dpi", {}))

    asyncio.create_task(run_pipeline(config))

    interval = int(config["schedule"]["update_interval_minutes"])
    scheduler = AsyncIOScheduler()
    scheduler.add_job(run_pipeline, "interval", minutes=interval, args=[config])
    scheduler.start()
    logger.info(f"Планировщик запущен: обновление каждые {interval} мин")

    app = web.Application()
    app.router.add_get("/sub/{profile}", handle_sub_profile)
    app.router.add_get("/", handle_status)
    app.router.add_get("/status", handle_status)

    host = config["http_server"]["host"]
    port = int(config["http_server"]["port"])

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    local_ip = _get_local_ip()
    logger.info("=" * 60)
    logger.info(f"HTTP-сервер слушает {host}:{port}")
    for profile in config.get("subscription_profiles", []):
        logger.info(
            f"  '{profile['name']}': http://{local_ip}:{port}/sub/{profile['path']}"
        )
    logger.info(f"Статус:            http://{local_ip}:{port}/status")
    logger.info("=" * 60)
    logger.info("Ctrl+C — остановка")

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass

    logger.info("Останавливаемся...")
    scheduler.shutdown(wait=False)
    await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass