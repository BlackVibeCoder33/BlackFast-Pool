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
    filter_and_rank,
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
        self.default_yaml: str = ""
        self.default_count: int = 0
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
            proxies = await fetch_all(config["subscriptions"])
            logger.info(f"[1] После парсинга: {len(proxies)}")

            representatives, expansion_map = group_by_server_port(proxies)
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

            default_required_pre = config["thresholds"].get(
                "required_services", []
            )
            profiles_cfg = config.get("subscription_profiles", [])

            def _matches_any(p: dict[str, Any]) -> bool:
                svc = p.get("_services", {})
                if all(svc.get(r, {}).get("ok") for r in default_required_pre):
                    return True
                for prof in profiles_cfg:
                    reqs = prof.get("required_services", [])
                    if reqs and all(svc.get(r, {}).get("ok") for r in reqs):
                        return True
                return False

            relevant = [p for p in checked if _matches_any(p)]
            logger.info(
                f"[2.5] Прошли хотя бы один набор сервисов: {len(relevant)} "
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
            max_ping_val = config["thresholds"]["max_ping_ms"]

            default_required = config["thresholds"].get("required_services", [])
            default_passed = filter_and_rank(
                speed_results, default_required, min_speed
            )
            default_expanded = expand_representatives(
                default_passed, expansion_map
            )
            default_final = sort_alphabetically(
                ensure_unique_names(list(default_expanded))
            )
            if default_final:
                yaml_content = build_subscription(
                    default_final, group_prefix="BlackFast"
                )
                state.default_yaml = yaml_content
                state.default_count = len(default_final)
                out_path = base_dir() / config["paths"]["out_subscription"]
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(yaml_content, encoding="utf-8")
                golden_path = base_dir() / "out" / "golden.yaml"
                golden_path.write_text(yaml_content, encoding="utf-8")
                sources: dict[str, int] = {}
                for p in default_final:
                    s = p.get("_source") or "unknown"
                    sources[s] = sources.get(s, 0) + 1
                source_str = ", ".join(f"{k}={v}" for k, v in sources.items())
                logger.info(
                    f"[3] Основная подписка: {len(default_final)} записей "
                    f"({len(default_passed)} уникальных серверов) "
                    f"[{source_str}] (золотой пул обновлён)"
                )
            else:
                golden_path = base_dir() / "out" / "golden.yaml"
                if golden_path.exists():
                    golden_text = golden_path.read_text(encoding="utf-8")
                    if golden_text.strip():
                        state.default_yaml = golden_text
                        try:
                            parsed = yaml.safe_load(golden_text)
                            count = len(parsed.get("proxies", []))
                        except Exception:
                            count = 0
                        state.default_count = count
                        age_min = int(
                            (time.time() - golden_path.stat().st_mtime) / 60
                        )
                        logger.warning(
                            f"[3] Пул пуст — отдаю золотой ({count} серверов, "
                            f"{age_min} мин назад)"
                        )
                    else:
                        logger.warning("[3] Пул пуст, золотой тоже пуст")
                else:
                    logger.warning("[3] Пул пуст, золотого ещё нет")

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
                    final_list = sort_alphabetically(
                        ensure_unique_names(list(expanded))
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
                f"Пул: {state.default_count} основных, "
                f"{len(state.profiles_yaml)} профилей"
            )

            local_ip = _get_local_ip()
            port = int(config["http_server"]["port"])
            logger.info("=" * 60)
            logger.info("ГОТОВЫЕ ССЫЛКИ ДЛЯ KARING:")
            logger.info(
                f"  Основная BlackFast ({state.default_count} серверов):"
            )
            logger.info(f"    http://{local_ip}:{port}/sub")
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


async def handle_sub(request: web.Request) -> web.Response:
    if not state.default_yaml:
        return web.Response(
            status=503, text="BlackFast pool is not ready yet. Try again later."
        )
    return web.Response(
        text=state.default_yaml,
        content_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="BlackFast.yaml"'},
    )


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
        f"Default subscription (/sub): {state.default_count} servers",
    ]
    if state.profiles_yaml:
        lines.append("")
        lines.append("Profiles:")
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

    golden_path = base_dir() / "out" / "golden.yaml"
    if golden_path.exists():
        try:
            golden_text = golden_path.read_text(encoding="utf-8")
            if golden_text.strip():
                state.default_yaml = golden_text
                parsed = yaml.safe_load(golden_text)
                state.default_count = len(parsed.get("proxies", []))
                state.last_updated = golden_path.stat().st_mtime
                age_min = int((time.time() - state.last_updated) / 60)
                logger.info(
                    f"Загружен золотой пул: {state.default_count} серверов, "
                    f"{age_min} мин назад"
                )
        except Exception as e:
            logger.warning(f"Не удалось загрузить золотой пул: {e}")

    asyncio.create_task(run_pipeline(config))


    interval = int(config["schedule"]["update_interval_minutes"])
    scheduler = AsyncIOScheduler()
    scheduler.add_job(run_pipeline, "interval", minutes=interval, args=[config])
    scheduler.start()
    logger.info(f"Планировщик запущен: обновление каждые {interval} мин")

    app = web.Application()
    app.router.add_get("/sub", handle_sub)
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
    logger.info(f"Основная подписка: http://{local_ip}:{port}/sub")
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