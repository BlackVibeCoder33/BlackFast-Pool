"""
Однократный прогон pipeline — для GitHub Actions.
Выполняет fetch → tcp → service → speed → filter → build,
сохраняет YAML в out/subscription.yaml и завершается.
"""
import asyncio
import sys
import time
from typing import Any

import yaml
from loguru import logger

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
from core.speed_test import get_speed_concurrent, speed_test_all
from core.tcp_check import tcp_check_all


async def run(config: dict[str, Any]) -> None:
    logger.info("=" * 60)
    logger.info("Pipeline: старт (однократный режим)")
    logger.info("=" * 60)
    t_start = time.time()

    proxies = await fetch_all(config["subscriptions"])
    logger.info(f"[1] После парсинга: {len(proxies)}")

    representatives, expansion_map = group_by_server_port(proxies)
    logger.info(f"[1.5] Уникальных (server, port): {len(representatives)}")

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
    is_github = True
    svc_concurrent = get_service_concurrent(config, is_github)
    spd_concurrent = get_speed_concurrent(config, is_github)

    cache_cfg = config.get("cache", {}) or {}
    cache_enabled = bool(cache_cfg.get("enabled", False))
    from pathlib import Path as _Path
    cache_path = _Path(cache_cfg.get("cache_file", "out/cache.json"))
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

    default_required_pre = config["thresholds"].get("required_services", [])
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
    default_required = config["thresholds"].get("required_services", [])
    default_passed = filter_and_rank(speed_results, default_required, min_speed)
    default_expanded = expand_representatives(default_passed, expansion_map)
    default_final = sort_alphabetically(
        ensure_unique_names(list(default_expanded))
    )

    if not default_final:
        logger.warning("Финал пуст — выходим без сохранения")
        return

    yaml_content = build_subscription(default_final, group_prefix="BlackFast")

    from pathlib import Path

    out_dir = Path("out")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "Global-subscription.yaml").write_text(yaml_content, encoding="utf-8")
    logger.info(
        f"[3] Основная подписка: {len(default_final)} записей "
        f"({len(default_passed)} уникальных серверов)"
    )

    profiles = config.get("subscription_profiles", [])
    if profiles:
        selections = build_profiles(speed_results, profiles, min_speed)
        for profile in profiles:
            path = profile["path"]
            prefix = profile.get("group_prefix", profile["name"])
            selected = selections.get(path, [])
            expanded = expand_representatives(selected, expansion_map)
            final_list = sort_alphabetically(
                ensure_unique_names(list(expanded))
            )
            if not final_list:
                logger.warning(f"Профиль '{path}' пуст — пропуск")
                continue
            profile_yaml = build_subscription(final_list, group_prefix=prefix)
            filename = profile.get("filename", f"{path}.yaml")
            (out_dir / filename).write_text(profile_yaml, encoding="utf-8")
            logger.info(
                f"[profiles] '{path}': {len(final_list)} записей "
                f"({len(selected)} уникальных)"
            )

    elapsed = time.time() - t_start
    logger.info(f"[4] Pipeline завершён за {elapsed:.0f} с")


async def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")

    with open("config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    from core.singbox import set_anti_dpi
    set_anti_dpi(config.get("anti_dpi", {}))

    await run(config)


if __name__ == "__main__":
    asyncio.run(main())