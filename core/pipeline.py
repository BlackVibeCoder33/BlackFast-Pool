# core/pipeline.py
import time
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from core.paths import base_dir
from core.builder import build_subscription
from core.hiddify_builder import build_hiddify_subscription
from core.fetcher import (
    expand_representatives,
    fetch_all,
    group_by_server_port,
)
from core.filter_rank import (
    build_profiles,
    ensure_unique_names,
    sort_by_speed,
)
from core.cache import (
    filter_banned,
    load_cache,
    save_cache,
    update_after_run,
)
from core.cdn_filter import filter_fake_speeds
from core.geoip import lookup_countries
from core.service_check import get_service_concurrent, service_check_all
from core.speed_test import get_speed_concurrent, speed_test_all
from core.tcp_check import tcp_check_all


@dataclass
class PipelineResult:
    """Результат работы пайплайна — удобная структура вместо кортежа."""
    yaml_subscriptions: dict[str, str] = field(default_factory=dict)
    hiddify_subscriptions: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    total_fetched: int = 0
    total_tcp_alive: int = 0
    total_speed_passed: int = 0


async def run_core_pipeline(
    config: dict[str, Any], is_github: bool
) -> PipelineResult:
    logger.info("=" * 60)
    logger.info(f"Pipeline: старт ({'GitHub' if is_github else 'PC'})")
    logger.info("=" * 60)
    t_start = time.time()

    proxies_all = await fetch_all(config["subscriptions"])
    logger.info(f"[1] После парсинга: {len(proxies_all)}")
    ru_after_parse = sum(1 for p in proxies_all if p.get("_is_russian"))
    logger.info(f"[1] РФ-серверов после парсинга: {ru_after_parse}")

    udp_types = set(config.get("udp_types", ["hysteria2"]))

    tcp_proxies = [p for p in proxies_all if p.get("type") not in udp_types]
    hy2_proxies = [p for p in proxies_all if p.get("type") in udp_types]
    logger.info(
        f"[1.5] Разделение: TCP-протоколов {len(tcp_proxies)}, "
        f"UDP/hy2 {len(hy2_proxies)}"
    )

    tcp_reps, tcp_map = group_by_server_port(tcp_proxies)
    logger.info(f"[1.5] TCP уникальных (server, port): {len(tcp_reps)}")

    tcp_cfg = config.get("tcp_check", {})
    tcp_alive, _ = await tcp_check_all(
        tcp_reps,
        concurrent=tcp_cfg.get("concurrent", 200),
        timeout=float(tcp_cfg.get("timeout_seconds", 3)),
    )
    max_ping = config["thresholds"]["max_ping_ms"]
    tcp_alive = [p for p in tcp_alive if p.get("_tcp_ping_ms", 1e9) <= max_ping]
    logger.info(f"[2] TCP живых и <= {max_ping} мс: {len(tcp_alive)}")

    for p in hy2_proxies:
        p["_tcp_ok"] = True
        p["_tcp_ping_ms"] = 0.0
        p["_tcp_skip"] = True
    logger.info(f"[2] hy2 к service-check: {len(hy2_proxies)}")

    alive = tcp_alive + hy2_proxies
    logger.info(f"[2.5] Всего к service-check: {len(alive)}")
    ru_alive = sum(1 for p in alive if p.get("_is_russian"))
    logger.info(f"[2.5] РФ-серверов к service-check: {ru_alive}")

    st = config.get("speed_test", {})
    scfg = config.get("service_check", {})
    svc_concurrent = get_service_concurrent(config, is_github)
    spd_concurrent = get_speed_concurrent(config, is_github)

    cache_cfg = config.get("cache", {}) or {}
    cache_enabled = bool(cache_cfg.get("enabled", False))
    cache_path = base_dir() / cache_cfg.get("cache_file", "out/cache.json")
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
    logger.info(f"[2.5] Прошли хотя бы один сервис: {len(relevant)} из {len(checked)}")
    ru_after_service = sum(1 for p in relevant if p.get("_is_russian"))
    logger.info(f"[2.5] РФ-серверов прошли service-check: {ru_after_service}")

    test_urls = st.get("test_urls")
    if not test_urls:
        test_urls = [
            st.get("test_url", "https://speed.cloudflare.com/__down?bytes=2000000")
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

    # Отсеиваем CDN-прокси с нереальными скоростями (CF-to-CF кэш).
    speed_results = filter_fake_speeds(speed_results)

    # Гео-детект по IP: нужен для профилей с exclude_geo, где имя
    # не содержит гео-подсказок (напр. "Node 123" с IP в США).
    # Если сервис недоступен — фильтр работает как раньше (только по именам).
    await lookup_countries(speed_results)

    ru_after_speed = sum(1 for p in speed_results if p.get("_is_russian"))
    logger.info(f"[3] РФ-серверов после speed-test: {ru_after_speed}")

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
    
    result = PipelineResult()

    if profiles:
        selections = build_profiles(
            speed_results,
            profiles,
            min_speed,
            max_service_latency_ms=config["thresholds"].get("max_service_latency_ms"),
            thresholds_by_type=config.get("thresholds_by_type", {}),
        )
        for profile in profiles:
            path = profile["path"]
            prefix = profile.get("group_prefix", profile["name"])
            selected = selections.get(path, [])
            
            selected_tcp = [p for p in selected if not p.get("_tcp_skip")]
            selected_hy2 = [p for p in selected if p.get("_tcp_skip")]
            max_fp_variants = int(
                config.get("dedupe", {}).get("max_fp_variants", 3)
            )
            expanded_tcp = expand_representatives(
                selected_tcp, tcp_map, max_fp_variants=max_fp_variants
            )
            base_list = list(expanded_tcp) + list(selected_hy2)
            
            final_list = sort_by_speed(ensure_unique_names(base_list))
            if not final_list:
                logger.warning(f"[profiles] '{path}' пуст — пропуск")
                continue
                
            # Передаем флаг блокировки, если в конфиге профиля задан exclude_geo
            # (Но не применяем его для ChatGPT)
            should_block_us = bool(profile.get("exclude_geo")) and "chatgpt" not in path
            
            result.yaml_subscriptions[path] = build_subscription(
                final_list, 
                group_prefix=prefix,
                block_us_ca=should_block_us
            )
            result.counts[path] = len(final_list)

            hiddify_b64 = build_hiddify_subscription(final_list)
            if hiddify_b64:
                result.hiddify_subscriptions[path] = hiddify_b64
                logger.info(f"[hiddify] '{path}': {len(final_list)} записей")

            logger.info(f"[profiles] '{path}': {len(final_list)} записей (уникальных {len(selected)})")

    elapsed = time.time() - t_start
    russian_passed = [p for p in speed_results if p.get("_is_russian")]
    logger.info(f"[4] Pipeline завершён за {elapsed:.0f} с. РФ прошли speed-test: {len(russian_passed)}")

    result.total_fetched = len(proxies_all)
    result.total_tcp_alive = len(alive)
    result.total_speed_passed = len(speed_results)

    return result