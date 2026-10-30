"""Гео-детект по IP через ip-api.com/batch с graceful fallback.

Нужен для отсева серверов по стране (exclude_geo), когда имя прокси
не содержит явных гео-подсказок (например, "Node 123" с IP в США).

Если сервис недоступен (блокировка, таймаут, rate-limit) — пробуем
ipwho.is (fallback), затем возвращаем прокси без изменений.

Кэш: out/geoip_cache.json хранит {ip: country_code} между прогонами.
Это экономит бесплатные лимиты ip-api.com (45/мин) и ipwho.is (200/сутки).
"""
import asyncio
import ipaddress
import json
import socket
import time
from pathlib import Path
from typing import Any

import aiohttp
from loguru import logger


BATCH_URL = "http://ip-api.com/batch?fields=query,countryCode"
BATCH_SIZE = 100
RESOLVE_TIMEOUT = 3.0
RESOLVE_CONCURRENCY = 64
HTTP_TIMEOUT = 10.0

FALLBACK_URL = "https://ipwho.is/{ip}"
FALLBACK_CONCURRENCY = 10

CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 дней — страны меняются редко


def _cache_path() -> Path:
    """out/geoip_cache.json — рядом с кэшем банов."""
    try:
        from core.paths import base_dir
        return base_dir() / "out" / "geoip_cache.json"
    except Exception:
        return Path("out") / "geoip_cache.json"


def _load_cache() -> dict[str, Any]:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        # структура: {"ip": {"code": "US", "ts": 1234567890}}
        return data
    except Exception as e:
        logger.warning(f"GeoIP cache: не прочитать {p}: {e}")
        return {}


def _save_cache(cache: dict[str, Any]) -> None:
    p = _cache_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(
            json.dumps(cache, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        logger.warning(f"GeoIP cache: не записать {p}: {e}")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _resolve_one(server: str) -> str | None:
    """Возвращает IP для сервера (IP — как есть, домен — резолвится)."""
    if not server:
        return None
    if _is_ip(server):
        return server
    loop = asyncio.get_event_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(server, None, type=socket.SOCK_STREAM),
            timeout=RESOLVE_TIMEOUT,
        )
        for info in infos:
            candidate = info[4][0]
            if _is_ip(candidate):
                return candidate
    except Exception:
        return None
    return None


async def _resolve_all(
    servers: list[str],
    concurrency: int = RESOLVE_CONCURRENCY,
) -> dict[str, str | None]:
    unique = list({s for s in servers if s})
    if not unique:
        return {}
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(s: str) -> tuple[str, str | None]:
        async with sem:
            return s, await _resolve_one(s)

    pairs = await asyncio.gather(*[_bounded(s) for s in unique])
    return dict(pairs)


async def _batch_lookup(
    session: aiohttp.ClientSession,
    ips: list[str],
) -> dict[str, str]:
    if not ips:
        return {}
    body = [{"query": ip} for ip in ips]
    timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
    try:
        async with session.post(BATCH_URL, json=body, timeout=timeout) as resp:
            if resp.status >= 400:
                logger.warning(f"GeoIP: ip-api.com вернул HTTP {resp.status}")
                return {}
            data = await resp.json()
    except Exception as e:
        logger.warning(f"GeoIP: запрос к ip-api.com не удался: {e}")
        return {}
    if not isinstance(data, list):
        return {}
    result: dict[str, str] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        query = item.get("query")
        code = item.get("countryCode")
        if query and code:
            result[query] = str(code).upper()
    return result


async def _fallback_lookup_one(
    session: aiohttp.ClientSession,
    ip: str,
) -> str | None:
    """Один IP через ipwho.is."""
    timeout = aiohttp.ClientTimeout(total=5)
    try:
        async with session.get(
            FALLBACK_URL.format(ip=ip), timeout=timeout
        ) as resp:
            if resp.status >= 400:
                return None
            data = await resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    code = data.get("country_code")
    if code and isinstance(code, str) and len(code) == 2:
        return code.upper()
    return None


async def _fallback_lookup_batch(
    ips: list[str],
    concurrency: int = FALLBACK_CONCURRENCY,
) -> dict[str, str]:
    if not ips:
        return {}
    sem = asyncio.Semaphore(concurrency)
    timeout = aiohttp.ClientTimeout(total=8)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async def _bounded(ip: str) -> tuple[str, str | None]:
            async with sem:
                return ip, await _fallback_lookup_one(session, ip)

        pairs = await asyncio.gather(*[_bounded(ip) for ip in ips])
    return {ip: code for ip, code in pairs if code}


async def lookup_countries(
    proxies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Ставит на каждый прокси `_country_code` (ISO 3166-1 alpha-2), если удалось.
    Модифицирует список in-place и возвращает его же для удобства.

    Использует 3 источника:
    1. Файловый кэш out/geoip_cache.json (без лимитов)
    2. ip-api.com/batch (45/мин)
    3. ipwho.is (200/сутки) — fallback, только если ip-api упал
    """
    if not proxies:
        return proxies

    # 1. Резолв доменов → IP (сетевой вызов, но локальный DNS)
    servers = [str(p.get("server") or "") for p in proxies]
    resolved = await _resolve_all(servers)

    ip_to_servers: dict[str, list[str]] = {}
    for server, ip in resolved.items():
        if ip:
            ip_to_servers.setdefault(ip, []).append(server)

    unique_ips = list(ip_to_servers.keys())
    if not unique_ips:
        logger.info("GeoIP: ни один server не удалось резолвить в IP")
        return proxies

    # 2. Кэш
    cache = _load_cache()
    now = time.time()
    ip_to_country: dict[str, str] = {}
    cached_hits = 0
    cache_misses: list[str] = []

    for ip in unique_ips:
        entry = cache.get(ip)
        if isinstance(entry, dict):
            ts = float(entry.get("ts", 0) or 0)
            code = entry.get("code")
            if code and (now - ts) < CACHE_TTL_SECONDS:
                ip_to_country[ip] = str(code).upper()
                cached_hits += 1
                continue
        cache_misses.append(ip)

    logger.info(
        f"GeoIP: {len(unique_ips)} IP, из кэша {cached_hits}, "
        f"к запросу {len(cache_misses)}"
    )

    # 3. ip-api.com для некэшированных
    if cache_misses:
        logger.info("GeoIP: запрашиваю ip-api.com...")
        async with aiohttp.ClientSession() as session:
            chunks = [
                cache_misses[i:i + BATCH_SIZE]
                for i in range(0, len(cache_misses), BATCH_SIZE)
            ]
            results = await asyncio.gather(
                *[_batch_lookup(session, chunk) for chunk in chunks],
                return_exceptions=True,
            )
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"GeoIP: батч упал: {r}")
                continue
            ip_to_country.update(r)

        # Обновляем кэш
        for ip, code in ip_to_country.items():
            cache[ip] = {"code": code, "ts": now}

    # 4. Fallback ipwho.is для тех, кто не попал в ip-api
    still_missing = [ip for ip in unique_ips if ip not in ip_to_country]
    if still_missing:
        logger.warning(
            f"GeoIP: {len(still_missing)} IP не покрыты ip-api, "
            f"пробую ipwho.is..."
        )
        fallback = await _fallback_lookup_batch(still_missing)
        if fallback:
            ip_to_country.update(fallback)
            for ip, code in fallback.items():
                cache[ip] = {"code": code, "ts": now}

    # 5. Сохраняем кэш
    if cache_misses:
        _save_cache(cache)

    # 6. Прокидываем результат в прокси
    for p in proxies:
        server = str(p.get("server") or "")
        ip = resolved.get(server)
        if ip and ip in ip_to_country:
            p["_country_code"] = ip_to_country[ip]

    known = sum(1 for p in proxies if p.get("_country_code"))
    logger.info(f"GeoIP: страны определены для {known} из {len(proxies)} прокси")
    return proxies