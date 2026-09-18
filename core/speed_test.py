import asyncio
import time
from typing import Any

import aiohttp
from loguru import logger

from core.singbox import run_batch_test


MIN_BYTES = 500_000


async def _measure_one(
    proxy: dict[str, Any],
    http_port: int,
    session: aiohttp.ClientSession,
    test_url: str,
    timeout: float,
) -> dict[str, Any]:
    if proxy.get("_batch_error"):
        proxy["_speed_mbps"] = 0.0
        proxy["_speed_error"] = proxy["_batch_error"]
        return proxy

    proxy_url = f"http://127.0.0.1:{http_port}"
    start = time.perf_counter()
    total = 0
    err = None
    try:
        req_timeout = aiohttp.ClientTimeout(
            total=timeout, sock_connect=8, sock_read=timeout
        )
        async with session.get(
            test_url, proxy=proxy_url, timeout=req_timeout
        ) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"http {resp.status}")
            async for chunk in resp.content.iter_chunked(65536):
                total += len(chunk)
    except asyncio.TimeoutError:
        err = "timeout"
    except Exception as e:
        err = type(e).__name__

    elapsed = time.perf_counter() - start
    if elapsed <= 0:
        elapsed = 0.001

    name = (proxy.get("name") or "?")[:45]

    if total < MIN_BYTES:
        proxy["_speed_mbps"] = 0.0
        proxy["_speed_error"] = err or "too_slow"
        proxy["_downloaded_bytes"] = total
        logger.info(
            f"  0.00 Mbps ({(total/1024):.0f} KB) [{proxy['_speed_error']}]  {name}"
        )
        return proxy

    mbps = total * 8 / elapsed / 1_000_000
    proxy["_speed_mbps"] = round(mbps, 2)
    proxy["_downloaded_bytes"] = total
    proxy["_elapsed_sec"] = round(elapsed, 2)
    logger.info(f"{mbps:>7.2f} Mbps  ({total//1024} KB)  {name}")
    return proxy


async def speed_test_all(
    proxies: list[dict[str, Any]],
    test_url: str,
    timeout: float = 20.0,
    concurrent: int = 4,
) -> list[dict[str, Any]]:
    if not proxies:
        return []

    logger.info(f"Speed-test: {len(proxies)} серверов, батчами по {concurrent}")

    async def _tester_bound(proxy, http_port, session):
        return await _measure_one(proxy, http_port, session, test_url, timeout)

    results = await run_batch_test(
        proxies, tester_fn=_tester_bound, batch_size=concurrent
    )

    for p in results:
        if "_speed_mbps" not in p:
            p["_speed_mbps"] = 0.0
            p["_speed_error"] = p.get("_batch_error", "unknown")

    logger.info("Speed-test завершён")
    return results