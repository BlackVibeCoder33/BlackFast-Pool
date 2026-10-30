import asyncio
import re
import time
from typing import Any

from loguru import logger


_HOST_RE = re.compile(r"^[a-zA-Z0-9._\-]+$")
# Windows-коды DNS-сбоев, которые обычно транзиентные (retry помогает)
_TRANSIENT_ERRNOS = {22, 11001, 11002, 11003}


def _is_valid_hostname(host: str) -> bool:
    """Отсеиваем мусорные хостнеймы ДО попытки соединения.

    - Только ASCII буквы/цифры/точка/дефис/подчёркивание
    - Длина <= 253 (RFC 1035)
    - Не пустой

    Юникод-хостнеймы (китайский, арабский, русский в имени хоста)
    отсеиваются — их DNS-резолв на Windows даёт EINVAL / UnicodeEncodeError.
    """
    if not host or len(host) > 253:
        return False
    return bool(_HOST_RE.match(host))


async def _check_one(
    proxy: dict[str, Any],
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    async with semaphore:
        host = str(proxy.get("server") or "")
        port = proxy.get("port")
        if not host or not port:
            proxy["_tcp_ok"] = False
            proxy["_tcp_error"] = "no host/port"
            return proxy

        # Pre-flight валидация — отсеиваем заведомо битые имена
        # без сетевого вызова. Дешевле, чем ловить EINVAL в OSError.
        if not _is_valid_hostname(host):
            proxy["_tcp_ok"] = False
            proxy["_tcp_error"] = "invalid_hostname"
            return proxy

        start = time.perf_counter()
        last_err: str = "unknown"

        # 2 попытки: на транзиентных DNS-ошибках (Windows WSAHOST_NOT_FOUND=11001
        # и EINVAL=22) второй заход через 0.5 с обычно проходит.
        for attempt in range(2):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                proxy["_tcp_ok"] = True
                proxy["_tcp_ping_ms"] = round(elapsed_ms, 1)
                if attempt > 0:
                    proxy["_tcp_retry"] = attempt
                return proxy
            except asyncio.TimeoutError:
                last_err = "timeout"
                break
            except OSError as e:
                errno = e.errno
                last_err = f"oserr:{errno}"
                if errno in _TRANSIENT_ERRNOS and attempt == 0:
                    await asyncio.sleep(0.5)
                    continue
                break
            except Exception as e:
                last_err = type(e).__name__
                break

        proxy["_tcp_ok"] = False
        proxy["_tcp_error"] = last_err
        return proxy


async def tcp_check_all(
    proxies: list[dict[str, Any]],
    concurrent: int = 200,
    timeout: float = 4.0,
    skip_types: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not proxies:
        return [], []

    skip_types = skip_types or set()

    to_check: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for p in proxies:
        if p.get("type") in skip_types:
            # UDP/QUIC-протоколы: TCP-чек бессмыслен, помечаем «живыми»
            p["_tcp_ok"] = True
            p["_tcp_ping_ms"] = 0.0
            p["_tcp_skip"] = True
            skipped.append(p)
        else:
            to_check.append(p)

    semaphore = asyncio.Semaphore(concurrent)
    tasks = [_check_one(p, timeout, semaphore) for p in to_check]
    checked = await asyncio.gather(*tasks)

    results = list(checked) + skipped

    alive = [p for p in results if p.get("_tcp_ok")]
    dead = [p for p in results if not p.get("_tcp_ok")]

    # Разбивка ошибок TCP — для отладки «0 живых».
    err_counts: dict[str, int] = {}
    for p in dead:
        err = str(p.get("_tcp_error") or "unknown")
        err_counts[err] = err_counts.get(err, 0) + 1

    logger.info(
        f"TCP-чек: проверено {len(checked)}, пропущено (UDP) {len(skipped)}, "
        f"живых {len(alive)}, отсеяно {len(dead)}"
    )
    if err_counts:
        top_err = sorted(err_counts.items(), key=lambda x: -x[1])[:5]
        logger.info(f"TCP-чек: причины отсева top5: {top_err}")

    # Если живых 0 при >100 проверенных — это инцидент, не норма.
    if not alive and len(checked) > 100:
        logger.warning(
            f"[tcp] FAIL: 0 живых из {len(checked)} — "
            f"возможен обрыв сети или DPI-инцидент. "
            f"Проверь соединение и запусти повторно."
        )
    return alive, dead