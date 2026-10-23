"""Фильтр «фейковых» скоростей через CloudFlare.

Публичные подписки часто содержат прокси, чей IP принадлежит CloudFlare.
Через них `dl.google.com` (тоже на CF) отдаётся из кэша с космической
скоростью (500–1200 Mbps), но при реальном трафике (YouTube, Telegram)
такой прокси либо умирает, либо даёт 1–5 Mbps.

Отсеиваем такие серверы после speed-test, до формирования профилей.
"""
import ipaddress
from typing import Any

from loguru import logger


CDN_RANGES = [
    # CloudFlare IPv4
    "104.16.0.0/13", "104.24.0.0/14",
    "172.64.0.0/13", "162.158.0.0/15",
    "173.245.48.0/20", "103.21.244.0/22",
    "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17",
    "131.0.72.0/22",
    # CloudFlare IPv6
    "2400:cb00::/32",
    "2405:8100::/32", "2405:b500::/32",
    "2606:4700::/32", "2803:f800::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]

_CDN_NETWORKS = [ipaddress.ip_network(n) for n in CDN_RANGES]


def _is_cdn_ip(server: str) -> bool:
    if not server:
        return False
    try:
        ip = ipaddress.ip_address(server)
    except ValueError:
        return False
    return any(ip in net for net in _CDN_NETWORKS)


def filter_fake_speeds(
    proxies: list[dict[str, Any]],
    max_plausible_mbps: float = 500.0,
) -> list[dict[str, Any]]:
    """Убирает CDN-прокси с нереально высокой скоростью.

    Порог 500 Mbps эмпирический: реальный VPN через публичный сервер
    редко даёт >500 Mbps — это уже физика канала. А CF-to-CF кэш
    `dl.google.com` легко выдаёт 800–1200 Mbps.
    """
    result: list[dict[str, Any]] = []
    removed_cf_ip = 0
    removed_cf_domain = 0
    for p in proxies:
        speed = float(p.get("_speed_mbps", 0) or 0)
        if speed <= max_plausible_mbps:
            result.append(p)
            continue

        server = str(p.get("server") or "")
        if _is_cdn_ip(server):
            removed_cf_ip += 1
            continue

        # Проверяем: сервер — это IP или домен?
        # Если IP — оставляем (>500 Mbps на реальном IP возможны, это VPS с платным каналом).
        # Если домен — почти всегда CF-кэш, отсеиваем как suspect.
        try:
            ipaddress.ip_address(server)
            # Настоящий IP, не в CF-диапазоне, но > max_plausible_mbps.
            # Оставляем: может быть реальный быстрый сервер.
            result.append(p)
        except ValueError:
            # Домен + нереальная скорость = CF-кэш `dl.google.com` через CF-прокси.
            removed_cf_domain += 1
            continue

    if removed_cf_ip or removed_cf_domain:
        logger.info(
            f"CDN-фильтр: убрано {removed_cf_ip + removed_cf_domain} серверов "
            f"(CF-IP: {removed_cf_ip}, домены с >{max_plausible_mbps:g} Mbps: "
            f"{removed_cf_domain})"
        )
    return result