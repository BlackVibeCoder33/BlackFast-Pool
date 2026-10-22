import ipaddress
import json
import time
from pathlib import Path
from typing import Any

from loguru import logger


SUBNET_BAN_THRESHOLD = 5
PERMANENT_BAN_STREAK = 10
PERMANENT_BAN_HOURS = 168  # 7 дней
SUBNET_EXTENDED_BAN_HOURS = 24
SUBNET_STRIKE_DECAY_HOURS = 24


def _server_key(proxy: dict[str, Any]) -> str:
    return f"{proxy.get('server')}:{proxy.get('port')}"


def _ip_subnet(server: str) -> str | None:
    """Возвращает /24 подсеть для IPv4, иначе None (домены не трогаем)."""
    if not server:
        return None
    try:
        ip = ipaddress.ip_address(server)
    except ValueError:
        return None
    if ip.version != 4:
        return None
    parts = str(ip).split(".")
    return ".".join(parts[:3]) + ".0/24"


def load_cache(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"servers": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "servers" not in data:
            return {"servers": {}}
        return data
    except Exception as e:
        logger.warning(f"Cache: не удалось прочитать {path}: {e}")
        return {"servers": {}}


def save_cache(path: Path, cache: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            json.dumps(cache, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        logger.warning(f"Cache: не удалось записать {path}: {e}")


def filter_banned(
    proxies: list[dict[str, Any]],
    cache: dict[str, Any],
    ban_duration_hours: float,
) -> list[dict[str, Any]]:
    now = time.time()
    banned: set[str] = set()
    servers = cache.get("servers", {})
    for key, entry in servers.items():
        if entry.get("banned_until", 0) > now:
            banned.add(key)

    result: list[dict[str, Any]] = []
    for p in proxies:
        key = _server_key(p)
        if key in banned:
            continue
        # Прокидываем историю из кэша для последующей сортировки
        entry = servers.get(key)
        if entry:
            p["_success_streak"] = int(entry.get("success_streak", 0) or 0)
            p["_avg_speed"] = float(entry.get("avg_speed", 0) or 0)
        result.append(p)

    if banned:
        logger.info(
            f"Cache: пропущено {len(proxies) - len(result)} серверов из бана "
            f"(активно {len(banned)} ключей)"
        )
    return result


def update_after_run(
    proxies: list[dict[str, Any]],
    cache: dict[str, Any],
    ban_after: int,
    ban_duration_hours: float,
) -> dict[str, Any]:
    now = time.time()
    servers = cache.setdefault("servers", {})
    for p in proxies:
        key = _server_key(p)
        speed = float(p.get("_speed_mbps", 0) or 0)
        services_ok = any(
            v.get("ok") for v in (p.get("_services") or {}).values()
        )
        entry = servers.get(key) or {
            "fail_streak": 0,
            "success_streak": 0,
            "last_seen": now,
            "avg_speed": 0.0,
        }
        entry["last_seen"] = now

        if speed > 0 and services_ok:
            entry["fail_streak"] = 0
            entry["success_streak"] = int(entry.get("success_streak", 0)) + 1
            entry["banned_until"] = 0
            # EMA по скорости: 30% от текущего замера, 70% — от истории.
            # Так «однодневки» с одним удачным замером не всплывают наверх.
            prev_avg = float(entry.get("avg_speed", 0) or 0)
            entry["avg_speed"] = round(0.3 * speed + 0.7 * prev_avg, 2)
        else:
            entry["success_streak"] = 0
            entry["fail_streak"] = int(entry.get("fail_streak", 0)) + 1
            if entry["fail_streak"] >= PERMANENT_BAN_STREAK:
                entry["banned_until"] = now + PERMANENT_BAN_HOURS * 3600
                logger.info(
                    f"Cache: ПЕРМАНЕНТНЫЙ бан {key} на "
                    f"{PERMANENT_BAN_HOURS} ч (streak={entry['fail_streak']})"
                )
            elif entry["fail_streak"] >= ban_after:
                entry["banned_until"] = now + ban_duration_hours * 3600
                logger.info(
                    f"Cache: забанил {key} на {ban_duration_hours:g} ч "
                    f"(streak={entry['fail_streak']})"
                )

        # Прокидываем историю в прокси для последующей сортировки
        p["_success_streak"] = int(entry.get("success_streak", 0) or 0)
        p["_avg_speed"] = float(entry.get("avg_speed", 0) or 0)

        servers[key] = entry

    # Умный бан /24: если в одной подсети >= SUBNET_BAN_THRESHOLD
    # серверов ушли в бан — баним всю подсеть. Это серверный даунтайм
    # у провайдера, нет смысла на следующем прогоне тестировать соседей.
    subnets_db = cache.setdefault("subnets", {})
    _ban_hot_subnets(servers, subnets_db, now, ban_duration_hours)

    return cache


def _ban_hot_subnets(
    servers: dict[str, Any],
    subnets_db: dict[str, Any],
    now: float,
    ban_duration_hours: float,
) -> None:
    """Банит «горячие» /24 подсети, где уже много забаненных серверов.

    Если одна и та же /24 попадает в бан повторно (в пределах
    SUBNET_STRIKE_DECAY_HOURS), срок бана расширяется до
    SUBNET_EXTENDED_BAN_HOURS (24 ч). Логика: единичный даунтайм
    провайдера — случайность, повторный — системная проблема.
    """
    subnet_banned: dict[str, int] = {}
    for key, entry in servers.items():
        if entry.get("banned_until", 0) <= now:
            continue
        ip = key.partition(":")[0]
        subnet = _ip_subnet(ip)
        if subnet:
            subnet_banned[subnet] = subnet_banned.get(subnet, 0) + 1

    hot_subnets = {
        subnet
        for subnet, count in subnet_banned.items()
        if count >= SUBNET_BAN_THRESHOLD
    }
    if not hot_subnets:
        return

    extended_count = 0
    normal_count = 0
    for subnet in hot_subnets:
        s = subnets_db.get(subnet) or {"strikes": 0, "last_hot_at": 0}
        if now - s["last_hot_at"] > SUBNET_STRIKE_DECAY_HOURS * 3600:
            s["strikes"] = 0
        s["strikes"] += 1
        s["last_hot_at"] = now
        subnets_db[subnet] = s

        hours = (
            SUBNET_EXTENDED_BAN_HOURS
            if s["strikes"] >= 2
            else ban_duration_hours
        )
        ban_seconds = hours * 3600
        for key, entry in servers.items():
            if entry.get("banned_until", 0) > now:
                continue
            ip = key.partition(":")[0]
            if _ip_subnet(ip) == subnet:
                entry["banned_until"] = now + ban_seconds
                if hours == SUBNET_EXTENDED_BAN_HOURS:
                    extended_count += 1
                else:
                    normal_count += 1

    if normal_count or extended_count:
        logger.info(
            f"Cache: умный бан подсетей — забанил {normal_count} "
            f"на {ban_duration_hours:g} ч, {extended_count} на "
            f"{SUBNET_EXTENDED_BAN_HOURS} ч из {len(hot_subnets)} "
            f"«горячих» /24"
        )