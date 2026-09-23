import json
import time
from pathlib import Path
from typing import Any

from loguru import logger


def _server_key(proxy: dict[str, Any]) -> str:
    return f"{proxy.get('server')}:{proxy.get('port')}"


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
    ban_seconds = ban_duration_hours * 3600
    banned: list[str] = []
    servers = cache.get("servers", {})
    for key, entry in servers.items():
        banned_until = entry.get("banned_until", 0)
        if banned_until > now:
            banned.append(key)
    if not banned:
        return proxies
    banned_set = set(banned)
    before = len(proxies)
    result = [p for p in proxies if _server_key(p) not in banned_set]
    logger.info(
        f"Cache: пропущено {before - len(result)} серверов из бана "
        f"(активно {len(banned_set)} ключей)"
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
        }
        entry["last_seen"] = now

        if speed > 0 and services_ok:
            entry["fail_streak"] = 0
            entry["success_streak"] = int(entry.get("success_streak", 0)) + 1
            entry["banned_until"] = 0
        else:
            entry["success_streak"] = 0
            entry["fail_streak"] = int(entry.get("fail_streak", 0)) + 1
            if entry["fail_streak"] >= ban_after:
                entry["banned_until"] = now + ban_duration_hours * 3600
                logger.info(
                    f"Cache: забанил {key} на {ban_duration_hours:g} ч "
                    f"(streak={entry['fail_streak']})"
                )
        servers[key] = entry
    return cache