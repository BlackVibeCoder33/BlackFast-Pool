from typing import Any

from loguru import logger


def filter_and_rank(
    proxies: list[dict[str, Any]],
    required_services: list[str],
    min_speed_mbps: float,
) -> list[dict[str, Any]]:
    passed: list[dict[str, Any]] = []
    for p in proxies:
        svc = p.get("_services", {})
        if not all(svc.get(req, {}).get("ok") for req in required_services):
            continue
        if p.get("_speed_mbps", 0) < min_speed_mbps:
            continue
        passed.append(p)
    logger.info(
        f"Фильтр ({'+'.join(required_services)}): {len(passed)} из {len(proxies)}"
    )
    return passed


def build_profiles(
    proxies: list[dict[str, Any]],
    profiles: list[dict[str, Any]],
    min_speed_mbps: float,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        path = profile["path"]
        required = profile["required_services"]
        profile_min_speed = float(profile.get("min_speed_mbps", min_speed_mbps))
        exclude_patterns = [
            str(x).lower()
            for x in profile.get("exclude_name_contains", [])
            if x
        ]

        selected: list[dict[str, Any]] = []
        excluded_by_pattern = 0
        for p in proxies:
            svc = p.get("_services", {})
            if not all(svc.get(req, {}).get("ok") for req in required):
                continue
            if p.get("_speed_mbps", 0) < profile_min_speed:
                continue
            if exclude_patterns:
                haystack = f"{p.get('name') or ''} {p.get('server') or ''}".lower()
                if any(pat in haystack for pat in exclude_patterns):
                    excluded_by_pattern += 1
                    continue
            selected.append(p)

        result[path] = selected

        sources: dict[str, int] = {}
        for p in selected:
            s = p.get("_source") or "unknown"
            sources[s] = sources.get(s, 0) + 1
        source_str = ", ".join(f"{k}={v}" for k, v in sources.items())
        excluded_str = (
            f", исключено по фильтру: {excluded_by_pattern}"
            if excluded_by_pattern
            else ""
        )
        logger.info(
            f"Профиль '{path}' ({'+'.join(required)}) min_speed={profile_min_speed:g}: "
            f"{len(selected)} серверов [{source_str}]{excluded_str}"
        )
    return result


def ensure_unique_names(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, int] = {}
    for p in proxies:
        base = (p.get("name") or "Server").strip()
        if base not in seen:
            seen[base] = 0
            p["name"] = base
            continue
        seen[base] += 1
        p["name"] = f"{base} [{p.get('server')}:{p.get('port')}]"
    return proxies


def sort_alphabetically(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(proxies, key=lambda p: (p.get("name") or "").lower())