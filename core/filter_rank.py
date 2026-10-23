import re
from typing import Any

from loguru import logger


_JUNK_NAME_WORDS = {
    "channel", "free", "all", "server", "vpn", "node",
    "config", "unlimited", "join", "telegram", "proxy",
    "keys", "net", "network", "direct", "fast", "new",
    "premium", "upgrade", "best", "top", "super", "our",
}


def _code_to_flag(code: str) -> str:
    """ISO-код страны → эмодзи-флаг."""
    if not code or len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def _is_junk_name(name: str) -> bool:
    n = name.strip()
    if not n:
        return True
    # Совсем короткое без букв (?, !, →)
    if len(n) < 4 and not any(c.isalpha() for c in n):
        return True
    # Нет ни латинских/кириллических букв, ни цифр — только эмодзи/спецсимволы
    if not re.search(r"[a-zA-Zа-яА-ЯёЁ0-9]", n):
        return True
    # Телеграм-хендлы, ссылки, каналы
    if "@" in n or "t.me" in n.lower() or "telegram" in n.lower():
        return True
    # Все значимые слова имени — мусорные ("Channel", "All", "OurChannel")
    words = re.findall(r"[a-zA-Zа-яА-ЯёЁ]+", n.lower())
    if words and all(w in _JUNK_NAME_WORDS for w in words):
        return True
    # Одно латинское/кириллическое слово без разделителей — бренд канала,
    # а не адрес сервера: "EPODONIOS", "surfboardv2ray", "OurChannel"
    if (
        len(words) == 1
        and not re.search(r"[.:/_\- ]", n)
        and len(words[0]) >= 5
    ):
        return True
    # Бренд с подчёркиванием и мусорным словом: "Alfred_Config", "Capital_NET"
    if "_" in n and any(w in _JUNK_NAME_WORDS for w in words):
        return True
    return False


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
    max_service_latency_ms: float | None = None,
    thresholds_by_type: dict[str, dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    thresholds_by_type = thresholds_by_type or {}
    result: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        path = profile["path"]
        required = profile["required_services"]
        profile_min_speed = float(profile.get("min_speed_mbps", min_speed_mbps))
        allow_russian = bool(profile.get("allow_russian", False))
        exclude_patterns = [
            str(x).lower()
            for x in profile.get("exclude_name_contains", [])
            if x
        ]
        exclude_geo = [str(x).lower() for x in profile.get("exclude_geo", [])]
        exclude_geo_iso = {
            g.upper() for g in exclude_geo if len(g) == 2 and g.isalpha()
        }

        selected: list[dict[str, Any]] = []
        excluded_by_pattern = 0
        excluded_russian = 0
        excluded_by_latency = 0
        excluded_by_geo = 0
        for p in proxies:
            if p.get("_is_russian") and not allow_russian:
                excluded_russian += 1
                continue
            
            if exclude_geo:
                # Собираем все имена дублей (их сохраняет _dedupe в _all_names),
                # чтобы гео-подсказка из «мёртвого» дубля не терялась.
                all_names = p.get("_all_names") or []
                if not all_names:
                    all_names = [p.get("name") or ""]
                all_names = [str(n).lower() for n in all_names if n]

                # Ищем целые слова/флаги, а не подстроки. 
                # Иначе "US" совпадает с "Australia", "Belarus", "Cyprus" и т.д.
                # Для флагов emoji оставляем прямое вхождение.
                def _has_geo_match(name: str) -> bool:
                    for geo in exclude_geo:
                        if len(geo) <= 4:
                            # Короткие коды ищем как отдельные слова
                            import re as _re
                            if _re.search(rf"\b{_re.escape(geo)}\b", name):
                                return True
                            # Для флагов emoji - прямое вхождение
                            if not geo.isalnum() and geo in name:
                                return True
                        else:
                            if geo in name:
                                return True
                    return False
                
                if any(_has_geo_match(n) for n in all_names):
                    excluded_by_geo += 1
                    continue

                # Гео-детект по IP: если _country_code известен и совпадает
                # с ISO-кодом из exclude_geo — исключаем. Закрывает
                # «скрытых американцев» с нейтральными именами.
                country = (p.get("_country_code") or "").upper()
                if country and country in exclude_geo_iso:
                    excluded_by_geo += 1
                    continue
            svc = p.get("_services", {})
            if not all(svc.get(req, {}).get("ok") for req in required):
                continue
            if p.get("_speed_mbps", 0) < profile_min_speed:
                continue

            # Порог задержки до сервиса: свой для каждого типа прокси,
            # если задан в thresholds_by_type, иначе — глобальный.
            ptype = p.get("type") or ""
            type_overrides = thresholds_by_type.get(ptype) or {}
            effective_max_lat = type_overrides.get(
                "max_service_latency_ms", max_service_latency_ms
            )
            if effective_max_lat is not None:
                too_slow = False
                for req in required:
                    ms = svc.get(req, {}).get("ms", 0) or 0
                    if ms > effective_max_lat:
                        too_slow = True
                        break
                if too_slow:
                    excluded_by_latency += 1
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
        
        # Восстанавливаем строку с исключениями
        excluded_str = ""
        if excluded_by_pattern:
            excluded_str += f", исключено по фильтру: {excluded_by_pattern}"
        if excluded_russian:
            excluded_str += f", исключено РФ: {excluded_russian}"
        if excluded_by_latency:
            excluded_str += f", исключено по задержке: {excluded_by_latency}"
        if excluded_by_geo:
            excluded_str += f", исключено по гео: {excluded_by_geo}"

        logger.info(
            f"Профиль '{path}' ({'+'.join(required)}) "
            f"min_speed={profile_min_speed:g}"
            f"{' +РФ' if allow_russian else ''}: "
            f"{len(selected)} серверов [{source_str}]{excluded_str}"
        )

    # Источники, не давшие ни одного сервера ни в один профиль — мусорные.
    # Полезно для чистки config.yaml после расширения пула.
    all_sources: set[str] = set()
    for p in proxies:
        s = p.get("_source")
        if s:
            all_sources.add(s)
    used_sources: set[str] = set()
    for selected in result.values():
        for p in selected:
            s = p.get("_source")
            if s:
                used_sources.add(s)
    dead_sources = sorted(all_sources - used_sources)
    if dead_sources:
        logger.warning(
            f"[sources] мертвые источники (0 серверов ни в один профиль): "
            f"{', '.join(dead_sources)}"
        )
    return result


def ensure_unique_names(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, int] = {}
    for p in proxies:
        base = (p.get("name") or "").strip()

        # Мусорные имена («Channel», «Free», «?», «✨») заменяем на
        # «{флаг} {код} {server}:{port}» — так в Karing сразу видно,
        # что это за сервер. Гео берём из _country_code (geoip.py).
        if _is_junk_name(base):
            code = str(p.get("_country_code") or "").upper()
            flag = _code_to_flag(code) if code else ""
            server = str(p.get("server") or "?")
            port = p.get("port") or "?"
            prefix = f"{flag} {code}".strip() if code else "Server"
            base = f"{prefix} {server}:{port}"

        if not base:
            base = "Server"

        if base not in seen:
            seen[base] = 0
            p["name"] = base
            continue

        # Коллизия: сначала пробуем [server:port]. Если это тоже
        # коллизия (тот же сервер с разными client-fingerprint) —
        # добавляем fp в суффикс, чтобы имена гарантированно различались.
        seen[base] += 1
        candidate = f"{base} [{p.get('server')}:{p.get('port')}]"
        if candidate not in seen:
            seen[candidate] = 0
            p["name"] = candidate
            continue
        seen[candidate] += 1
        fp = str(p.get("client-fingerprint") or "default")
        p["name"] = f"{candidate} [{fp}]"
    return proxies


def sort_alphabetically(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(proxies, key=lambda p: (p.get("name") or "").lower())

def sort_by_speed(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Сортирует прокси по убыванию скорости с бонусом за стабильность.

    Сервер с длинным success_streak (из кэша) получает бонус до 30%
    к скорости — так «однодневки», которые один раз дали 500 Mbps
    и больше не появлялись, уступают стабильным 100-Mbps серверам.
    """
    def _key(p: dict[str, Any]) -> float:
        speed = float(p.get("_speed_mbps", 0) or 0)
        streak = int(p.get("_success_streak", 0) or 0)
        stability_bonus = 1.0 + 0.03 * min(streak, 10)
        return speed * stability_bonus

    return sorted(proxies, key=_key, reverse=True)