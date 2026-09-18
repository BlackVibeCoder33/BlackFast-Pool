import asyncio
import base64
import json
from typing import Any
from urllib.parse import urlparse, parse_qs, unquote

import aiohttp
import yaml
from loguru import logger


async def _fetch_one(session: aiohttp.ClientSession, url: str, name: str) -> str:
    logger.info(f"-> Скачиваю '{name}': {url}")
    timeout = aiohttp.ClientTimeout(total=30)
    async with session.get(url, timeout=timeout) as resp:
        resp.raise_for_status()
        text = await resp.text()
    logger.info(f"   получено {len(text)} байт")
    return text


def _parse_yaml(text: str, source_name: str) -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        logger.error(f"Ошибка YAML в '{source_name}': {e}")
        return []

    if not isinstance(data, dict):
        logger.error(f"'{source_name}': ожидался dict, получен {type(data).__name__}")
        return []

    proxies = data.get("proxies")
    if not proxies:
        logger.warning(f"'{source_name}': ключ 'proxies' отсутствует или пуст")
        return []

    for p in proxies:
        p["_source"] = source_name

    logger.info(f"   из '{source_name}' извлечено {len(proxies)} серверов (YAML)")
    return proxies


SKIP_NAME_PREFIXES = ("[OpenRay]",)


def _parse_uri_list(text: str, source_name: str) -> list[dict[str, Any]]:
    proxies: list[dict[str, Any]] = []
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for uri in line.split():
            uri = uri.strip()
            if not uri:
                continue
            parsed = _parse_single_uri(uri)
            if not parsed:
                continue
            pname = (parsed.get("name") or "").strip()
            if any(pname.startswith(prefix) for prefix in SKIP_NAME_PREFIXES):
                skipped += 1
                continue
            parsed["_source"] = source_name
            parsed["_raw_uri"] = uri
            proxies.append(parsed)
    suffix = f" (пропущено {skipped} мусорных)" if skipped else ""
    logger.info(
        f"   из '{source_name}' извлечено {len(proxies)} серверов "
        f"(URI list){suffix}"
    )
    return proxies


def _parse_single_uri(uri: str) -> dict[str, Any] | None:
    try:
        if uri.startswith("vmess://"):
            return _parse_vmess_uri(uri)
        if uri.startswith("vless://"):
            return _parse_vless_uri(uri)
        if uri.startswith("trojan://"):
            return _parse_trojan_uri(uri)
        if uri.startswith("ss://"):
            return _parse_ss_uri(uri)
        if uri.startswith("hysteria2://") or uri.startswith("hy2://"):
            return _parse_hysteria2_uri(uri)
    except Exception as e:
        logger.debug(f"Не удалось распарсить URI: {uri[:60]}... ({e})")
    return None


def _parse_vmess_uri(uri: str) -> dict[str, Any] | None:
    b64 = uri[len("vmess://"):]
    b64 += "=" * (-len(b64) % 4)
    data = json.loads(base64.b64decode(b64).decode("utf-8"))
    result: dict[str, Any] = {
        "type": "vmess",
        "server": data.get("add", ""),
        "port": int(data.get("port", 0)),
        "uuid": data.get("id", ""),
        "alterId": int(data.get("aid", 0)),
        "cipher": data.get("scy", "auto"),
        "name": data.get("ps", ""),
        "network": data.get("net", "tcp"),
    }

    ws_host = (data.get("host") or "").strip()
    sni = (data.get("sni") or "").strip()

    if data.get("tls") == "tls":
        result["tls"] = True
        if sni:
            result["servername"] = sni
        elif ws_host:
            result["servername"] = ws_host
        result["skip-cert-verify"] = True

    if data.get("net") == "ws":
        ws: dict[str, Any] = {"path": data.get("path", "/")}
        if ws_host:
            ws["headers"] = {"Host": ws_host}
        result["ws-opts"] = ws
    return result


def _parse_vless_uri(uri: str) -> dict[str, Any] | None:
    parsed = urlparse(uri)
    if not parsed.hostname:
        return None
    result: dict[str, Any] = {
        "type": "vless",
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "uuid": unquote(parsed.username) if parsed.username else "",
    }
    if parsed.fragment:
        result["name"] = unquote(parsed.fragment)
    params = parse_qs(parsed.query)
    if "security" in params and params["security"][0] in ("tls", "reality"):
        result["tls"] = True
    if "flow" in params:
        result["flow"] = params["flow"][0]
    if "type" in params:
        result["network"] = params["type"][0]
    if "sni" in params:
        result["servername"] = params["sni"][0]
    if "fp" in params:
        result["client-fingerprint"] = params["fp"][0]
    if "pbk" in params:
        reality: dict[str, Any] = {"public-key": params["pbk"][0]}
        if "sid" in params:
            reality["short-id"] = params["sid"][0]
        result["reality-opts"] = reality
    if "path" in params and result.get("network") == "ws":
        result["ws-opts"] = {"path": params["path"][0]}
    if "host" in params and result.get("network") == "ws":
        if "ws-opts" not in result:
            result["ws-opts"] = {}
        if "headers" not in result["ws-opts"]:
            result["ws-opts"]["headers"] = {}
        result["ws-opts"]["headers"]["Host"] = params["host"][0]
    return result


def _parse_trojan_uri(uri: str) -> dict[str, Any] | None:
    parsed = urlparse(uri)
    if not parsed.hostname:
        return None
    result: dict[str, Any] = {
        "type": "trojan",
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "password": unquote(parsed.username) if parsed.username else "",
    }
    if parsed.fragment:
        result["name"] = unquote(parsed.fragment)
    params = parse_qs(parsed.query)
    if "sni" in params:
        result["sni"] = params["sni"][0]
    if "type" in params:
        result["network"] = params["type"][0]
    if "fp" in params:
        result["client-fingerprint"] = params["fp"][0]
    return result


def _parse_ss_uri(uri: str) -> dict[str, Any] | None:
    parsed = urlparse(uri)
    if not parsed.hostname:
        return None
    result: dict[str, Any] = {
        "type": "ss",
        "server": parsed.hostname,
        "port": parsed.port or 443,
    }
    if parsed.username:
        userinfo = unquote(parsed.username)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
            result["cipher"] = method
            result["password"] = password
        else:
            b64 = userinfo + "=" * (-len(userinfo) % 4)
            decoded = base64.b64decode(b64).decode("utf-8")
            if ":" in decoded:
                method, password = decoded.split(":", 1)
                result["cipher"] = method
                result["password"] = password
    if parsed.fragment:
        result["name"] = unquote(parsed.fragment)
    return result


def _parse_hysteria2_uri(uri: str) -> dict[str, Any] | None:
    if uri.startswith("hysteria2://"):
        rest = uri[len("hysteria2://"):]
    elif uri.startswith("hy2://"):
        rest = uri[len("hy2://"):]
    else:
        return None

    parsed = urlparse("hysteria2://" + rest)
    if not parsed.hostname:
        return None

    result: dict[str, Any] = {
        "type": "hysteria2",
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "password": unquote(parsed.username) if parsed.username else "",
        "tls": True,
    }
    if parsed.fragment:
        result["name"] = unquote(parsed.fragment)

    params = parse_qs(parsed.query)
    if "sni" in params:
        result["sni"] = params["sni"][0]
    if "insecure" in params:
        result["skip-cert-verify"] = params["insecure"][0] in ("1", "true")
    if "obfs" in params:
        result["obfs"] = params["obfs"][0]
    if "obfs-password" in params:
        result["obfs-password"] = params["obfs-password"][0]
    return result


def _parse_subscription(text: str, source_name: str) -> list[dict[str, Any]]:
    stripped = text.lstrip()
    if (
        stripped.startswith("proxies:")
        or "\nproxies:" in stripped
        or stripped.startswith("mode:")
        or "\nmode:" in stripped
    ):
        return _parse_yaml(text, source_name)
    if "://" in text:
        return _parse_uri_list(text, source_name)
    return _parse_yaml(text, source_name)


def _dedupe(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    dupes = 0
    for p in proxies:
        clean = {k: v for k, v in p.items() if not k.startswith("_")}
        try:
            key = json.dumps(clean, sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            key = str(sorted(clean.items()))
        if key in seen:
            dupes += 1
            continue
        seen.add(key)
        unique.append(p)
    logger.info(f"Дедупликация: {len(proxies)} -> {len(unique)} (убрано {dupes})")
    return unique


async def fetch_all(subscriptions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    active = [s for s in subscriptions if s.get("enabled", True)]
    if not active:
        logger.warning("Нет включённых подписок")
        return []

    async with aiohttp.ClientSession() as session:
        tasks = [_fetch_one(session, s["url"], s["name"]) for s in active]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_proxies: list[dict[str, Any]] = []
    for sub, result in zip(active, results):
        if isinstance(result, Exception):
            logger.error(f"Ошибка скачивания '{sub['name']}': {result}")
            continue
        all_proxies.extend(_parse_subscription(result, sub["name"]))

    return _dedupe(all_proxies)


def group_by_server_port(
    proxies: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[tuple, list[dict[str, Any]]]]:
    groups: dict[tuple, list[dict[str, Any]]] = {}
    for p in proxies:
        key = (p.get("server"), p.get("port"))
        if key not in groups:
            groups[key] = []
        groups[key].append(p)

    representatives: list[dict[str, Any]] = []
    for key, group in groups.items():
        representatives.append(group[0])

    return representatives, groups


def expand_representatives(
    representatives: list[dict[str, Any]],
    expansion_map: dict[tuple, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for rep in representatives:
        key = (rep.get("server"), rep.get("port"))
        group = expansion_map.get(key, [rep])
        for p in group:
            p["_tcp_ok"] = rep.get("_tcp_ok")
            p["_tcp_ping_ms"] = rep.get("_tcp_ping_ms")
            p["_services"] = rep.get("_services")
            p["_speed_mbps"] = rep.get("_speed_mbps")
            p["_speed_error"] = rep.get("_speed_error")
            expanded.append(p)
    return expanded