"""Генератор base64-подписки для Hiddify и других клиентов
на ядре sing-box / Xray. Формат — стандартный список URI,
упакованный в base64 (universal subscription format).
"""
import base64
import json
from typing import Any
from urllib.parse import quote, urlencode


def _q(value: str) -> str:
    """URL-encode значение для query/fragment."""
    return quote(str(value), safe="")


def build_hiddify_subscription(proxies: list[dict[str, Any]]) -> str:
    links: list[str] = []
    for p in proxies:
        ptype = p.get("type")
        link: str | None = None
        if ptype == "vless":
            link = _build_vless_link(p)
        elif ptype == "vmess":
            link = _build_vmess_link(p)
        elif ptype == "trojan":
            link = _build_trojan_link(p)
        elif ptype == "ss":
            link = _build_ss_link(p)
        elif ptype == "hysteria2":
            link = _build_hysteria2_link(p)
        if link:
            links.append(link)

    if not links:
        return ""

    text = "\n".join(links)
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _build_vless_link(p: dict[str, Any]) -> str | None:
    uuid = p.get("uuid")
    server = p.get("server")
    port = p.get("port")
    if not (uuid and server and port):
        return None

    ro = p.get("reality-opts")
    is_reality = bool(ro and ro.get("public-key"))

    params: list[str] = []

    # security: reality ИЛИ tls — взаимоисключающие, не дублируем.
    if is_reality:
        params.append("security=reality")
        params.append(f"pbk={_q(ro['public-key'])}")
        if ro.get("short-id"):
            params.append(f"sid={_q(ro['short-id'])}")
        # spx (spiderX) — обязателен по спецификации Xray, дефолт "/"
        params.append("spx=%2F")
    elif p.get("tls"):
        params.append("security=tls")

    if p.get("flow"):
        params.append(f"flow={_q(p['flow'])}")
    if p.get("servername"):
        params.append(f"sni={_q(p['servername'])}")
    if p.get("client-fingerprint"):
        params.append(f"fp={_q(p['client-fingerprint'])}")

    network = p.get("network") or "tcp"
    params.append(f"type={_q(network)}")

    ws = p.get("ws-opts")
    if ws:
        if ws.get("path"):
            params.append(f"path={_q(ws['path'])}")
        host = ws.get("headers", {}).get("Host")
        if host:
            params.append(f"host={_q(host)}")

    name = p.get("name") or f"{server}:{port}"
    query = "&".join(params)
    return f"vless://{uuid}@{server}:{port}?{query}#{_q(name)}"


def _build_vmess_link(p: dict[str, Any]) -> str | None:
    uuid = p.get("uuid")
    server = p.get("server")
    port = p.get("port")
    if not (uuid and server and port):
        return None

    obj: dict[str, Any] = {
        "v": "2",
        "ps": p.get("name") or f"{server}:{port}",
        "add": server,
        "port": str(port),
        "id": uuid,
        "aid": str(p.get("alterId", 0)),
        "scy": p.get("cipher", "auto"),
        "net": p.get("network", "tcp"),
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if p.get("tls") else "",
    }
    ws = p.get("ws-opts")
    if ws:
        obj["path"] = ws.get("path", "/")
        obj["host"] = ws.get("headers", {}).get("Host", "")
    if p.get("servername"):
        obj["sni"] = p["servername"]

    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return f"vmess://{b64}"


def _build_trojan_link(p: dict[str, Any]) -> str | None:
    password = p.get("password")
    server = p.get("server")
    port = p.get("port")
    if not (password and server and port):
        return None

    params: list[str] = []
    if p.get("sni"):
        params.append(f"sni={_q(p['sni'])}")
    if p.get("client-fingerprint"):
        params.append(f"fp={_q(p['client-fingerprint'])}")
    network = p.get("network") or "tcp"
    params.append(f"type={_q(network)}")

    name = p.get("name") or f"{server}:{port}"
    query = "&".join(params)
    return (
        f"trojan://{_q(password)}@{server}:{port}?{query}#{_q(name)}"
    )


def _build_ss_link(p: dict[str, Any]) -> str | None:
    method = p.get("cipher")
    password = p.get("password")
    server = p.get("server")
    port = p.get("port")
    if not (method and password and server and port):
        return None

    userinfo = base64.b64encode(
        f"{method}:{password}".encode()
    ).decode("ascii")
    name = p.get("name") or f"{server}:{port}"
    return f"ss://{userinfo}@{server}:{port}#{name}"


def _build_hysteria2_link(p: dict[str, Any]) -> str | None:
    password = p.get("password")
    server = p.get("server")
    port = p.get("port")
    if not (password and server and port):
        return None

    params: list[str] = []
    if p.get("sni"):
        params.append(f"sni={_q(p['sni'])}")
    if p.get("skip-cert-verify"):
        params.append("insecure=1")
    if p.get("obfs"):
        params.append(f"obfs={_q(p['obfs'])}")
    if p.get("obfs-password"):
        params.append(f"obfs-password={_q(p['obfs-password'])}")

    name = p.get("name") or f"{server}:{port}"
    query = "&".join(params)
    return (
        f"hysteria2://{_q(password)}@{server}:{port}?{query}#{_q(name)}"
    )