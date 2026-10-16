"""Генератор base64-подписки для Hiddify и других клиентов
на ядре sing-box / Xray. Формат — стандартный список URI,
упакованный в base64 (universal subscription format).
"""
import base64
import json
from typing import Any


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

    params: list[str] = []
    if p.get("flow"):
        params.append(f"flow={p['flow']}")
    if p.get("tls"):
        params.append("security=tls")
    if p.get("servername"):
        params.append(f"sni={p['servername']}")
    if p.get("client-fingerprint"):
        params.append(f"fp={p['client-fingerprint']}")
    ro = p.get("reality-opts")
    if ro:
        params.append("security=reality")
        if ro.get("public-key"):
            params.append(f"pbk={ro['public-key']}")
        if ro.get("short-id"):
            params.append(f"sid={ro['short-id']}")
    if p.get("network"):
        params.append(f"type={p['network']}")
    ws = p.get("ws-opts")
    if ws:
        if ws.get("path"):
            params.append(f"path={ws['path']}")
        if ws.get("headers", {}).get("Host"):
            params.append(f"host={ws['headers']['Host']}")

    name = p.get("name") or f"{server}:{port}"
    query = "&".join(params)
    return f"vless://{uuid}@{server}:{port}?{query}#{name}"


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
        params.append(f"sni={p['sni']}")
    if p.get("client-fingerprint"):
        params.append(f"fp={p['client-fingerprint']}")
    if p.get("network"):
        params.append(f"type={p['network']}")

    name = p.get("name") or f"{server}:{port}"
    query = "&".join(params)
    return f"trojan://{password}@{server}:{port}?{query}#{name}"


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
        params.append(f"sni={p['sni']}")
    if p.get("skip-cert-verify"):
        params.append("insecure=1")
    if p.get("obfs"):
        params.append(f"obfs={p['obfs']}")
    if p.get("obfs-password"):
        params.append(f"obfs-password={p['obfs-password']}")

    name = p.get("name") or f"{server}:{port}"
    query = "&".join(params)
    return f"hysteria2://{password}@{server}:{port}?{query}#{name}"