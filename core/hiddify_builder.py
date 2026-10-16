"""Упрощённый builder для Hiddify (sing-box ядро).
Убирает поля, которые не понимает Hiddify: fallback, include-all,
exclude-type, profile, sniffer, expected-status.
Оставляет только proxies + два select-группы (Auto / Manual).
"""
from typing import Any

import yaml


def build_hiddify_subscription(
    proxies: list[dict[str, Any]],
    group_prefix: str = "BlackFast",
) -> str:
    cleaned = [
        {k: v for k, v in p.items() if not k.startswith("_")}
        for p in proxies
    ]

    auto_name = f"{group_prefix} Auto"
    manual_name = f"{group_prefix} Manual"

    config: dict[str, Any] = {
        "proxies": cleaned,
        "proxy-groups": [
            {
                "name": auto_name,
                "type": "url-test",
                "proxies": [p.get("name") for p in cleaned if p.get("name")],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 150,
            },
            {
                "name": manual_name,
                "type": "select",
                "proxies": [auto_name] + [
                    p.get("name") for p in cleaned if p.get("name")
                ],
            },
        ],
    }

    return yaml.dump(
        config,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=4096,
    )