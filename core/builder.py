from typing import Any

import yaml


DNS_CONFIG: dict[str, Any] = {
    "enable": True,
    "prefer-h3": False,
    "ipv6": False,
    "use-hosts": True,
    "use-system-hosts": True,
    "respect-rules": False,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter-mode": "blacklist",
    "fake-ip-filter": [
        "*.lan", "*.local", "localhost",
        "time.*.com", "time.*.gov", "time.*.apple.com", "time-ios.apple.com",
        "time1.*.com", "time2.*.com", "time3.*.com", "time4.*.com",
        "time5.*.com", "time6.*.com", "time7.*.com",
        "ntp.*.com", "ntp1.*.com", "ntp2.*.com", "ntp3.*.com", "ntp4.*.com",
        "ntp5.*.com", "ntp6.*.com", "ntp7.*.com", "*.pool.ntp.org",
        "+.push.apple.com",
        "+.stun.*.*", "+.stun.*.*.*", "+.stun.*.*.*.*", "+.stun.*.*.*.*.*",
        "+.stun.playstation.net",
        "lens.l.google.com", "*.n.n.srv.nintendo.net",
        "xbox.*.*.microsoft.com", "*.*.xboxlive.com",
        "*.msftncsi.com", "*.msftconnecttest.com",
        "WORKGROUP",
    ],
    "cache-algorithm": "arc",
    "default-nameserver": [
        "8.8.8.8", "8.8.4.4", "9.9.9.9", "94.140.14.14",
        "76.76.2.0", "76.76.10.0", "1.0.0.1", "1.1.1.1",
        "208.67.220.220", "208.67.222.222",
    ],
    "nameserver": [
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://dns.adguard-dns.com/dns-query",
        "https://freedns.controld.com/p0",
        "https://dns.mullvad.net/dns-query",
        "https://cloudflare-dns.com/dns-query",
        "https://doh.opendns.com/dns-query",
        "https://doh.libredns.gr/dns-query",
        "https://doh.dns4all.eu/dns-query",
        "https://wikimedia-dns.org/dns-query",
        "https://dns.hostux.net/dns-query",
        "https://blank.dnsforge.de/dns-query",
    ],
    "proxy-server-nameserver": [
        "8.8.8.8", "8.8.4.4", "9.9.9.9", "94.140.14.14",
        "76.76.2.0", "76.76.10.0", "1.0.0.1", "1.1.1.1",
        "208.67.220.220", "208.67.222.222", "system",
    ],
    "direct-nameserver": [
        "8.8.8.8", "8.8.4.4", "9.9.9.9", "94.140.14.14",
        "76.76.2.0", "76.76.10.0", "1.0.0.1", "1.1.1.1",
        "208.67.220.220", "208.67.222.222", "system",
    ],
    "direct-nameserver-follow-policy": False,
}


SNIFFER_CONFIG: dict[str, Any] = {
    "enable": True,
    "force-dns-mapping": True,
    "parse-pure-ip": True,
    "override-destination": False,
    "sniff": {
        "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
        "TLS": {"ports": [443, 8443]},
        "QUIC": {"ports": [443, 8443]},
    },
}


BASE_RULES: list[str] = [
    "DOMAIN-SUFFIX,localhost,DIRECT",
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,lan,DIRECT",
    "DOMAIN-REGEX,^[^.]+$,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    "DOMAIN-SUFFIX,ru,DIRECT",
    "DOMAIN-SUFFIX,xn--p1ai,DIRECT",
    "GEOSITE,category-ru,DIRECT",
    "GEOIP,RU,DIRECT",
]


INTERNAL_PREFIX = "_"


def _clean_proxy(p: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in p.items() if not k.startswith(INTERNAL_PREFIX)}


def build_subscription(
    proxies: list[dict[str, Any]],
    group_prefix: str = "BlackFast",
) -> str:
    cleaned = [_clean_proxy(p) for p in proxies]
    auto_name = f"{group_prefix} Auto"
    manual_name = f"{group_prefix} Manual"

    rules = list(BASE_RULES) + [f"MATCH,{manual_name}"]

    config: dict[str, Any] = {
        "mode": "rule",
        "unified-delay": True,
        "tcp-concurrent": True,
        "keep-alive-idle": 300,
        "keep-alive-interval": 60,
        "disable-keep-alive": False,
        "profile": {
            "store-selected": True,
            "store-fake-ip": True,
        },
        "dns": DNS_CONFIG,
        "sniffer": SNIFFER_CONFIG,
        "proxies": cleaned,
        "proxy-groups": [
            {
                "name": auto_name,
                "type": "url-test",
                "include-all": True,
                "exclude-type": "Direct|Reject|RejectDrop|Compatible|Pass|Dns",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 150,
                "lazy": True,
                "timeout": 5000,
                "max-failed-times": 2,
                "expected-status": 204,
            },
            {
                "name": manual_name,
                "type": "select",
                "proxies": [auto_name],
                "include-all": True,
                "exclude-type": "Direct|Reject|RejectDrop|Compatible|Pass|Dns",
                "default-selected": auto_name,
            },
            {
                "name": "GLOBAL",
                "type": "select",
                "proxies": [auto_name, manual_name],
                "default-selected": auto_name,
            },
        ],
        "rules": rules,
    }

    return yaml.dump(
        config,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=4096,
    )