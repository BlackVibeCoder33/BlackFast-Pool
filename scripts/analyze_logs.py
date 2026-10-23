"""Разбор логов pipeline BlackFast-Pool → структурированный отчёт.

Запуск в VS Code (из корня проекта, там же где config.yaml):
    python scripts/analyze_logs.py                    # все logs/pipeline_*.log
    python scripts/analyze_logs.py logs/pipeline_XXX.log  # конкретный файл

Результат: logs/analysis/report_YYYYMMDD_HHMMSS.md
Папка logs/ в .gitignore — отчёты в гит не попадут.

Что извлекается по каждому прогону:
- Воронка (парсинг → TCP → service-check → speed-test → профили)
- hy2 service-check (%)
- Баны: обычные / перманентные / серверов через /24
- Speed-test: >500/700/1000 Mbps (детектор CF-фейков)
- Ошибки speed-test по типам
- Профили: selected / built / uniq / hiddify (built|skip)
- Junk-имена в speed-test логе (до ensure_unique_names)
- Warnings: подозрительные аномалии
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from loguru import logger


MSK_OFFSET = timedelta(hours=3)

# --- Регексы: воронка ---
RE_RUN_START = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+ \|.* Лог прогона")
RE_PARSED = re.compile(r"\[1\] После парсинга: (\d+)")
RE_RU_PARSED = re.compile(r"\[1\] РФ-серверов после парсинга: (\d+)")
RE_RU_DEDUPE = re.compile(r"Помечено РФ-серверов до дедупа: (\d+), после дедупа: (\d+)")
RE_DEDUPE = re.compile(r"Глобальная дедупликация: (\d+) -> (\d+) \(убрано (\d+) дублей\)")
RE_SPLIT = re.compile(r"\[1\.5\] Разделение: TCP-протоколов (\d+), UDP/hy2 (\d+)")
RE_TCP_UNIQ = re.compile(r"\[1\.5\] TCP уникальных \(server, port\): (\d+)")
RE_TCP_CHECK = re.compile(
    r"TCP-чек: проверено (\d+), пропущено \(UDP\) (\d+), живых (\d+), отсеяно (\d+)"
)
RE_TCP_ALIVE = re.compile(r"\[2\] TCP живых и <= (\d+) мс: (\d+)")
RE_HY2_TO_SVC = re.compile(r"\[2\] hy2 к service-check: (\d+)")
RE_TO_SVC = re.compile(r"\[2\.5\] Всего к service-check: (\d+)")
RE_RU_TO_SVC = re.compile(r"\[2\.5\] РФ-серверов к service-check: (\d+)")
RE_CACHE_SKIPPED = re.compile(r"Cache: пропущено (\d+) серверов из бана")
RE_SVC_START = re.compile(r"Service-check: (\d+) серверов")
RE_SVC_PASSED = re.compile(r"\[2\.5\] Прошли хотя бы один сервис: (\d+) из (\d+)")
RE_HY2_SVC = re.compile(r"\[2\.5\] hy2 прошли service-check: (\d+) из (\d+)")
RE_RU_SVC = re.compile(r"\[2\.5\] РФ-серверов прошли service-check: (\d+)")
RE_SPEED_START = re.compile(r"Speed-test: (\d+) серверов")
RE_GEO_RESOLVED = re.compile(r"GeoIP: резолвлено (\d+) IP")
RE_GEO_DONE = re.compile(r"GeoIP: страны определены для (\d+) из (\d+) прокси")
RE_RU_SPEED = re.compile(r"\[3\] РФ-серверов после speed-test: (\d+)")
RE_DONE = re.compile(r"\[4\] Pipeline завершён за (\d+) с")

# --- Регексы: CDN / баны ---
RE_CDN_FILTER = re.compile(r"CDN-фильтр: убрано (\d+) серверов")
RE_BAN_REGULAR = re.compile(r"Cache: забанил (\S+) на ([\d.]+) ч \(streak=(\d+)\)")
RE_BAN_PERM = re.compile(r"Cache: ПЕРМАНЕНТНЫЙ бан (\S+) на (\d+) ч \(streak=(\d+)\)")
RE_BAN_SUBNET = re.compile(
    r"Cache: умный бан подсетей — забанил (\d+) на ([\d.]+) ч, "
    r"(\d+) на (\d+) ч из (\d+) «горячих» /24"
)

# --- Speed-test строки ---
# `  123.45 Mbps  (9765 KB)  name`
# `  0.00 Mbps (123 KB) [timeout]  name`
RE_SPEED_LINE = re.compile(
    r"(\d+\.\d+) Mbps\s*\((\d+) KB\)(?:\s*\[([^\]]+)\])?\s+(.+)$"
)

# --- Профили ---
RE_PROFILE = re.compile(
    r"Профиль '([^']+)' \(([^)]+)\) min_speed=([\d.]+)(?:\s*\+РФ)?: (\d+) серверов"
)
RE_PROFILE_BUILD = re.compile(
    r"\[profiles\] '([^']+)': (\d+) записей \(уникальных (\d+)\)"
)
RE_HIDDIFY_BUILT = re.compile(r"\[hiddify\] '([^']+)': (\d+) записей")
RE_HIDDIFY_SKIP = re.compile(r"\[hiddify\] '([^']+)': пропущено \(karing_only\)")

# Что считаем мусорными именами (для отчёта — до ensure_unique_names)
JUNK_PATTERNS = [
    "Channel",
    "EPODONIOS",
    "🌐سرور",
    "@Capoit",
    "OurChannel",
    "surfboard2ray",
    "Alfred_Config",
    "Capital_NET",
    "@Vip_Security",
]

# Нормализация verbose-ошибок speed-test
ERROR_PREFIXES = [
    ("timeout", "timeout"),
    ("http 404", "http_404"),
    ("http 500", "http_5xx"),
    ("http 502", "http_5xx"),
    ("http 503", "http_5xx"),
    ("slow_first_200kb", "slow_first_200kb"),
    ("too_slow", "too_slow"),
    ("Cannot connect to host", "cannot_connect_dl_google"),
    ("Response payload is not completed", "payload_incomplete"),
]


@dataclass
class ProfileInfo:
    path: str
    services: str = ""
    min_speed: float = 0.0
    selected: int = 0
    built_records: int = 0
    built_unique: int = 0
    hiddify_records: int = 0
    hiddify_skipped: bool = False


@dataclass
class RunReport:
    source_file: str = ""
    log_time_utc: datetime | None = None

    # Воронка
    parsed: int = 0
    ru_parsed: int = 0
    dedupe_in: int = 0
    dedupe_out: int = 0
    ru_before_dedupe: int = 0
    ru_after_dedupe: int = 0
    tcp_proxies: int = 0
    hy2_proxies: int = 0
    tcp_unique: int = 0
    tcp_checked: int = 0
    tcp_alive_raw: int = 0
    tcp_alive_ping: int = 0
    hy2_to_svc: int = 0
    to_svc: int = 0
    ru_to_svc: int = 0
    cache_skipped: int = 0
    svc_total: int = 0
    svc_passed: int = 0
    hy2_svc_passed: int = 0
    hy2_svc_total: int = 0
    ru_svc_passed: int = 0
    speed_total: int = 0
    geo_resolved: int = 0
    geo_done: int = 0
    geo_total: int = 0
    ru_after_speed: int = 0

    # CDN
    cdn_removed: int = 0

    # Баны
    bans_regular: int = 0
    bans_permanent: int = 0
    subnet_banned_servers: int = 0  # серверов забанено через /24
    subnet_hot_count: int = 0       # «горячих» /24 сработало

    # Speed-test
    speeds_good: int = 0
    speeds_failed: int = 0
    max_speed_mbps: float = 0.0
    max_speed_name: str = ""
    speeds_above_500: int = 0
    speeds_above_700: int = 0
    speeds_above_1000: int = 0
    error_counts: Counter = field(default_factory=Counter)

    # Профили и junk
    profiles: dict[str, ProfileInfo] = field(default_factory=dict)
    junk_hits: Counter = field(default_factory=Counter)

    # Прочее
    duration_sec: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def log_time_msk(self) -> datetime | None:
        if self.log_time_utc is None:
            return None
        return self.log_time_utc + MSK_OFFSET

    @property
    def svc_pct(self) -> float:
        return 100.0 * self.svc_passed / self.svc_total if self.svc_total else 0.0

    @property
    def hy2_svc_pct(self) -> float:
        return 100.0 * self.hy2_svc_passed / self.hy2_svc_total if self.hy2_svc_total else 0.0


def _is_tag_like(s: str) -> bool:
    """Похоже ли на тег ошибки, а не на emoji-флаг в имени.

    Любой codepoint >= 0x1F000 — эмодзи (региональные флаги, символы),
    значит это не тег, а часть имени прокси. Отсекаем такие строки
    из error_counts, чтобы не засорять статистику.
    """
    if not s:
        return False
    return all(ord(ch) < 0x1F000 for ch in s)


def _norm_err(err: str | None) -> str:
    if not err:
        return "(no error tag)"
    if not _is_tag_like(err):
        return "(no error tag)"
    for prefix, label in ERROR_PREFIXES:
        if prefix in err:
            return label
    return err[:80] + "..." if len(err) > 80 else err


def parse_log(path: Path) -> RunReport:
    rep = RunReport(source_file=path.name)
    text = path.read_text(encoding="utf-8", errors="replace")

    # Время берём из имени файла (надёжнее, чем из первой строки)
    m = re.search(r"pipeline_(\d{8})_(\d{6})", path.name)
    if m:
        try:
            rep.log_time_utc = datetime.strptime(
                m.group(1) + m.group(2), "%Y%m%d%H%M%S"
            )
        except ValueError:
            pass
    if rep.log_time_utc is None:
        m = RE_RUN_START.search(text)
        if m:
            rep.log_time_utc = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")

    def _int(regex: re.Pattern, group: int = 1) -> int:
        mm = regex.search(text)
        if not mm:
            return 0
        try:
            return int(mm.group(group))
        except (ValueError, IndexError):
            return 0

    rep.parsed = _int(RE_PARSED)
    rep.ru_parsed = _int(RE_RU_PARSED)

    m = RE_RU_DEDUPE.search(text)
    if m:
        rep.ru_before_dedupe = int(m.group(1))
        rep.ru_after_dedupe = int(m.group(2))

    m = RE_DEDUPE.search(text)
    if m:
        rep.dedupe_in = int(m.group(1))
        rep.dedupe_out = int(m.group(2))

    m = RE_SPLIT.search(text)
    if m:
        rep.tcp_proxies = int(m.group(1))
        rep.hy2_proxies = int(m.group(2))

    rep.tcp_unique = _int(RE_TCP_UNIQ)

    m = RE_TCP_CHECK.search(text)
    if m:
        rep.tcp_checked = int(m.group(1))
        rep.tcp_alive_raw = int(m.group(3))

    m = RE_TCP_ALIVE.search(text)
    if m:
        rep.tcp_alive_ping = int(m.group(2))

    rep.hy2_to_svc = _int(RE_HY2_TO_SVC)
    rep.to_svc = _int(RE_TO_SVC)
    rep.ru_to_svc = _int(RE_RU_TO_SVC)
    rep.cache_skipped = _int(RE_CACHE_SKIPPED)
    rep.svc_total = _int(RE_SVC_START)

    m = RE_SVC_PASSED.search(text)
    if m:
        rep.svc_passed = int(m.group(1))

    m = RE_HY2_SVC.search(text)
    if m:
        rep.hy2_svc_passed = int(m.group(1))
        rep.hy2_svc_total = int(m.group(2))

    rep.ru_svc_passed = _int(RE_RU_SVC)
    rep.speed_total = _int(RE_SPEED_START)
    rep.geo_resolved = _int(RE_GEO_RESOLVED)

    m = RE_GEO_DONE.search(text)
    if m:
        rep.geo_done = int(m.group(1))
        rep.geo_total = int(m.group(2))

    rep.ru_after_speed = _int(RE_RU_SPEED)
    rep.cdn_removed = _int(RE_CDN_FILTER)
    rep.bans_regular = len(RE_BAN_REGULAR.findall(text))
    rep.bans_permanent = len(RE_BAN_PERM.findall(text))

    for mm in RE_BAN_SUBNET.finditer(text):
        rep.subnet_banned_servers += int(mm.group(1)) + int(mm.group(3))
        rep.subnet_hot_count += int(mm.group(5))

    rep.duration_sec = _int(RE_DONE)

    # Speed-test строки
    for line in text.splitlines():
        mm = RE_SPEED_LINE.search(line)
        if not mm:
            continue
        mbps = float(mm.group(1))
        err = mm.group(3)
        name = mm.group(4).strip()

        if err is None and mbps > 0:
            rep.speeds_good += 1
            if mbps > rep.max_speed_mbps:
                rep.max_speed_mbps = mbps
                rep.max_speed_name = name
            if mbps > 500:
                rep.speeds_above_500 += 1
            if mbps > 700:
                rep.speeds_above_700 += 1
            if mbps > 1000:
                rep.speeds_above_1000 += 1
            for junk in JUNK_PATTERNS:
                if junk in name:
                    rep.junk_hits[junk] += 1
        else:
            rep.speeds_failed += 1
            rep.error_counts[_norm_err(err)] += 1

    # Профили
    for mm in RE_PROFILE.finditer(text):
        p = rep.profiles.setdefault(mm.group(1), ProfileInfo(path=mm.group(1)))
        p.services = mm.group(2)
        p.min_speed = float(mm.group(3))
        p.selected = int(mm.group(4))

    for mm in RE_PROFILE_BUILD.finditer(text):
        p = rep.profiles.setdefault(mm.group(1), ProfileInfo(path=mm.group(1)))
        p.built_records = int(mm.group(2))
        p.built_unique = int(mm.group(3))

    for mm in RE_HIDDIFY_BUILT.finditer(text):
        p = rep.profiles.setdefault(mm.group(1), ProfileInfo(path=mm.group(1)))
        p.hiddify_records = int(mm.group(2))

    for mm in RE_HIDDIFY_SKIP.finditer(text):
        p = rep.profiles.setdefault(mm.group(1), ProfileInfo(path=mm.group(1)))
        p.hiddify_skipped = True

    # Warnings
    for path_, p in rep.profiles.items():
        if p.hiddify_records > 0 and p.hiddify_skipped:
            rep.warnings.append(
                f"BUG: '{path_}' одновременно пропущен И собран в Hiddify"
            )
        # tg-flashscore* должны быть karing_only (по config.yaml)
        if path_.startswith("tg-flashscore") and not p.hiddify_skipped and p.hiddify_records > 0:
            rep.warnings.append(
                f"BUG: '{path_}' собран в Hiddify, хотя должен быть karing_only"
            )

    if rep.svc_total > 0 and rep.svc_passed == 0:
        rep.warnings.append("Ни один сервер не прошёл service-check")
    if rep.speeds_above_1000 > 0:
        rep.warnings.append(
            f"{rep.speeds_above_1000} серверов >1000 Mbps — "
            f"CF-фейки не отфильтрованы (cdn_filter.py)"
        )

    return rep


def format_summary_table(reports: list[RunReport]) -> str:
    lines = [
        "| Время (MSK) | Svc≥1 | Svc% | hy2 | Speed | RU spd | >500 | >700 | >1000 | /24 | Прод., с |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in reports:
        ts = r.log_time_msk.strftime("%Y-%m-%d %H:%M") if r.log_time_msk else "?"
        lines.append(
            f"| {ts} | {r.svc_passed}/{r.svc_total} | {r.svc_pct:.1f}% | "
            f"{r.hy2_svc_passed}/{r.hy2_svc_total} | {r.speed_total} | {r.ru_after_speed} | "
            f"{r.speeds_above_500} | {r.speeds_above_700} | {r.speeds_above_1000} | "
            f"{r.subnet_hot_count} | {r.duration_sec} |"
        )
    return "\n".join(lines)


def format_run_detail(r: RunReport) -> str:
    out: list[str] = []
    ts_msk = r.log_time_msk.strftime("%Y-%m-%d %H:%M:%S MSK") if r.log_time_msk else "?"
    ts_utc = r.log_time_utc.strftime("%Y-%m-%d %H:%M:%S UTC") if r.log_time_utc else "?"
    out.append(f"### {ts_msk}  ({ts_utc})")
    out.append(f"*Файл:* `{r.source_file}`")
    out.append("")

    out.append("**Воронка:**")
    out.append(f"- После парсинга: {r.parsed}")
    out.append(f"- РФ после дедупа: {r.ru_after_dedupe} (было {r.ru_before_dedupe})")
    out.append(f"- Дедуп: {r.dedupe_in} → {r.dedupe_out}")
    out.append(f"- TCP: {r.tcp_proxies}, hy2: {r.hy2_proxies}, TCP-уникальных: {r.tcp_unique}")
    out.append(f"- TCP живых ≤ping: {r.tcp_alive_ping} (сырых {r.tcp_alive_raw})")
    out.append(f"- К service-check: {r.to_svc}")
    out.append(f"- Cache пропущено: {r.cache_skipped}")
    out.append(f"- Прошли ≥1 сервис: **{r.svc_passed}/{r.svc_total}** ({r.svc_pct:.1f}%)")
    out.append(f"- hy2 прошли: {r.hy2_svc_passed}/{r.hy2_svc_total} ({r.hy2_svc_pct:.1f}%)")
    out.append(f"- РФ прошли svc: {r.ru_svc_passed}")
    out.append(f"- Speed-test: {r.speed_total}, GeoIP: {r.geo_done}/{r.geo_total}")
    out.append(f"- РФ после speed: {r.ru_after_speed}")
    out.append(f"- CDN-фильтр убрано: {r.cdn_removed}")
    out.append(f"- Продолжительность: {r.duration_sec} с")
    out.append("")

    out.append("**Баны:**")
    out.append(f"- Обычных: {r.bans_regular}, перманентных: {r.bans_permanent}")
    out.append(
        f"- /24: {r.subnet_hot_count} «горячих» подсетей "
        f"→ забанено {r.subnet_banned_servers} серверов"
    )
    out.append("")

    out.append("**Скорости (детектор CF-фейков):**")
    out.append(
        f"- Успешно: {r.speeds_good}, провалено: {r.speeds_failed}"
    )
    out.append(
        f"- >500: {r.speeds_above_500} | >700: {r.speeds_above_700} | "
        f">1000: {r.speeds_above_1000}"
    )
    if r.max_speed_mbps > 0:
        out.append(f"- Максимум: **{r.max_speed_mbps:.2f} Mbps** — `{r.max_speed_name}`")
    out.append("")

    if r.error_counts:
        out.append("**Ошибки speed-test:**")
        for err, cnt in r.error_counts.most_common():
            out.append(f"- `{err}`: {cnt}")
        out.append("")

    if r.junk_hits:
        out.append(
            "**Junk-имена в speed-test логе** *(до ensure_unique_names — это норма)*:"
        )
        for name, cnt in r.junk_hits.most_common():
            out.append(f"- `{name}`: {cnt}")
        out.append("")

    if r.profiles:
        out.append("**Профили:**")
        out.append("| path | svc | min | selected | built | uniq | hiddify |")
        out.append("|---|---|---|---|---|---|---|")
        for path_, p in r.profiles.items():
            if p.hiddify_skipped:
                hid = "⏭ skip"
            elif p.hiddify_records > 0:
                hid = str(p.hiddify_records)
            else:
                hid = "—"
            out.append(
                f"| `{path_}` | {p.services or '?'} | {p.min_speed:g} | "
                f"{p.selected} | {p.built_records} | {p.built_unique} | {hid} |"
            )
        out.append("")

    if r.warnings:
        out.append("**⚠️ Warnings:**")
        for w in r.warnings:
            out.append(f"- {w}")
        out.append("")

    return "\n".join(out)


def format_report(reports: list[RunReport]) -> str:
    out: list[str] = []
    out.append("# BlackFast-Pool — Анализ логов pipeline")
    out.append("")

    if reports and reports[0].log_time_utc and reports[-1].log_time_utc:
        newest = reports[0].log_time_msk
        oldest = reports[-1].log_time_msk
        out.append(f"**Прогонов:** {len(reports)}")
        out.append(
            f"**Диапазон (MSK):** "
            f"{oldest.strftime('%Y-%m-%d %H:%M')} → {newest.strftime('%Y-%m-%d %H:%M')}"
        )
        out.append(f"**Отчёт создан:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        out.append("")
        out.append("*Время в логах — UTC. В отчёте MSK = UTC+3.*")
        out.append("")

    out.append("## Сводная таблица")
    out.append("")
    out.append(format_summary_table(reports))
    out.append("")
    out.append("> **Svc% — главный KPI.** Стабильный днём ~16.3–17.2%, "
               "вечером падает до ~13%. >1000 Mbps = 100% CF-фейк.")
    out.append("")

    out.append("## Детали по прогонам")
    out.append("")
    for r in reports:
        out.append(format_run_detail(r))
        out.append("---")
        out.append("")

    return "\n".join(out)


def _resolve_logs_dir() -> Path | None:
    if Path("logs").exists():
        return Path("logs")
    here = Path(__file__).resolve().parent.parent / "logs"
    if here.exists():
        return here
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Разбор логов pipeline BlackFast-Pool → отчёт в logs/analysis/"
    )
    parser.add_argument(
        "logs",
        nargs="*",
        help="Файлы логов. Без аргументов — все logs/pipeline_*.log",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Куда писать отчёт (по умолчанию logs/analysis)",
    )
    args = parser.parse_args()

    logs_dir = _resolve_logs_dir()
    if logs_dir is None:
        logger.error("Папка logs/ не найдена. Запусти из корня проекта.")
        return 1

    if args.logs:
        paths = [Path(p) for p in args.logs if Path(p).exists()]
    else:
        paths = sorted(logs_dir.glob("pipeline_*.log"))

    if not paths:
        logger.error("Не найдено ни одного лог-файла")
        return 1

    logger.info(f"Обрабатываю {len(paths)} файлов")
    reports: list[RunReport] = []
    for p in paths:
        try:
            rep = parse_log(p)
            reports.append(rep)
            logger.info(
                f"  {p.name}: {rep.svc_passed}/{rep.svc_total} svc "
                f"({rep.svc_pct:.1f}%), >500Mbps={rep.speeds_above_500}"
            )
        except Exception as e:
            logger.error(f"  {p.name}: ошибка разбора: {e}")

    if not reports:
        logger.error("Ни один файл не разобран")
        return 1

    reports.sort(key=lambda r: r.log_time_utc or datetime.min, reverse=True)

    report_text = format_report(reports)

    out_dir = Path(args.out_dir) if args.out_dir else (logs_dir / "analysis")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    out_file.write_text(report_text, encoding="utf-8")

    logger.info("=" * 60)
    logger.info(f"✅ Отчёт сохранён: {out_file}")
    logger.info(f"   Прогонов: {len(reports)}, размер: {len(report_text):,} байт")
    logger.info(f"   Прикрепи этот файл к следующему сообщению")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())