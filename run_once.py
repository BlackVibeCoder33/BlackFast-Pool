"""
Однократный прогон pipeline — для GitHub Actions и локального анализа.

Запуск:
    python run_once.py            # GHA-режим (concurrent_github, лог *_gha.log)
    python run_once.py --local    # Локальный режим (concurrent_pc, лог *_local.log)
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

import yaml
from loguru import logger

from core.pipeline import run_core_pipeline
from core.singbox import set_anti_dpi


PIPELINE_LOGS_KEEP = 20


def _setup_pipeline_logging(is_local: bool) -> Path:
    """Пишет лог текущего прогона в logs/pipeline_<ts>_<mode>.log.
    Удаляет старые pipeline-логи, оставляя PIPELINE_LOGS_KEEP последних.
    Возвращает путь к файлу лога текущего прогона.
    """
    from datetime import datetime

    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    mode = "local" if is_local else "gha"
    log_path = logs_dir / f"pipeline_{ts}_{mode}.log"

    old = sorted(logs_dir.glob("pipeline_*.log"))
    for f in old:
        if len(old) - old.index(f) > PIPELINE_LOGS_KEEP - 1:
            try:
                f.unlink()
            except Exception:
                pass

    return log_path


async def run(config: dict, is_local: bool) -> None:
    result = await run_core_pipeline(config, is_github=not is_local)

    out_dir = Path("out")
    out_dir.mkdir(exist_ok=True)

    for profile in config.get("subscription_profiles", []):
        path = profile["path"]
        filename = profile.get("filename", f"{path}.yaml")
        base_name = filename.replace(".yaml", "")
        hiddify_filename = f"Hiddify-{base_name}.txt"

        # Сохраняем YAML для Karing
        if path in result.yaml_subscriptions:
            (out_dir / filename).write_text(result.yaml_subscriptions[path], encoding="utf-8")

        # Сохраняем base64 TXT для Hiddify — только если не karing_only
        if not profile.get("karing_only", False) and path in result.hiddify_subscriptions:
            (out_dir / hiddify_filename).write_text(result.hiddify_subscriptions[path], encoding="utf-8")

    # Сохраняем статистику воронки
    stats_path = out_dir / "stats.json"
    stats = {
        "mode": "local" if is_local else "gha",
        "total_fetched": result.total_fetched,
        "total_tcp_alive": result.total_tcp_alive,
        "total_speed_passed": result.total_speed_passed,
        "profiles": result.counts,
    }
    stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(f"Статистика сохранена в {stats_path}")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Однократный прогон pipeline BlackFast-Pool"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Локальный режим: concurrent_pc (6) вместо concurrent_github (8), "
             "лог с суффиксом _local. Для анализа на своём ПК.",
    )
    args = parser.parse_args()

    log_path = _setup_pipeline_logging(args.local)

    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add(log_path, level="INFO", encoding="utf-8")
    logger.info(f"Режим: {'LOCAL' if args.local else 'GITHUB'}")
    logger.info(f"Лог прогона: {log_path}")

    with open("config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    set_anti_dpi(config.get("anti_dpi", {}))

    await run(config, is_local=args.local)


if __name__ == "__main__":
    asyncio.run(main())