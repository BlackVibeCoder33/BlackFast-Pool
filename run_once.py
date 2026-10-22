"""
Однократный прогон pipeline — для GitHub Actions.
"""
import asyncio
import json
import sys
from pathlib import Path

import yaml
from loguru import logger

from core.pipeline import run_core_pipeline
from core.singbox import set_anti_dpi


PIPELINE_LOGS_KEEP = 3


def _setup_pipeline_logging() -> Path:
    """Пишет лог текущего прогона в logs/pipeline_<ts>.log.
    Удаляет старые pipeline-логи, оставляя PIPELINE_LOGS_KEEP последних.
    Возвращает путь к файлу лога текущего прогона.
    """
    from datetime import datetime

    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"pipeline_{ts}.log"

    old = sorted(logs_dir.glob("pipeline_*.log"))
    for f in old:
        if len(old) - old.index(f) > PIPELINE_LOGS_KEEP - 1:
            try:
                f.unlink()
            except Exception:
                pass

    return log_path


async def run(config: dict) -> None:
    result = await run_core_pipeline(config, is_github=True)

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

        # Сохраняем base64 TXT для Hiddify
        if path in result.hiddify_subscriptions:
            (out_dir / hiddify_filename).write_text(result.hiddify_subscriptions[path], encoding="utf-8")

    # Сохраняем статистику воронки
    stats_path = out_dir / "stats.json"
    stats = {
        "total_fetched": result.total_fetched,
        "total_tcp_alive": result.total_tcp_alive,
        "total_speed_passed": result.total_speed_passed,
        "profiles": result.counts
    }
    stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(f"Статистика сохранена в {stats_path}")


async def main() -> None:
    log_path = _setup_pipeline_logging()

    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add(log_path, level="INFO", encoding="utf-8")
    logger.info(f"Лог прогона: {log_path}")

    with open("config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    set_anti_dpi(config.get("anti_dpi", {}))

    await run(config)


if __name__ == "__main__":
    asyncio.run(main())