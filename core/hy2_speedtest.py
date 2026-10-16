import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import yaml
from loguru import logger

from core.paths import base_dir


async def test_hy2_speed(
    hy2_proxies: list[dict[str, Any]],
    min_download_mbps: float = 5.0,
    timeout_sec: int = 300,
) -> list[dict[str, Any]]:
    """
    Тестирует скорость Hysteria2-прокси через clash-speedtest.
    Возвращает только те, что прошли порог скорости.
    """
    if not hy2_proxies:
        return []

    logger.info(f"Hy2-speedtest: {len(hy2_proxies)} серверов, порог {min_download_mbps} Мбит/с")

    # 1. Готовим временный YAML с hy2-прокси
    tmp_dir = base_dir() / "out" / "hy2_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    input_yaml = tmp_dir / "hy2_input.yaml"
    output_yaml = tmp_dir / "hy2_output.yaml"

    clash_proxies = []
    for p in hy2_proxies:
        # Оставляем только те поля, которые понимает Clash/Mihomo
        clean = {k: v for k, v in p.items() if not k.startswith("_")}
        clash_proxies.append(clean)

    with open(input_yaml, "w", encoding="utf-8") as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

    # 2. Запускаем clash-speedtest
    #    -c input_yaml  — входной конфиг
    #    -output output_yaml — куда сохранить отфильтрованный конфиг
    #    -min-download-speed — порог в MB/s (не Мбит/с!)
    #    -fast — пропускаем тесты задержки, только скорость (если поддерживается)
    min_speed_mb = min_download_mbps / 8.0  # Мбит/с -> МБ/с
    cmd = [
        "clash-speedtest",
        "-c", str(input_yaml),
        "-output", str(output_yaml),
        "-min-download-speed", str(min_speed_mb),
        "-fast",
    ]
    logger.info(f"Запуск: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        logger.error("clash-speedtest не завершился за отведённое время")
        return []
    except FileNotFoundError:
        logger.error("clash-speedtest не найден. Установи его: go install github.com/faceair/clash-speedtest@latest")
        return []
    except Exception as e:
        logger.error(f"Ошибка запуска clash-speedtest: {e}")
        return []

    if proc.returncode != 0:
        logger.error(f"clash-speedtest завершился с кодом {proc.returncode}")
        logger.error(f"stderr: {stderr.decode(errors='ignore')[:500]}")
        return []

    # 3. Читаем результат
    if not output_yaml.exists():
        logger.warning("clash-speedtest не создал выходной файл — вероятно, никто не прошёл порог")
        return []

    with open(output_yaml, "r", encoding="utf-8") as f:
        result = yaml.safe_load(f)

    passed_proxies = result.get("proxies", [])
    logger.info(f"Hy2-speedtest: прошло {len(passed_proxies)} из {len(hy2_proxies)}")

    # 4. Возвращаем исходные объекты (с внутренними полями), соответствующие прошедшим
    passed_keys = {(p.get("server"), p.get("port")) for p in passed_proxies}
    passed_original = [
        p for p in hy2_proxies
        if (p.get("server"), p.get("port")) in passed_keys
    ]

    return passed_original