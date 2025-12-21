from pathlib import Path
import sys
import loguru

# Определяем путь к директории для логов
BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = f"{BASE_DIR}/logs"

logger = loguru.logger

# Настройка уровня логирования
logger.remove()  # Удаляем стандартный обработчик, установленный по умолчанию
# Создаем свой, очень подробный формат с тегами
custom_format = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | " # <level> отвечает за цвет уровня
    "<cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>" # и здесь тоже
)
logger.add(
    f"{LOGS_DIR}/logs.log",
    rotation="10 Mb",
    retention="1 week",
    compression="gz",
    format=custom_format, 
    colorize=True,
    backtrace=True, 
    diagnose=True,
    enqueue=True,
)
# Добавляем обработчик для печати в stdout
logger.add(sys.stderr)
