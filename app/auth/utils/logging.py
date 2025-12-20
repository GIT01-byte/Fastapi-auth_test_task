from pathlib import Path
import loguru

# Определяем путь к директории для логов
BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = f"{BASE_DIR}/logs"

logger = loguru.logger

# Настройка уровня логирования
logger.remove()  # Удаляем стандартный обработчик, установленный по умолчанию
logger.add(
    f"{LOGS_DIR}/logs.log",
    rotation="1 week",
    # serialize=True, 
    colorize=True,
    backtrace=True, 
    diagnose=True,
)
# Добавляем обработчик для печати в stdout
logger.add(lambda msg: print(msg), level="DEBUG")
