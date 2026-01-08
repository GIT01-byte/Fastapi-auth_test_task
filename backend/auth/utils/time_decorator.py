import time
import functools
import asyncio
from datetime import datetime

def async_timed_report(filename="../reports/async_timed_report.txt"):
    """
    Декоратор для замера времени выполнения асинхронных функций.
    Результаты дописываются в указанный файл.
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Фиксируем время начала
            start_time = time.perf_counter()
            
            try:
                # Выполняем асинхронную функцию
                return await func(*args, **kwargs)
            finally:
                # Фиксируем время окончания даже если функция завершилась с ошибкой
                end_time = time.perf_counter()
                duration = end_time - start_time
                
                # Формируем строку отчета
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                report_line = (f"[{timestamp}] Функция: {func.__name__} | "
                               f"Время выполнения: {duration:.4f} сек.\n")
                
                # Записываем в файл (режим 'a' — дозапись)
                with open(filename, "a", encoding="utf-8") as f:
                    f.write(report_line)
                    
        return wrapper
    return decorator


def timed_report(filename="../reports/sync_timed_report.txt"):
    """
    Декоратор для замера времени выполнения синхронных функций.
    Результаты записываются в файл.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Фиксируем время начала
            start_time = time.perf_counter()
            
            try:
                # Выполняем саму функцию
                result = func(*args, **kwargs)
                return result
            finally:
                # Фиксируем время окончания даже при ошибке
                end_time = time.perf_counter()
                duration = end_time - start_time
                
                # Формируем строку отчета
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                report_line = (f"[{timestamp}] Функция: {func.__name__} | "
                               f"Время выполнения: {duration:.4f} сек.\n")
                
                # Записываем в файл (режим 'a' — дозапись)
                with open(filename, "a", encoding="utf-8") as f:
                    f.write(report_line)
                    
        return wrapper
    return decorator
