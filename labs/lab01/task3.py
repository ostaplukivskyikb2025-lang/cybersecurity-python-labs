"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування (Варіант 3)."""

import csv
import functools
import hashlib
import json
import os
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 8
HASH_ALGORITHM = "sha1"
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_CSV_PATH = DATA_DIR / "users.csv"
LOG_JSON_PATH = DATA_DIR / "log.json"


class ValidationError(Exception):
    """Власний виняток для помилок валідації довжини пароля."""


def log_event(func: Callable[..., bool]) -> Callable[..., bool]:
    """Декоратор для логування спроб автентифікації у JSON-файл."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> bool:
        username = args[0] if args else kwargs.get("username", "unknown")
        result_bool = False
        try:
            result_bool = func(*args, **kwargs)
            return result_bool
        finally:
            status = "success" if result_bool else "failure"
            safe_args = [username, "***"] if len(args) > 1 else list(args)
            log_entry = {
                "event": "login",
                "user": username,
                "result": status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": safe_args,
                "kwargs": {
                    k: ("***" if k == "password" else v) for k, v in kwargs.items()
                },
            }
            _write_json_log(log_entry)

    return wrapper


def _write_json_log(entry: dict[str, Any]) -> None:
    """Додає запис у JSON-журнал подій."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        logs: list[dict[str, Any]] = []
        if LOG_JSON_PATH.exists():
            with LOG_JSON_PATH.open("r", encoding="utf-8") as file:
                content = file.read().strip()
                if content:
                    logs = json.loads(content)

        logs.append(entry)
        with LOG_JSON_PATH.open("w", encoding="utf-8") as file:
            json.dump(logs, file, indent=4, ensure_ascii=False)
    except (OSError, PermissionError, json.JSONDecodeError) as err:
        print(f"[Помилка логування]: {err}")


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує SHA-1 хеш для конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий (мінімум {MIN_PASSWORD_LENGTH} символів)."
        )

    salted_data = f"{password}{salt}".encode()
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(salted_data)
    return hasher.hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з хешованим паролем."""
    if not username:
        raise ValueError("Ім'я користувача не може бути порожнім.")
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    """Обробляє список користувачів та зберігає їх у CSV-базу."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with USERS_CSV_PATH.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password_hash"])
        for username, password in users_list:
            try:
                user_record = create_user(username, password)
                writer.writerow(user_record)
            except (ValueError, ValidationError) as err:
                print(f"[Пропущено користувача '{username}']: {err}")


def read_users_db() -> list[dict[str, str]]:
    """Зчитує базу користувачів із CSV-файлу."""
    if not USERS_CSV_PATH.exists():
        raise FileNotFoundError(f"Файл бази даних не знайдено: {USERS_CSV_PATH}")

    with USERS_CSV_PATH.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return list(reader)


@log_event
def login(username: str, password: str) -> bool:
    """Автентифікує користувача за даними з CSV-бази."""
    if not username or not password:
        raise ValueError("Логін та пароль обов'язкові для входу.")

    users_db = read_users_db()
    target_hash = generate_hash(password, PERSONAL_SALT)

    for row in users_db:
        if row["username"] == username and row["password_hash"] == target_hash:
            return True
    return False


def main() -> None:
    """Головна функція запуску модуля реєстрації та автентифікації."""
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print(f"Алгоритм: {HASH_ALGORITHM.upper()} | Сіль: '{PERSONAL_SALT}'\n")

    users_to_register = (
        ("security_chief", "ChiefPass#2026"),
        ("network_admin", "NetAdmin!99"),
        ("help_desk", "HelpDesk2026"),
        ("auditor_ext", "Audit$ecure1"),
        ("soc_analyst", "SocAlert#77"),
        ("incident_lead", "Resp0nse!Team"),
        ("dev_sec_ops", "Pipeline@2026"),
        ("crypto_eng", "CipherKey#88"),
        ("threat_intel", "Hunter!2026"),
        ("sys_operator", "Operator$123"),
    )

    try:
        create_users(users_to_register)

        users_db = read_users_db()
        print("=== База користувачів (users.csv) ===")
        print(f"{'Логін':<18} | {'SHA-1 Хеш пароля'}")
        print("-" * 62)
        for user in users_db:
            print(f"{user['username']:<18} | {user['password_hash']}")

        print("\n=== Тестування автентифікації ===")
        test_attempts = [
            ("security_chief", "ChiefPass#2026"),
            ("network_admin", "WrongPassword1"),
            ("unknown_user", "SomePass123!"),
            ("help_desk", "short"),
            ("", "SomePass123!"),
        ]

        for user, pwd in test_attempts:
            try:
                is_authenticated = login(user, pwd)
                status = "УСПІШНО" if is_authenticated else "ВІДМОВА"
                print(f"Вхід користувача '{user}': {status}")
            except (ValidationError, ValueError) as err:
                print(f"Помилка валідації для '{user}': {err}")

    except (OSError, FileNotFoundError, PermissionError) as file_err:
        print(f"Критична помилка роботи з файлами: {file_err}")


if __name__ == "__main__":
    main()
