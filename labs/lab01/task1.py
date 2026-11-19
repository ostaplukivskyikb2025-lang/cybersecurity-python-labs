"""Завдання 1: Комплексний аналізатор надійності паролів (Варіант 3)."""

import os
import random
import string
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "UserPass1!",
    "temp",
    "Cyber$ecurity",
    "guest",
    "P0w3rful@Pass",
    "login",
    "Defens3#2023",
    "abc123",
    "Elit3@Secur",
    "demo",
]

CRITERIA = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {"temp", "guest", "login", "demo", "abc123", "user"}


def evaluate_password(password: str, all_passwords: list[str]) -> str:
    """Оцінює рівень надійності пароля згідно з критеріями варіанта."""
    min_len = CRITERIA["min_length"]

    if password in FORBIDDEN_PASSWORDS or len(password) < min_len:
        return "Заборонений"

    has_digit = any(ch.isdigit() for ch in password)
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_special = any(ch in string.punctuation for ch in password)

    checks = [
        has_digit if CRITERIA["require_digits"] else True,
        has_upper if CRITERIA["require_upper"] else True,
        has_special if CRITERIA["require_special"] else True,
    ]

    any_group = any([has_digit, has_upper, has_lower, has_special])

    if not all(checks):
        if sum([has_digit, has_upper, has_lower, has_special]) >= 2:
            return "Середній"
        if any_group:
            return "Слабкий"
        return "Заборонений"

    is_unique = all_passwords.count(password) == 1
    if len(password) >= min_len + 4 and is_unique:
        return "Дуже сильний"

    return "Сильний"


def main() -> None:
    """Головна функція запуску аналізатора паролів."""
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("-" * 65)

    passwords_list = PASSWORDS.copy()
    for _ in range(3):
        random_idx = random.randint(0, len(PASSWORDS) - 1)
        passwords_list.append(PASSWORDS[random_idx])

    print(
        f"{'№':<4} | {'Пароль':<18} | {'Довжина':<8} | {'Унікальний':<11} | {'Статус'}"
    )
    print("-" * 65)

    for idx, pwd in enumerate(passwords_list, start=1):
        status = evaluate_password(pwd, passwords_list)
        unique_str = "Так" if passwords_list.count(pwd) == 1 else "Ні (дубль)"
        print(f"{idx:<4} | {pwd:<18} | {len(pwd):<8} | {unique_str:<11} | {status}")


if __name__ == "__main__":
    main()
