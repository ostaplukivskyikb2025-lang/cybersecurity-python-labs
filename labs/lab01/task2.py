"""Завдання 2: Багаторівнева система контролю доступу (Варіант 3)."""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "security_chief": {
        "role": "security_officer",
        "clearance": 4,
        "department": "Security",
        "active": True,
    },
    "network_admin": {
        "role": "network_admin",
        "clearance": 3,
        "department": "Network",
        "active": True,
    },
    "help_desk": {
        "role": "support",
        "clearance": 1,
        "department": "Support",
        "active": True,
    },
    "auditor_ext": {
        "role": "auditor",
        "clearance": 3,
        "department": "Audit",
        "active": True,
    },
    "temp_worker": {
        "role": "temporary",
        "clearance": 1,
        "department": "Temp",
        "active": False,
    },
}

RESOURCES = [
    ("incident_reports", 4),
    ("network_topology", 3),
    ("user_manual", 1),
    ("vulnerability_scans", 3),
    ("root_access", 4),
    ("help_tickets", 1),
    ("penetration_tests", 4),
    ("firewall_rules", 3),
    ("software_licenses", 2),
    ("faq_docs", 1),
]

SECURITY_LEVELS = ("Unrestricted", "Limited", "Sensitive", "Classified")
BLOCKED_USERS = {"temp_worker", "fired_employee", "compromised_acc"}


def check_access(username: str, resource_level: int) -> tuple[bool, str]:
    """Перевіряє право доступу користувача до ресурсу заданого рівня."""
    if username not in USERS:
        return False, "User not found"

    if username in BLOCKED_USERS:
        return False, "User is blocked"

    user_data = USERS[username]
    if not user_data.get("active", False):
        return False, "Account inactive"

    if user_data["clearance"] >= resource_level:
        return True, ""

    return False, "Insufficient clearance"


def main() -> None:
    """Головна функція демонстрації системи контролю доступу."""
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("\n=== Список ресурсів системи ===")
    for res_name, level in RESOURCES:
        level_name = SECURITY_LEVELS[level - 1]
        print(f"- {res_name:<22} | Рівень безпеки: {level_name}")

    print("\n=== Журнал перевірки доступу ===")
    test_users = [*list(USERS.keys()), "unknown_hacker"]

    for username in test_users:
        for res_name, res_level in RESOURCES:
            allowed, reason = check_access(username, res_level)
            if allowed:
                print(f"user={username} resource={res_name} -> ALLOW")
            else:
                print(f"user={username} resource={res_name} -> DENY ({reason})")


if __name__ == "__main__":
    main()
