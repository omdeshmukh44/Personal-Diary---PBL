#!/usr/bin/env python3
"""Personal Diary with Encryption - educational console application.

Diary text is transformed with a Caesar cipher (shift 3) before storage.
This demonstrates basic cryptography; Caesar cipher is NOT secure for real
private information. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes.
"""

from __future__ import annotations

import calendar
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import uuid
from datetime import date, datetime
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "users.json"
DIARY_FILE = BASE_DIR / "diary.json"
EXPORT_DIR = BASE_DIR / "exports"
SHIFT = 3
PBKDF2_ITERATIONS = 300_000


# ---------------------------- JSON file handling ----------------------------

def load_json(path: Path, default: Any) -> Any:
    """Load JSON. Return a fresh default if the file does not exist."""
    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError) as exc:
        # Do not silently replace a damaged data file with empty data.
        raise RuntimeError(
            f"Could not read {path.name}. Your data file may be damaged. "
            "Make a backup before attempting repairs."
        ) from exc


def save_json(path: Path, data: Any) -> None:
    """Save JSON through a temporary file to reduce the risk of partial writes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None

    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent,
            delete=False, suffix=".tmp"
        ) as temporary_file:
            temporary_name = temporary_file.name
            json.dump(data, temporary_file, indent=4, ensure_ascii=False)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temporary_name, path)
    except OSError:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
        raise


# ------------------------------- Encryption ---------------------------------

def encrypt_text(text: str, shift: int = SHIFT) -> str:
    """Encrypt letters with a Caesar shift; preserve case and punctuation."""
    result: list[str] = []
    shift %= 26

    for char in text:
        if "A" <= char <= "Z":
            result.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        elif "a" <= char <= "z":
            result.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        else:
            result.append(char)

    return "".join(result)


def decrypt_text(ciphertext: str, shift: int = SHIFT) -> str:
    """Decrypt Caesar-shifted text by moving letters backwards."""
    return encrypt_text(ciphertext, -shift)


# --------------------------- Password management ----------------------------

def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Return (salt, PBKDF2 hash). The original password is never saved."""
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        PBKDF2_ITERATIONS,
    )
    return salt_hex, digest.hex()


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    try:
        _, actual_hash = hash_password(password, salt_hex)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash)


def read_password(prompt: str) -> str:
    """Hide password input when running in a terminal."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise
    except Exception:
        # Some IDE consoles do not support getpass.
        return input(prompt)


def register_user() -> None:
    users = load_json(USERS_FILE, {})
    username = input("Choose a username (3-30 letters/numbers/._-): ").strip().lower()

    if not re.fullmatch(r"[a-z0-9_.-]{3,30}", username):
        print("Username must be 3-30 characters and contain only letters, numbers, ., _ or -.")
        return
    if username in users:
        print("That username is already registered.")
        return

    password = read_password("Choose a password (at least 8 characters): ")
    if len(password) < 8:
        print("Password must contain at least 8 characters.")
        return

    confirmation = read_password("Enter the password again: ")
    if password != confirmation:
        print("Passwords do not match.")
        return

    salt, password_hash = hash_password(password)
    users[username] = {
        "salt": salt,
        "password_hash": password_hash,
        "password_algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
    }
    save_json(USERS_FILE, users)
    print("Account created successfully. You can now log in.")


def login_user() -> str | None:
    users = load_json(USERS_FILE, {})
    username = input("Username: ").strip().lower()
    account = users.get(username)

    if not isinstance(account, dict):
        print("Incorrect username or password.")
        return None

    password = read_password("Password: ")
    if verify_password(password, account.get("salt", ""), account.get("password_hash", "")):
        print(f"\nWelcome, {username}!")
        return username

    print("Incorrect username or password.")
    return None


# ----------------------------- Diary operations -----------------------------

def load_diary() -> dict[str, list[dict[str, Any]]]:
    data = load_json(DIARY_FILE, {})
    if not isinstance(data, dict):
        raise RuntimeError("diary.json has an unexpected format. Please make a backup.")
    return data


def read_diary_text() -> str:
    print("Write your entry below. Enter a single period (.) on its own line to finish:")
    lines: list[str] = []
    while True:
        line = input()
        if line == ".":
            break
        lines.append(line)
    return "\n".join(lines).strip()


def prompt_entry_date() -> str | None:
    raw_date = input(f"Entry date (YYYY-MM-DD, Enter for today {date.today().isoformat()}): ").strip()
    if not raw_date:
        return date.today().isoformat()
    try:
        return date.fromisoformat(raw_date).isoformat()
    except ValueError:
        print("Invalid date. Please use YYYY-MM-DD, for example 2026-11-15.")
        return None


def add_entry(username: str) -> None:
    entry_date = prompt_entry_date()
    if entry_date is None:
        return

    text = read_diary_text()
    if not text:
        print("Empty entries are not saved.")
        return

    diary = load_diary()
    user_entries = diary.setdefault(username, [])
    entry_id = uuid.uuid4().hex[:8]
    now = datetime.now().isoformat(timespec="seconds")
    user_entries.append({
        "id": entry_id,
        "date": entry_date,
        "created_at": now,
        "updated_at": now,
        "cipher": "caesar-3",
        "text": encrypt_text(text),
    })
    save_json(DIARY_FILE, diary)
    print(f"Entry saved in encrypted form. Entry ID: {entry_id}")


def get_user_entries(username: str) -> list[dict[str, Any]]:
    diary = load_diary()
    entries = diary.get(username, [])
    if not isinstance(entries, list):
        raise RuntimeError("Diary data for this account has an unexpected format.")
    return entries


def display_entries(entries: list[dict[str, Any]], show_text: bool = True) -> None:
    """Display diary entries, including entries saved by the earlier project version."""
    if not entries:
        print("No diary entries found.")
        return

    valid_entries = [entry for entry in entries if isinstance(entry, dict)]
    if not valid_entries:
        print("The diary file contains entries in an unexpected format.")
        return

    for entry in sorted(
        valid_entries,
        key=lambda item: (str(item.get("date", "")), str(item.get("created_at", "")))
    ):
        print("\n" + "-" * 60)
        print(f"ID: {entry.get('id', 'legacy')}  |  Date: {entry.get('date', 'unknown')}")
        if show_text:
            encrypted_text = entry.get("text", "")
            if isinstance(encrypted_text, str):
                print(decrypt_text(encrypted_text))
            else:
                print("[This entry has no readable text field.] ")


def view_entries(username: str) -> None:
    """Show entries for the logged-in user and explain the empty-data case."""
    diary = load_diary()
    entries = diary.get(username, [])

    if not isinstance(entries, list):
        print("Your diary data is not in the expected format.")
        print(f"Diary file being read: {DIARY_FILE}")
        return

    if not entries:
        print("No diary entries are saved for this account yet.")
        print("Choose option 1, add an entry, and finish it with a single '.' on a new line.")
        print(f"Diary file being read: {DIARY_FILE}")
        return

    print(f"\nFound {len(entries)} diary entr{'y' if len(entries) == 1 else 'ies'} for {username}:")
    display_entries(entries)


def find_entry(entries: list[dict[str, Any]], entry_id: str) -> dict[str, Any] | None:
    for entry in entries:
        if entry.get("id", "").lower() == entry_id.lower():
            return entry
    return None


def edit_entry(username: str) -> None:
    diary = load_diary()
    entries = diary.get(username, [])
    if not entries:
        print("You do not have any entries to edit.")
        return

    display_entries(entries, show_text=False)
    entry_id = input("Enter the ID of the entry to edit: ").strip()
    entry = find_entry(entries, entry_id)
    if entry is None:
        print("Entry ID not found.")
        return

    print("Current entry:")
    print(decrypt_text(entry.get("text", "")))
    print("Enter the replacement text:")
    new_text = read_diary_text()
    if not new_text:
        print("Empty entries are not saved; the original entry was kept.")
        return

    entry["text"] = encrypt_text(new_text)
    entry["updated_at"] = datetime.now().isoformat(timespec="seconds")
    save_json(DIARY_FILE, diary)
    print("Entry updated successfully.")


def delete_entry(username: str) -> None:
    diary = load_diary()
    entries = diary.get(username, [])
    if not entries:
        print("You do not have any entries to delete.")
        return

    display_entries(entries, show_text=False)
    entry_id = input("Enter the ID of the entry to delete: ").strip()
    entry = find_entry(entries, entry_id)
    if entry is None:
        print("Entry ID not found.")
        return

    confirm = input(f"Delete entry dated {entry.get('date')}? (y/N): ").strip().lower()
    if confirm != "y":
        print("Deletion cancelled.")
        return

    diary[username] = [
        item for item in entries
        if item.get("id", "").lower() != entry_id.lower()
    ]
    save_json(DIARY_FILE, diary)
    print("Entry deleted successfully.")


# ------------------------------- Search/export -------------------------------

def search_entries(username: str) -> None:
    entries = get_user_entries(username)
    if not entries:
        print("You do not have any diary entries yet.")
        return

    print("\nSearch by: 1. Keyword  2. Date")
    choice = input("Choose an option: ").strip()

    if choice == "1":
        keyword = input("Enter keyword: ").strip().casefold()
        if not keyword:
            print("Please enter a keyword.")
            return
        matches = [
            entry for entry in entries
            if keyword in decrypt_text(entry.get("text", "")).casefold()
        ]
    elif choice == "2":
        search_date = input("Enter date (YYYY-MM-DD): ").strip()
        try:
            search_date = date.fromisoformat(search_date).isoformat()
        except ValueError:
            print("Invalid date format.")
            return
        matches = [entry for entry in entries if entry.get("date") == search_date]
    else:
        print("Invalid option.")
        return

    print(f"\nFound {len(matches)} matching entr{'y' if len(matches) == 1 else 'ies'}:")
    display_entries(matches)


def export_entries(username: str) -> None:
    entries = get_user_entries(username)
    if not entries:
        print("You do not have any diary entries to export.")
        return

    display_entries(entries, show_text=False)
    print("Enter one or more entry IDs separated by commas, or type 'all'.")
    selection = input("Your selection: ").strip()

    if selection.lower() == "all":
        selected = entries
    else:
        requested_ids = {item.strip().lower() for item in selection.split(",") if item.strip()}
        selected = [entry for entry in entries if entry.get("id", "").lower() in requested_ids]
        found_ids = {entry.get("id", "").lower() for entry in selected}
        missing = requested_ids - found_ids
        if missing:
            print("Unknown entry ID(s): " + ", ".join(sorted(missing)))
        if not selected:
            print("No valid entries selected.")
            return

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = EXPORT_DIR / f"{username}_diary_{timestamp}.txt"

    with output_path.open("w", encoding="utf-8") as file:
        file.write(f"Personal Diary Export - User: {username}\n")
        file.write("=" * 60 + "\n\n")
        for entry in selected:
            file.write(f"Date: {entry.get('date', 'unknown')}\n")
            file.write("-" * 60 + "\n")
            file.write(decrypt_text(entry.get("text", "")) + "\n\n")

    print(f"Export complete: {output_path.relative_to(BASE_DIR)}")
    print("Reminder: this export is plain text. Keep it somewhere private.")


# --------------------------------- Calendar ----------------------------------

def show_calendar(username: str) -> None:
    entries = get_user_entries(username)
    today = date.today()
    raw_year = input(f"Year (Enter for {today.year}): ").strip()
    raw_month = input(f"Month 1-12 (Enter for {today.month}): ").strip()

    try:
        year = int(raw_year) if raw_year else today.year
        month = int(raw_month) if raw_month else today.month
        if not 1 <= month <= 12 or not 1 <= year <= 9999:
            raise ValueError
    except ValueError:
        print("Please enter a valid year and month.")
        return

    entry_days: set[int] = set()
    for entry in entries:
        try:
            entry_day = date.fromisoformat(entry.get("date", ""))
            if entry_day.year == year and entry_day.month == month:
                entry_days.add(entry_day.day)
        except (ValueError, TypeError):
            continue

    print(f"\n{calendar.month_name[month]} {year}")
    print("Mo   Tu   We   Th   Fr   Sa   Su")
    for week in calendar.monthcalendar(year, month):
        cells = []
        for day in week:
            if day == 0:
                cells.append("    ")
            else:
                marker = "*" if day in entry_days else " "
                cells.append(f"{day:2d}{marker} ")
        print("".join(cells).rstrip())

    print("\n* = at least one diary entry")
    if entry_days:
        print("Days with entries:", ", ".join(str(day) for day in sorted(entry_days)))
    else:
        print("No entries for this month.")


# --------------------------------- Menus -------------------------------------

def diary_menu(username: str) -> None:
    while True:
        print("\n" + "=" * 48)
        print("       PERSONAL DIARY WITH ENCRYPTION")
        print(f"                  User: {username}")
        print("=" * 48)
        print("1. Add New Diary Entry")
        print("2. View Diary Entries")
        print("3. Edit Diary Entry")
        print("4. Delete Diary Entry")
        print("5. Search Diary Entries")
        print("6. Export Selected Entries")
        print("7. View Calendar")
        print("8. Logout")

        choice = input("\nEnter your choice: ").strip()
        try:
            if choice == "1":
                add_entry(username)
            elif choice == "2":
                view_entries(username)
            elif choice == "3":
                edit_entry(username)
            elif choice == "4":
                delete_entry(username)
            elif choice == "5":
                search_entries(username)
            elif choice == "6":
                export_entries(username)
            elif choice == "7":
                show_calendar(username)
            elif choice == "8":
                print("Logged out successfully.")
                break
            else:
                print("Invalid choice. Please select 1-8.")
        except (OSError, RuntimeError) as exc:
            print(f"Operation could not be completed: {exc}")


def main() -> None:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 48)
    print("       PERSONAL DIARY WITH ENCRYPTION")
    print("=" * 48)

    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        try:
            if choice == "1":
                register_user()
            elif choice == "2":
                username = login_user()
                if username:
                    diary_menu(username)
            elif choice == "3":
                print("Thank you for using Personal Diary with Encryption.")
                break
            else:
                print("Invalid choice. Please select 1, 2 or 3.")
        except (OSError, RuntimeError) as exc:
            print(f"Operation could not be completed: {exc}")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nApplication closed.")
        sys.exit(0)
