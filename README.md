# Personal-Diary---PBL

A beginner-friendly, menu-driven console application implementing Project 07.

## Features

- User registration and login
- Password verification using salted PBKDF2-HMAC-SHA256 hashes
- Create, view, edit and delete dated diary entries
- Caesar cipher encryption (shift 3) before diary entries are saved
- Search by keyword or date
- Export one, several, or all selected entries to a decrypted `.txt` file
- Calendar view marking days that contain diary entries
- Multiple entries on the same date (each entry has its own ID)
- JSON file storage using Python's standard library

## Requirements

- Python 3.10 or newer recommended
- No third-party packages required

## Run the application

1. Extract the ZIP file.
2. Open a terminal in the extracted `personal_diary_project` folder.
3. Run `python3 main.py` (on Windows, `python main.py`).
4. Select `1. Register`, create an account, then select `2. Login`.
5. Use the diary menu to manage your entries.

## Important: completing a diary entry

When adding an entry, type your diary text. To finish, type a single period (`.`) on a new line and press Enter. The application will then save the entry and return to the diary menu. After that, choose `2. View Diary Entries`.

## Data files

The application creates these files in the same folder as `main.py`:

- `users.json` — usernames, salts and password hashes (not plaintext passwords)
- `diary.json` — diary entries stored using Caesar cipher text
- `exports/` — plaintext files created by the export feature

The View option now reports the exact `diary.json` path it checked when the logged-in account has no entries. This helps identify when a different extracted project copy is being run.

## How the encryption works

The Caesar cipher moves each English letter three positions forward. For example, `HELLO` becomes `KHOOR`. Decryption shifts letters three positions backward. Uppercase and lowercase letters are preserved, and punctuation, spaces, and numbers are left unchanged.

**Security limitation:** Caesar cipher is easily cracked and is included because the assignment specifically asks for it. It does not provide real privacy or strong encryption. A production app should use authenticated encryption such as AES-GCM or ChaCha20-Poly1305, with securely managed keys. Exported text files are also unencrypted.

## Entry editing and deletion

Each new entry receives an eight-character ID, so multiple entries can be stored on the same date. Use that ID when editing, deleting, or exporting selected entries. Older entries without IDs remain viewable and searchable.

## Data recovery

The program avoids silently overwriting a JSON file if it cannot be read. Make regular backups of the project folder, especially `users.json` and `diary.json`.
