# Password Manager

## Overview
 Simple and secure Password Manager built using Python and Tkinter for the GUI. It allows users to securely store, manage, and retrieve passwords while protecting sensitive data with encryption.

## Features
- **Master Password**: Secure access with a master password.
- **Password Encryption**: AES-based encryption using the `cryptography` library.
- **Password Vault**: Store and manage credentials securely.
- **Password Generator**: Generate strong passwords.
- **Clipboard Copying**: Copy passwords securely to the clipboard.
- **Search Functionality**: Easily find stored credentials.
- **Recovery Mechanism**: Reset the master password with a recovery key.

## Technologies Used
- **Python** (3.12)
- **SQLite** (for local storage)
- **Tkinter** (GUI framework)
- **Cryptography** (for secure encryption)
- **Pyperclip** (for clipboard management)

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/password-manager.git
   cd password-manager
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Run the application:
   ```sh
   python main.py
   ```

## Usage
- On the first run, set up a **Master Password**.
- Use the password vault to **add, edit, or delete entries**.
- Click on the **Generate Password** button to create a strong password.
- Use the **search bar** to find credentials quickly.
- Reset the master password using the **recovery key** if needed.

## Security Measures
- The master password is **hashed** before storage.
- Stored passwords are **encrypted** using AES-based encryption.
- Recovery keys allow secure password resets without compromising data.



