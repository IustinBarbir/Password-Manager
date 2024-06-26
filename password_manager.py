import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog, messagebox
from functools import partial
import uuid
import pyperclip
import base64
import random
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b"2444"

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryption_key = b""


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# Database
with sqlite3.connect("password_manager.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recovery_key TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")


# Pop ups
def pop_up(text):
    answer = simpledialog.askstring("input string", text)
    return answer


# Window
window = Tk()
window.update()

window.title("Password Manager")


def hash_password(input):
    hash = hashlib.sha256((input))
    hash = hash.hexdigest()

    return hash


def first_screen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")

    label = Label(window, text="Create master password")
    label.config(anchor=CENTER)
    label.pack()

    text = Entry(window, width=20)
    text.pack()
    text.focus()

    label1 = Label(window, text="Re-enter Password")
    label1.pack()

    text1 = Entry(window, width=20)
    text1.pack()

    def save_password():
        if text.get() == text1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashed_password = hash_password(text.get().encode("utf-8"))
            key = str(uuid.uuid4().hex)
            recovery_key = hash_password(key.encode("utf-8"))

            global encryption_key
            encryption_key = base64.urlsafe_b64encode(kdf.derive(text.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recovery_key)
            VALUES(?, ?) """
            cursor.execute(insert_password, (hashed_password, recovery_key))
            db.commit()

            recovery_screen(key)
        else:
            label.config(text="Passwords do not match")

    button = Button(window, text="Save", command=save_password)
    button.pack(pady=10)


def recovery_screen(key):
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")

    label = Label(window, text="Save the key for recovery")
    label.config(anchor=CENTER)
    label.pack()

    label1 = Label(window, text=key)
    label1.pack()

    def copy_key():
        pyperclip.copy(label1.cget("text"))

    button = Button(window, text="Copy key", command=copy_key)
    button.pack(pady=10)

    def done():
        password_manager()

    button = Button(window, text="Done", command=done)
    button.pack(pady=10)


def reset_screen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")

    label = Label(window, text="Enter recovery key")
    label.config(anchor=CENTER)
    label.pack()

    text = Entry(window, width=20)
    text.pack()
    text.focus()

    label1 = Label(window)
    label.config(anchor=CENTER)
    label1.pack()

    def get_recovery_key():
        recovery_key_check = hash_password(str(text.get()).encode("utf-8"))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recovery_key = ?", [recovery_key_check])
        return cursor.fetchall()

    def check_recovery_key():
        checked = get_recovery_key()
        if checked:
            first_screen()
        else:
            text.delete(0, "end")
            label1.config(text="Wrong key")

    button = Button(window, text="Check key", command=check_recovery_key)
    button.pack(pady=10)


def login_screen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")

    label = Label(window, text="Enter master password")
    label.config(anchor=CENTER)
    label.pack()

    #   for real-life use application use:
    #   text = Entry(window, width=20, show="*")
    text = Entry(window, width=20)
    text.pack()
    text.focus()

    label1 = Label(window)
    label1.pack()

    def get_masterpassword():
        check_hashedPassword = hash_password(text.get().encode("utf-8"))
        global encryption_key
        encryption_key = base64.urlsafe_b64encode(kdf.derive(text.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(check_hashedPassword)])
        print(check_hashedPassword)
        return cursor.fetchall()

    def check_password():
        match = get_masterpassword()

        print(match)

        if match:
            password_manager()
        else:
            text.delete(0, "end")
            label.config(text="Wrong Password")

    def reset_password():
        reset_screen()

    button = Button(window, text="Submit", command=check_password)
    button.pack(pady=10)

    button = Button(window, text="Reset password", command=reset_password)
    button.pack(pady=10)


def remove_entry(input):
    cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
    db.commit()

    password_manager()


def confirmation_popup(entry_id):
    result = messagebox.askyesno("Confirmation", "Are you sure you want to delete this entry?")
    if result:
        remove_entry(entry_id)


def password_manager():
    for widget in window.winfo_children():
        widget.destroy()

    def add_entry():
        website = pop_up("Website")
        if website is not None:
            username = pop_up("Username")
            if username is not None:
                password = pop_up("Password")
                if password is not None:
                    # Encrypt the information before inserting into the database
                    encrypted_website = encrypt(website.encode(), encryption_key)
                    encrypted_username = encrypt(username.encode(), encryption_key)
                    encrypted_password = encrypt(password.encode(), encryption_key)

                    insert_fields = """INSERT INTO vault(website, username, password)
                    VALUES(?, ?, ?)"""

                    cursor.execute(insert_fields, (encrypted_website, encrypted_username, encrypted_password))
                    db.commit()

                    password_manager()

    window.geometry("750x400")
    label = Label(window, text="Password Manager")
    label.grid(column=1)

    button = Button(window, text="Add entry", command=add_entry)
    button.grid(column=1, pady=10)

    label = Label(window, text="Website")
    label.grid(row=3, column=0, padx=80)
    label = Label(window, text="Username")
    label.grid(row=3, column=1, padx=80)
    label = Label(window, text="Password")
    label.grid(row=3, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if cursor.fetchall() != None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if len(array) == 0:
                break

            label1 = Label(window, text=(decrypt(array[i][1], encryption_key).decode("utf-8")), font=("Helvetica", 12))
            label1.grid(column=0, row=i + 4)
            label1 = Label(window, text=(decrypt(array[i][2], encryption_key).decode("utf-8")), font=("Helvetica", 12))
            label1.grid(column=1, row=i + 4)
            label1 = Label(window, text=(decrypt(array[i][3], encryption_key).decode("utf-8)")), font=("Helvetica", 12))
            label1.grid(column=2, row=i + 4)

            button = Button(window, text="Delete", command=partial(confirmation_popup, array[i][0]))
            button.grid(column=3, row=i + 4, pady=10)

            i += 1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break

    # Define and place the "Generate Password" button
    generate_password_button = Button(window, text="Generate Password", command=generate_password_popup)
    generate_password_button.grid(row=2, column=1, pady=10)


# Function to generate a password popup
def generate_password_popup():
    generated_password = generate_password_function()

    popup_window = Toplevel(window)
    popup_window.title("Generated Password")
    popup_window.geometry("300x150")

    label = Label(popup_window, text="Newly Generated Password:")
    label.pack()

    password_label = Label(popup_window, text=generated_password)
    password_label.pack()

    def copy_password():
        pyperclip.copy(generated_password)

    copy_button = Button(popup_window, text="Copy", command=copy_password)
    copy_button.pack()


# Function to generate a password
def generate_password_function():
    # Generate the password with specified requirements
    special_characters = "!@#$%^&*()_+=-"
    digits = string.digits
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase

    # At least one of each
    generated_password = random.choice(special_characters)
    generated_password += random.choice(digits)
    generated_password += random.choice(lowercase_letters)
    generated_password += random.choice(uppercase_letters)

    # Fill up to length 13
    generated_password += ''.join(random.choices(special_characters + digits + lowercase_letters + uppercase_letters, k=9))
    generated_password = ''.join(random.sample(generated_password, len(generated_password)))

    return generated_password


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login_screen()
else:
    first_screen()

window.mainloop()
