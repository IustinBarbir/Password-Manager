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
    window.geometry("350x150")

    label = Label(window, text="Enter master password")
    label.config(anchor=CENTER)
    label.pack()

    text = Entry(window, width=20, show="*")
    text.pack()
    text.focus()

    label1 = Label(window)
    label1.pack()

    def get_masterpassword():
        check_hashedPassword = hash_password(text.get().encode("utf-8"))
        global encryption_key
        encryption_key = base64.urlsafe_b64encode(kdf.derive(text.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(check_hashedPassword)])
        return cursor.fetchall()

    def check_password():
        match = get_masterpassword()

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


# Function to copy password to clipboard
def copy_password_to_clipboard(password):
    pyperclip.copy(password)


def password_manager():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("900x500")

    # Create a canvas and a scrollbar
    canvas = Canvas(window)
    canvas.pack(side=LEFT, fill=BOTH, expand=1)

    scrollbar = Scrollbar(window, orient=VERTICAL, command=canvas.yview)
    scrollbar.pack(side=RIGHT, fill=Y)

    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    # Create a frame inside the canvas
    frame = Frame(canvas)
    canvas.create_window((0, 0), window=frame, anchor="nw")

    # Password Manager Title
    label = Label(frame, text="Password Manager", font=("Helvetica", 16))
    label.grid(row=0, column=1, columnspan=3)

    add_button = Button(frame, text="Add entry", command=add_entry)
    add_button.grid(row=1, column=1, pady=10)

    # Labels for the columns
    website_label = Label(frame, text="Website", font=("Helvetica", 12, "bold"))
    website_label.grid(row=2, column=0, padx=80)
    username_label = Label(frame, text="Username", font=("Helvetica", 12, "bold"))
    username_label.grid(row=2, column=1, padx=80)
    password_label = Label(frame, text="Password", font=("Helvetica", 12, "bold"))
    password_label.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    entries = cursor.fetchall()

    if entries:
        for i, entry in enumerate(entries):
            # Decrypt and display website, username, and password
            decrypted_website = decrypt(entry[1], encryption_key).decode("utf-8")
            decrypted_username = decrypt(entry[2], encryption_key).decode("utf-8")
            decrypted_password = decrypt(entry[3], encryption_key).decode("utf-8")

            # Display website, username, and password in labels
            website_label = Label(frame, text=decrypted_website, font=("Helvetica", 12))
            website_label.grid(row=i + 3, column=0)
            username_label = Label(frame, text=decrypted_username, font=("Helvetica", 12))
            username_label.grid(row=i + 3, column=1)
            password_label = Label(frame, text=decrypted_password, font=("Helvetica", 12))
            password_label.grid(row=i + 3, column=2)

            # Add "Delete" button for each entry
            delete_button = Button(frame, text="Delete", command=partial(confirmation_popup, entry[0]))
            delete_button.grid(row=i + 3, column=3, padx=10, pady=10)

            # Add "Copy" button for each entry (to copy the password)
            copy_button = Button(frame, text="Copy", command=partial(copy_password_to_clipboard, decrypted_password))
            copy_button.grid(row=i + 3, column=4, padx=10, pady=10)

    # Define and place the "Generate Password" button
    generate_password_button = Button(frame, text="Generate Password", command=generate_password_popup)
    generate_password_button.grid(row=1, column=2, pady=10)


# Function to generate a random password
def generate_password_popup():
    length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))

    def copy_password():
        pyperclip.copy(password)

    messagebox.showinfo("Generated Password", password)
    copy_password()


# Function to add a new entry to the vault
def add_entry():
    website = pop_up("Website")
    username = pop_up("Username")
    password = pop_up("Password")

    encrypted_website = encrypt(website.encode(), encryption_key)
    encrypted_username = encrypt(username.encode(), encryption_key)
    encrypted_password = encrypt(password.encode(), encryption_key)

    insert_fields = """INSERT INTO vault(website, username, password)
    VALUES(?, ?, ?) """
    cursor.execute(insert_fields, (encrypted_website, encrypted_username, encrypted_password))
    db.commit()

    password_manager()


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login_screen()
else:
    first_screen()

window.mainloop()
