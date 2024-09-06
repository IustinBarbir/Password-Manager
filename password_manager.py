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


# Database setup
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


# Pop-ups
def pop_up(text):
    answer = simpledialog.askstring("input string", text)
    return answer


# Main window setup
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

    def save_password(event=None):
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

    text.bind("<Return>", save_password)
    text1.bind("<Return>", save_password)


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

    def check_recovery_key(event=None):
        checked = get_recovery_key()
        if checked:
            first_screen()
        else:
            text.delete(0, "end")
            label1.config(text="Wrong key")

    button = Button(window, text="Check key", command=check_recovery_key)
    button.pack(pady=10)

    text.bind("<Return>", check_recovery_key)


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

    def check_password(event=None):
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

    text.bind("<Return>", check_password)


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

    # Create a frame inside the canvas
    frame = Frame(canvas)
    canvas.create_window((0, 0), window=frame, anchor="nw")

    # Bind mouse wheel scrolling
    def on_mouse_wheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    canvas.bind_all("<MouseWheel>", on_mouse_wheel)

    # Update scroll region when the frame size changes
    def update_scroll_region(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    frame.bind("<Configure>", update_scroll_region)

    # Password Manager Title
    label = Label(frame, text="Password Manager", font=("Helvetica", 16))
    label.grid(row=0, column=0, columnspan=6, pady=10)

    # Add entry button
    add_button = Button(frame, text="Add entry", command=add_entry, font=("Helvetica", 12, "bold"))
    add_button.grid(row=1, column=0, pady=10, padx=10)

    # Generate Password button
    generate_password_button = Button(frame, text="Generate Password", command=generate_password_popup, font=("Helvetica", 12, "bold"))
    generate_password_button.grid(row=1, column=1, pady=10, padx=10)

    # Search bar for filtering
    search_label = Label(frame, text="Search:", font=("Helvetica", 12, "bold"))
    search_label.grid(row=1, column=2, pady=10, padx=10, sticky=W)

    search_entry = Entry(frame, width=30)
    search_entry.grid(row=1, column=3, pady=10, padx=10, columnspan=3)

    def display_entries(entries):
        # Clear existing entries and buttons
        for widget in frame.winfo_children():
            if widget.grid_info().get('row', None) is not None and widget.grid_info().get('row') > 2:
                widget.grid_forget()
        
        # Display entries
        for i, entry in enumerate(entries):
            decrypted_website = decrypt(entry[1], encryption_key).decode("utf-8")
            decrypted_username = decrypt(entry[2], encryption_key).decode("utf-8")
            decrypted_password = decrypt(entry[3], encryption_key).decode("utf-8")

            website_label = Label(frame, text=decrypted_website, font=("Helvetica", 12))
            website_label.grid(row=i + 3, column=0, padx=10, pady=5, sticky=W)
            username_label = Label(frame, text=decrypted_username, font=("Helvetica", 12))
            username_label.grid(row=i + 3, column=1, padx=10, pady=5, sticky=W)
            password_label = Label(frame, text=decrypted_password, font=("Helvetica", 12))
            password_label.grid(row=i + 3, column=2, padx=10, pady=5, sticky=W)

            edit_button = Button(frame, text="Edit", command=partial(edit_entry, entry[0], decrypted_website, decrypted_username, decrypted_password))
            edit_button.grid(row=i + 3, column=3, padx=10, pady=5)

            delete_button = Button(frame, text="Delete", command=partial(confirmation_popup, entry[0]))
            delete_button.grid(row=i + 3, column=4, padx=10, pady=5)

            copy_button = Button(frame, text="Copy", command=partial(copy_password_to_clipboard, decrypted_password))
            copy_button.grid(row=i + 3, column=5, padx=10, pady=5)

    def search_entries(*args):
        query = search_entry.get().lower()
        cursor.execute("SELECT * FROM vault")
        entries = cursor.fetchall()

        filtered_entries = [entry for entry in entries if query in decrypt(entry[1], encryption_key).decode("utf-8").lower() or query in decrypt(entry[2], encryption_key).decode("utf-8").lower()]
        display_entries(filtered_entries)

    # Initial display of all entries
    cursor.execute("SELECT * FROM vault")
    entries = cursor.fetchall()
    display_entries(entries)

    # Bind search function to key release
    search_entry.bind("<KeyRelease>", search_entries)


def generate_password_popup():
    # Function to generate a new password
    def generate_new_password():
        nonlocal password
        password = ''.join(random.choice(characters) for i in range(length))
        password_label.config(text=password)

    # Function to copy the current password to clipboard
    def copy_password():
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    length = 15
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))

    # Create a popup window for the generated password
    popup = Toplevel(window)
    popup.title("Generated Password")
    popup.geometry("350x200")

    # Display the generated password
    password_label = Label(popup, text=password, font=("Helvetica", 12))
    password_label.pack(pady=10)

    # Add the "Copy" button
    copy_button = Button(popup, text="Copy", command=copy_password)
    copy_button.pack(pady=5)

    # Add the "Regenerate" button
    regenerate_button = Button(popup, text="Regenerate", command=generate_new_password)
    regenerate_button.pack(pady=5)

    # Optionally, add a button to close the popup
    close_button = Button(popup, text="Close", command=popup.destroy)
    close_button.pack(pady=10)


def add_entry():
    def on_enter_website(event=None):
        username_entry.focus_set()
        return "break"

    def on_enter_username(event=None):
        password_entry.focus_set()
        return "break"

    def on_enter_password(event=None):
        add_button.invoke()  # Automatically triggers the "Add" button click
        return "break"

    # Create a new window for entering website, username, and password
    entry_window = Toplevel(window)
    entry_window.title("Add Entry")
    entry_window.geometry("300x200")

    Label(entry_window, text="Website").pack()
    website_entry = Entry(entry_window, width=30)
    website_entry.pack()
    website_entry.bind("<Return>", on_enter_website)
    website_entry.focus()

    Label(entry_window, text="Username").pack()
    username_entry = Entry(entry_window, width=30)
    username_entry.pack()
    username_entry.bind("<Return>", on_enter_username)

    Label(entry_window, text="Password").pack()
    password_entry = Entry(entry_window, width=30)
    password_entry.pack()
    password_entry.bind("<Return>", on_enter_password)

    add_button = Button(entry_window, text="Add", command=lambda: add_entry_to_db(website_entry.get(), username_entry.get(), password_entry.get()))
    add_button.pack(pady=10)

    # Bind Enter key events to the entries
    website_entry.bind("<Return>", on_enter_website)
    username_entry.bind("<Return>", on_enter_username)
    password_entry.bind("<Return>", on_enter_password)


def add_entry_to_db(website, username, password):
    encrypted_website = encrypt(website.encode(), encryption_key)
    encrypted_username = encrypt(username.encode(), encryption_key)
    encrypted_password = encrypt(password.encode(), encryption_key)

    insert_fields = """INSERT INTO vault(website, username, password)
    VALUES(?, ?, ?) """
    cursor.execute(insert_fields, (encrypted_website, encrypted_username, encrypted_password))
    db.commit()

    password_manager()


def edit_entry(entry_id, old_website, old_username, old_password):
    def on_enter_website(event=None):
        username_entry.focus_set()
        return "break"

    def on_enter_username(event=None):
        password_entry.focus_set()
        return "break"

    def on_enter_password(event=None):
        save_button.invoke()  # Automatically triggers the "Save" button click
        return "break"

    def save_changes():
        new_website = website_entry.get()
        new_username = username_entry.get()
        new_password = password_entry.get()

        encrypted_website = encrypt(new_website.encode(), encryption_key)
        encrypted_username = encrypt(new_username.encode(), encryption_key)
        encrypted_password = encrypt(new_password.encode(), encryption_key)

        cursor.execute("""
        UPDATE vault SET website = ?, username = ?, password = ? WHERE id = ?
        """, (encrypted_website, encrypted_username, encrypted_password, entry_id))
        db.commit()

        password_manager()

    # Create a new window for editing website, username, and password
    edit_window = Toplevel(window)
    edit_window.title("Edit Entry")
    edit_window.geometry("300x200")

    Label(edit_window, text="Website").pack()
    website_entry = Entry(edit_window, width=30)
    website_entry.pack()
    website_entry.insert(0, old_website)
    website_entry.bind("<Return>", on_enter_website)
    website_entry.focus()

    Label(edit_window, text="Username").pack()
    username_entry = Entry(edit_window, width=30)
    username_entry.pack()
    username_entry.insert(0, old_username)
    username_entry.bind("<Return>", on_enter_username)

    Label(edit_window, text="Password").pack()
    password_entry = Entry(edit_window, width=30)
    password_entry.pack()
    password_entry.insert(0, old_password)
    password_entry.bind("<Return>", on_enter_password)

    save_button = Button(edit_window, text="Save", command=save_changes)
    save_button.pack(pady=10)

    # Bind Enter key events to the entries
    website_entry.bind("<Return>", on_enter_website)
    username_entry.bind("<Return>", on_enter_username)
    password_entry.bind("<Return>", on_enter_password)


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login_screen()
else:
    first_screen()

window.mainloop()
