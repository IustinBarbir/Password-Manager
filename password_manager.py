import sqlite3, hashlib
from tkinter import *

#Database
with sqlite3.connect("password_manager.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")


#Window
window =Tk()

window.title("Password Manager")

def hash_password(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash
def first_screen():
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
            hashed_password = hash_password(text.get().encode("utf-8"))
            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashed_password)])
            db.commit()

            password_manager()
        else:
            label.config(text="Passwords do not match")

    button = Button(window, text="Save", command=save_password)
    button.pack(pady=10)


def login_screen():
    window.geometry("250x100")

    label = Label(window, text= "Enter master password")
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
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(check_hashedPassword)])
        print(check_hashedPassword)
        return cursor.fetchall()

    def check_password():
        match  = get_masterpassword()

        print(match)

        if match:
            password_manager()
        else:
            text.delete(0, "end")
            label.config(text="Wrong Password")

    button = Button(window, text="Submit", command=check_password)
    button.pack(pady=10)

def password_manager():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("750x400")
    label = Label(window, text="Password Manager")
    label.config(anchor=CENTER)
    label.pack()


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login_screen()
else:
    first_screen()

window.mainloop()
