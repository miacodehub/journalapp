import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import os
import json
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PASSKEY_FILE = "passkey.json"

# Define a global list to store encrypted passwords
encrypted_passwords = []

def add_entry():
    account_name = account_name_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    encrypted_password = encrypt_message(key, password.encode())
    encrypted_passwords.append(encrypted_password)  # Store encrypted password
    masked_password = '*' * len(password)  # Creating a masked password
    tree.insert('', 'end', values=(account_name, username, masked_password))
    clear_entries()


def clear_entries():
    account_name_entry.delete(0, 'end')
    username_entry.delete(0, 'end')
    password_entry.delete(0, 'end')

def search_entries():
    search_text = search_entry.get().lower()
    for row_id in tree.get_children():
        values = tree.item(row_id)['values']
        if search_text in str(values).lower():
            tree.selection_set(row_id)
            tree.focus(row_id)
            return

def decrypt_entry():
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item)
        encrypted_index = selected_item[0]  # Index corresponds to the position in encrypted_passwords list
        encrypted_password = encrypted_passwords[int(encrypted_index)]
        decrypted_password = decrypt_message(key, encrypted_password)
        messagebox.showinfo("Decrypted Password", f"The decrypted password is: {decrypted_password.decode()}")
    else:
        messagebox.showerror("Error", "Please select an entry to decrypt.")


def create_passkey(passkey_value):
    if passkey_value.strip() == "":
        messagebox.showerror("Error", "Passkey can't be empty.")
        return False
    else:
        with open(PASSKEY_FILE, "w") as f:
            json.dump({"passkey": passkey_value}, f)
        return True

def open_passkey_window():
    passkey_window = tk.Toplevel(root)
    passkey_window.title("Enter Passkey")
    passkey_window.geometry("300x200")  # Set a larger size

    passkey_label = tk.Label(passkey_window, text="Enter Passkey:", font=("Arial", 12))
    passkey_label.pack(pady=10)

    passkey_entry = tk.Entry(passkey_window, show="*", font=("Arial", 12))
    passkey_entry.pack(pady=10)

    def validate_passkey_callback():
        entered_passkey = passkey_entry.get()
        saved_passkey = load_passkey()
        if entered_passkey == saved_passkey:
            passkey_window.destroy()
            root.deiconify()
        else:
            passkey_entry.delete(0, 'end')
            messagebox.showerror("Error", "Wrong passkey.")

    passkey_button = tk.Button(passkey_window, text="Submit", command=validate_passkey_callback, font=("Arial", 12))
    passkey_button.pack(pady=10)

def load_passkey():
    if os.path.exists(PASSKEY_FILE):
        with open(PASSKEY_FILE, "r") as f:
            data = json.load(f)
            return data.get("passkey")
    return None

def pad_data(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad_data(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def encrypt_message(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad_data(message)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, iv_ciphertext):
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)
    return unpadded_data

def change_passkey_window():
    change_passkey_window = tk.Toplevel(root)
    change_passkey_window.title("Change Passkey")
    change_passkey_window.geometry("300x200")  # Set a suitable size

    old_passkey_label = tk.Label(change_passkey_window, text="Old Passkey:", font=("Arial", 12))
    old_passkey_label.pack(pady=10)

    old_passkey_entry = tk.Entry(change_passkey_window, show="*", font=("Arial", 12))
    old_passkey_entry.pack(pady=10)

    new_passkey_label = tk.Label(change_passkey_window, text="New Passkey:", font=("Arial", 12))
    new_passkey_label.pack(pady=10)

    new_passkey_entry = tk.Entry(change_passkey_window, show="*", font=("Arial", 12))
    new_passkey_entry.pack(pady=10)

    def save_passkey():
        old_passkey = old_passkey_entry.get()
        new_passkey = new_passkey_entry.get()
        saved_passkey = load_passkey()
        if old_passkey == saved_passkey:
            create_passkey(new_passkey)
            messagebox.showinfo("Success", "Passkey changed successfully.")
            change_passkey_window.destroy()
        else:
            messagebox.showerror("Error", "Incorrect old passkey.")

    save_button = tk.Button(change_passkey_window, text="Save", command=save_passkey, font=("Arial", 12))
    save_button.pack(pady=10)

# Set the encryption key
key = b'ThisIsASecretKey'  # 16, 24, or 32 bytes long

# Load or create passkey
passkey = load_passkey()
root = tk.Tk()
root.geometry("600x400")  # Set initial size
root.withdraw()  # Hide the main window until passkey is entered

# Create menu bar
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)
passkey_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Passkey", menu=passkey_menu)
passkey_menu.add_command(label="Change Passkey", command=change_passkey_window)

open_passkey_window()

# Modern theme for widgets
style = ttk.Style()
style.theme_use("clam")

# Creating labels and entries for adding new entries
tk.Label(root, text="Account Name:", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5)
account_name_entry = tk.Entry(root, font=("Arial", 12))
account_name_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Username:", font=("Arial", 12)).grid(row=1, column=0, padx=5, pady=5)
username_entry = tk.Entry(root, font=("Arial", 12))
username_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="Password:", font=("Arial", 12)).grid(row=2, column=0, padx=5, pady=5)
password_entry = tk.Entry(root, font=("Arial", 12))
password_entry.grid(row=2, column=1, padx=5, pady=5)

add_button = tk.Button(root, text="Add Entry", command=add_entry, font=("Arial", 12))
add_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="we")

# Creating a treeview (table) to display entries
tree = ttk.Treeview(root, columns=("Account Name", "Username", "Password"), show="headings")
tree.heading("Account Name", text="Account Name")
tree.heading("Username", text="Username")
tree.heading("Password", text="Password")
tree.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")  # Use sticky to resize

# Creating a search entry and button
search_label = tk.Label(root, text="Search:", font=("Arial", 12))
search_label.grid(row=5, column=0, padx=5, pady=5, sticky="e")
search_entry = tk.Entry(root, font=("Arial", 12))
search_entry.grid(row=5, column=1, padx=5, pady=5, sticky="we")

search_button = tk.Button(root, text="Search", command=search_entries, font=("Arial", 12))
search_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky="we")

# Decrypt button
decrypt_button = tk.Button(root, text="Decrypt Selected Entry", command=decrypt_entry, font=("Arial", 12))
decrypt_button.grid(row=7, column=0, columnspan=2, padx=5, pady=5, sticky="we")

root.mainloop()