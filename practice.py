import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

def open_passkey_window():
    global passkey_window
    passkey_window = tk.Toplevel(root)
    passkey_window.title("Enter Passkey")

    passkey_label = tk.Label(passkey_window, text = "enter passkey")
    passkey_label.pack(pady=5)

    global passkey_entry
    passkey_entry = tk.Entry(passkey_window, show = "*") #??
    passkey_entry.pack(pady=5)

    passkey_button = tk.Button(passkey_window, text = "submit", command = validate_passkey)
    passkey_button.pack(pady=5)

    passkey_window.mainloop()
# what is this doing exactly?



#create the window
root = tk.TK()
root.title("password manager")
root.withdraw() 
#hide until passkey is entered

#if no passkey, open as is
#prompt for a new passkey


open_passkey_window()



#
