import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QMessageBox, QTableWidget, QTableWidgetItem, QAction, QHeaderView
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json

PASSKEY_FILE = "passkey.json"

class PasskeyWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enter Passkey")
        self.setGeometry(200, 200, 300, 150)

        self.passkey_label = QLabel("Enter Passkey:")
        self.passkey_entry = QLineEdit()
        self.submit_button = QPushButton("Submit")
        self.error_label = QLabel("Wrong passkey")
        self.error_label.setStyleSheet("color: red")
        self.error_label.hide()

        layout = QVBoxLayout()
        layout.addWidget(self.passkey_label)
        layout.addWidget(self.passkey_entry)
        layout.addWidget(self.submit_button)
        layout.addWidget(self.error_label)

        self.submit_button.clicked.connect(self.validate_passkey)

        self.setLayout(layout)

    def validate_passkey(self):
        entered_passkey = self.passkey_entry.text()
        saved_passkey = load_passkey()
        if entered_passkey == saved_passkey:
            self.main_window.show()
            self.close()
        else:
            self.error_label.show()
    def open_passkey_window(self):
        if os.path.exists(PASSKEY_FILE):
            self.passkey_window.show()
        else:
            self.passkey_window.error_label.hide()
            self.passkey_window.show()


class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 400)

        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layouts
        main_layout = QVBoxLayout(central_widget)
        input_layout = QVBoxLayout()
        table_layout = QVBoxLayout()
        button_layout = QHBoxLayout()

        # Input Widgets
        self.account_name_entry = QLineEdit()
        self.username_entry = QLineEdit()
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)  # Password mode
        input_layout.addWidget(QLabel("Account Name:"))
        input_layout.addWidget(self.account_name_entry)
        input_layout.addWidget(QLabel("Username:"))
        input_layout.addWidget(self.username_entry)
        input_layout.addWidget(QLabel("Password:"))
        input_layout.addWidget(self.password_entry)

        # Table Widget
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Account Name", "Username", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table_layout.addWidget(self.table)

        # Buttons
        add_button = QPushButton("Add Entry")
        add_button.clicked.connect(self.add_entry)
        decrypt_button = QPushButton("Decrypt Selected Entry")
        decrypt_button.clicked.connect(self.decrypt_entry)
        button_layout.addWidget(add_button)
        button_layout.addWidget(decrypt_button)

        # Main Layout
        main_layout.addLayout(input_layout)
        main_layout.addLayout(table_layout)
        main_layout.addLayout(button_layout)

       # self.passkey_window = PasskeyWindow()
        self.main_window = self

    def showEvent(self, event):
        self.open_passkey_window()

  
    def add_entry(self):
        account_name = self.account_name_entry.text()
        username = self.username_entry.text()
        password = self.password_entry.text()
        encrypted_password = self.encrypt_message(password.encode())
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
        self.table.setItem(row_position, 0, QTableWidgetItem(account_name))
        self.table.setItem(row_position, 1, QTableWidgetItem(username))
        self.table.setItem(row_position, 2, QTableWidgetItem("*" * len(password)))
        self.password_entry.clear()

    def decrypt_entry(self):
        selected_row = self.table.currentRow()
        if selected_row != -1:
            encrypted_password = self.decrypt_message(selected_row)
            if encrypted_password:
                QMessageBox.information(self, "Decrypted Password", f"The decrypted password is: {encrypted_password.decode()}")
            else:
                QMessageBox.warning(self, "Error", "Unable to decrypt password.")
        else:
            QMessageBox.warning(self, "Error", "Please select an entry to decrypt.")

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_message(self, row):
        iv_ciphertext = self.table.item(row, 2).text().encode()
        iv = iv_ciphertext[:16]
        ciphertext = iv_ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data

def load_passkey():
    if os.path.exists(PASSKEY_FILE):
        with open(PASSKEY_FILE, "r") as f:
            data = json.load(f)
            return data.get("passkey")
    return None

if __name__ == '__main__':
    app = QApplication(sys.argv)
    password_manager = PasswordManager()
    password_manager.show()
    sys.exit(app.exec_())
