import tkinter as tk
from cryptography.fernet import Fernet
import os

# Generate or load the encryption key
def load_key():
    key_path = "key.key"
    if os.path.exists(key_path):
        with open(key_path, "rb") as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)
    return key

# Encrypt a password
def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Decrypt a password
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

# Store a password
def store_password(service, username, password, key):
    encrypted_password = encrypt_password(password, key)
    with open("passwords.txt", "a") as password_file:
        password_file.write(f"{service}: {username} - {encrypted_password.decode()}\n")

# Retrieve a password
def retrieve_password(service, username, key):
    with open("passwords.txt", "r") as password_file:
        for line in password_file:
            if line.startswith(f"{service}: {username}"):
                encrypted_password = line.split(" - ")[1].strip()
                decrypted_password = decrypt_password(encrypted_password.encode(), key)
                return decrypted_password
    return "Password not found."

# Create the main application window
app = tk.Tk()
app.title("Password Management Tool")

# Create and load the encryption key
key = load_key()

# Create and set up a label to display messages
message_label = tk.Label(app, text="", fg="blue")
message_label.pack()

# Create and set up input fields with clear functions
def clear_fields():
    service_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

service_label = tk.Label(app, text="Website/Service:")
service_label.pack()
service_entry = tk.Entry(app)
service_entry.pack()

username_label = tk.Label(app, text="Your Username:")
username_label.pack()
username_entry = tk.Entry(app)
username_entry.pack()

password_label = tk.Label(app, text="Your Password:")
password_label.pack()
password_entry = tk.Entry(app, show="*")  # Passwords are hidden
password_entry.pack()

# Function to store a password
def store_password_gui():
    service = service_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    if service and username and password:
        store_password(service, username, password, key)
        message_label.config(text="Password stored securely!", fg="green")
        clear_fields()
    else:
        message_label.config(text="Please fill in all fields.", fg="red")

# Function to retrieve a password
def retrieve_password_gui():
    service = service_entry.get()
    username = username_entry.get()
    if service and username:
        password = retrieve_password(service, username, key)
        if password != "Password not found.":
            message_label.config(text=f"Password for {service}: {username} is: {password}", fg="blue")
            clear_fields()
        else:
            message_label.config(text="Password not found.", fg="red")
    else:
        message_label.config(text="Please fill in all fields.", fg="red")

# Create and set up buttons
store_button = tk.Button(app, text="Store Password", command=store_password_gui)
store_button.pack()

retrieve_button = tk.Button(app, text="Retrieve Password", command=retrieve_password_gui)
retrieve_button.pack()

# Run the GUI application
app.mainloop()







