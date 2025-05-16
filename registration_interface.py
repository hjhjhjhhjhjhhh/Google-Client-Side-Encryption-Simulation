import tkinter as tk
from tkinter import messagebox
import secrets
import os
import hashlib

# Directory to store user data
USER_DATA_DIR = "user_data"
KMS_KEY_FILE = "kms_api_key.txt"
KMS_PRIVATE_KEY = "kms_private.pem"
KMS_PUBLIC_KEY = "kms_public.pem"
os.makedirs(USER_DATA_DIR, exist_ok=True)


def hash_password(password):
    # Use SHA-256 for secure password hashing
    return hashlib.sha256(password.encode()).hexdigest()


def generate_api_key():
    # Generate a 32-character API key
    return secrets.token_hex(16)

def save_user(username, password, email, api_key):
    filepath = os.path.join(USER_DATA_DIR, f"{username}.txt")
    with open(filepath, "w") as file:
        file.write(f"Username: {username}\n")
        file.write(f"Email: {email}\n")
        file.write(f"Password: {hash_password(password)}\n")
        file.write(f"API Key: {api_key}\n")
    # Append to the KMS API key file
    with open(KMS_KEY_FILE, "a") as kms_file:
        kms_file.write(f"{username} : {api_key}\n")


def register_user():
    username = username_entry.get()
    password = password_entry.get()
    email = email_entry.get()
    
    if not username or not password or not email:
        messagebox.showerror("Error", "All fields are required.")
        return
    if "@" not in email or "." not in email.split("@")[1]:
        messagebox.showerror("Error", "Invalid email address.")
        return
    if os.path.exists(os.path.join(USER_DATA_DIR, f"{username}.txt")):
        messagebox.showerror("Error", "Username already exists.")
        return
    
    api_key = generate_api_key()
    save_user(username, password, email, api_key)
    messagebox.showinfo("Success", f"Registration successful!\nYour API Key: {api_key}")
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    email_entry.delete(0, tk.END)


def create_registration_window():
    window = tk.Tk()
    window.title("User Registration")
    window.geometry("400x400")
    window.configure(bg="#f8f9fa")
    window.resizable(False, False)
    
    title_label = tk.Label(window, text="User Registration", font=("Arial", 18, "bold"), fg="#343a40", bg="#f8f9fa")
    title_label.pack(pady=(20, 10))

    frame = tk.Frame(window, bg="#ffffff", padx=20, pady=20, bd=2, relief=tk.RIDGE)
    frame.pack(pady=20)
    
    tk.Label(frame, text="Username:", font=("Arial", 12), bg="#ffffff").pack(anchor="w", pady=(0, 5))
    global username_entry
    username_entry = tk.Entry(frame, width=30, font=("Arial", 12), bd=2, relief=tk.SOLID)
    username_entry.pack(pady=(0, 10))

    tk.Label(frame, text="Password:", font=("Arial", 12), bg="#ffffff").pack(anchor="w", pady=(0, 5))
    global password_entry
    password_entry = tk.Entry(frame, width=30, font=("Arial", 12), show="*", bd=2, relief=tk.SOLID)
    password_entry.pack(pady=(0, 10))

    tk.Label(frame, text="Email:", font=("Arial", 12), bg="#ffffff").pack(anchor="w", pady=(0, 5))
    global email_entry
    email_entry = tk.Entry(frame, width=30, font=("Arial", 12), bd=2, relief=tk.SOLID)
    email_entry.pack(pady=(0, 20))

    register_button = tk.Button(frame, text="Register", command=register_user, font=("Arial", 14, "bold"), bg="#28a745", fg="white", padx=10, pady=5, bd=0, relief=tk.RAISED)
    register_button.pack()

    window.mainloop()


# Ensure KMS keys are generated externally
if not os.path.exists(KMS_PRIVATE_KEY) or not os.path.exists(KMS_PUBLIC_KEY):
    print("[INFO] Please run 'python kms_keygen.py' to generate KMS keys before registering users.")


# Run the registration window
create_registration_window()
