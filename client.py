# Requires: pip install tkinterdnd2
import os
import base64
import requests
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_URL = "http://localhost:5000"

def save_api_key(username, api_key):
    with open(f"{username}.txt", "w") as f:
        f.write(api_key)

def load_api_key(username):
    with open(f"{username}.txt", "r") as f:
        return f.read().strip()

def get_user_aes_key_path(username):
    return f"aes_key_{username}.bin"

def get_user_dec_key_path(username):
    return f"aes_key_dec_{username}.bin"

def encrypt_file(input_path, output_path, key_path):
    if not os.path.exists(key_path):
        print(f"[!] Key file {key_path} not found.")
        return False
    with open(input_path, 'rb') as f:
        data = f.read()
    with open(key_path, 'rb') as f:
        key = f.read()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    with open(output_path, 'wb') as f:
        f.write(nonce + ciphertext)
    return True

def decrypt_file(input_path, output_path, key_path):
    with open(input_path, 'rb') as f:
        data = f.read()
    with open(key_path, 'rb') as f:
        key = f.read()
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    with open(output_path, 'wb') as f:
        f.write(plaintext)

def encrypt_and_send_key(username, api_key):
    key_path = get_user_aes_key_path(username)
    key = os.urandom(32)
    with open(key_path, 'wb') as f:
        f.write(key)
    with open(f"rsa_keys/{username}_public.pem", 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    b64_enc_key = base64.b64encode(encrypted_key).decode()
    res = requests.post(f"{SERVER_URL}/store-key", json={"user": username, "key": api_key, "enc_key": b64_enc_key})
    if res.status_code == 200:
        print("[✓] AES key uploaded")
    else:
        print("[!] Upload failed:", res.text)

def retrieve_and_decrypt_key(username, api_key):
    res = requests.post(f"{SERVER_URL}/get-key", json={"user": username, "key": api_key})
    if res.status_code == 200:
        dec_key = base64.b64decode(res.json()['decrypted_key'])
        key_path = get_user_dec_key_path(username)
        with open(key_path, 'wb') as f:
            f.write(dec_key)
        return key_path
    else:
        print("[!] Failed to retrieve key")
        return None

class SecureClientGUI:
    def __init__(self, root):
        self.root = root
        self.username = None
        self.api_key = None
        self.mode = None

        self.root.title("Secure Client GUI")
        self.root.geometry("600x400")
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        self.status_label = tk.Label(
            root,
            text="尚未登入",
            fg="red",
            font=("Arial", 16)  
        )
        self.status_label.grid(row=0, column=0, pady=50, sticky="ew")  

        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=1, column=0, sticky="ew")
        for i in range(4):
            self.button_frame.grid_columnconfigure(i, weight=1)

        self.register_btn = tk.Button(self.button_frame, text="註冊", command=self.prompt_register)
        self.register_btn.grid(row=0, column=0, padx=5, sticky="ew")

        self.login_btn = tk.Button(self.button_frame, text="登入", command=self.prompt_login)
        self.login_btn.grid(row=0, column=1, padx=5, sticky="ew")

        self.encrypt_btn = tk.Button(self.button_frame, text="加密檔案", command=self.prepare_encrypt)
        self.encrypt_btn.grid(row=0, column=2, padx=5, sticky="ew")

        self.decrypt_btn = tk.Button(self.button_frame, text="解密檔案", command=self.prepare_decrypt)
        self.decrypt_btn.grid(row=0, column=3, padx=5, sticky="ew")

        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=2, column=0, pady=10, sticky="nsew")
        self.input_frame.grid_rowconfigure(0, weight=1)
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.drag_label = tk.Label(
            self.input_frame,
            text="請拖曳檔案到這裡或點擊選擇",
            bg="#f0f0f0",
            relief="ridge",
            width=40,
            height=5
        )
        self.drag_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.drag_label.drop_target_register(DND_FILES)
        self.drag_label.dnd_bind('<<Drop>>', self.handle_drop)
        self.drag_label.bind("<Button-1>", self.select_file)
        self.drag_label.grid_remove()

    def handle_drop(self, event):
        path = event.data.strip('{}')
        self.handle_file(path)

    def select_file(self, event=None):
        filetypes = [("Text Files", "*.txt")] if self.mode == "encrypt" else [("Encrypted Files", "*.enc")]
        path = filedialog.askopenfilename(title="選擇檔案", filetypes=filetypes)
        if path:
            self.handle_file(path)

    def handle_file(self, path):
        filename, ext = os.path.splitext(path)

        if self.mode == "encrypt":
            encrypt_and_send_key(self.username, self.api_key)
            key_path = get_user_aes_key_path(self.username)
            success = encrypt_file(path, filename + ".enc", key_path)
            if success:
                messagebox.showinfo("成功", "已成功加密")
        elif self.mode == "decrypt":
            key_path = retrieve_and_decrypt_key(self.username, self.api_key)
            if key_path:
                decrypt_file(path, filename + "_plain.txt", key_path)
                messagebox.showinfo("成功", "已成功解密")

    def prompt_register(self):
        self.show_auth_input("register")

    def prompt_login(self):
        self.show_auth_input("login")

    def show_auth_input(self, mode):
        auth_window = tk.Toplevel(self.root)
        auth_window.title("登入 / 註冊")
        auth_window.geometry("300x150")  

        tk.Label(auth_window, text="使用者名稱:", font=("Arial", 14)).pack(pady=(15, 5))

        username_entry = tk.Entry(auth_window, font=("Arial", 14), width=20)  
        username_entry.pack(pady=5)

        def handle_submit():
            username = username_entry.get().strip().lower()
            if not username:
                messagebox.showerror("錯誤", "請輸入帳號")
                return

            if mode == "register":
                res = requests.post(f"{SERVER_URL}/register", json={"user": username})
                if res.status_code == 200:
                    api_key = res.json()["api_key"]
                    save_api_key(username, api_key)
                    self.username = username
                    self.api_key = api_key
                    self.status_label.config(text=f"已登入：{username}", fg="green")
                    auth_window.destroy()
                else:
                    messagebox.showerror("錯誤", res.text)
            elif mode == "login":
                try:
                    api_key = load_api_key(username)
                    self.username = username
                    self.api_key = api_key
                    self.status_label.config(text=f"已登入：{username}", fg="green")
                    auth_window.destroy()
                except FileNotFoundError:
                    messagebox.showerror("錯誤", "找不到 API 金鑰，請先註冊。")

        submit_btn = tk.Button(auth_window, text="送出", font=("Arial", 14), command=handle_submit)
        submit_btn.pack(pady=10)

    def prepare_encrypt(self):
        if not self.api_key:
            messagebox.showerror("錯誤", "請先登入")
            return
        self.mode = "encrypt"
        self.drag_label.config(text="請拖曳 .txt 檔案或點擊選擇")
        self.drag_label.grid()

    def prepare_decrypt(self):
        if not self.api_key:
            messagebox.showerror("錯誤", "請先登入")
            return
        self.mode = "decrypt"
        self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")
        self.drag_label.grid()

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = SecureClientGUI(root)
    root.mainloop()
