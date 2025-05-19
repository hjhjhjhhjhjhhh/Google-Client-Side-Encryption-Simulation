import os
import base64
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinterdnd2 import DND_FILES, TkinterDnD
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_URL = "http://localhost:5000"
CLOUD_SERVER_URL = "http://localhost:5001"
KMS_PUBLIC_KEY_PATH = "kms_public.pem"
OTP_SECRET_DIR = "otp_secrets"

def upload_to_cloud(username, enc_path):
    key_path = get_user_aes_key_path(username)
    if not os.path.exists(key_path) or not os.path.exists(KMS_PUBLIC_KEY_PATH):
        messagebox.showerror("錯誤", "找不到金鑰或公鑰檔案")
        return
    with open(key_path, 'rb') as f:
        aes_key = f.read()
    with open(KMS_PUBLIC_KEY_PATH, 'rb') as f:
        kms_pub = serialization.load_pem_public_key(f.read())
    enc_key = kms_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    enc_filename = os.path.basename(enc_path)
    key_filename = enc_filename.replace(".enc", ".key")
    files = {
        "enc_file": (enc_filename, open(enc_path, 'rb')),
        "enc_key": (key_filename, enc_key)
    }
    res = requests.post(f"{CLOUD_SERVER_URL}/upload", data={"user": username}, files=files)
    if res.status_code == 200:
        messagebox.showinfo("成功", "已上傳到雲端")
    else:
        messagebox.showerror("錯誤", f"上傳失敗：{res.text}")

def download_from_cloud(username):
    target_user = simpledialog.askstring("下載目標", "輸入你要下載的用戶名：")
    if not target_user:
        return
    res = requests.get(f"{CLOUD_SERVER_URL}/list/{target_user}")
    if res.status_code != 200:
        messagebox.showerror("錯誤", res.text)
        return
    file_list = res.json()
    if not file_list:
        messagebox.showinfo("訊息", "該用戶沒有可用的雲端檔案。")
        return
    choice = simpledialog.askstring("檔案選擇", f"請輸入要下載的檔名(.enc)：\n{file_list}")
    if not choice or choice not in file_list:
        messagebox.showerror("錯誤", "請輸入正確檔案名稱。")
        return
    save_dir = os.path.join("download", username)
    os.makedirs(save_dir, exist_ok=True)
    for ext in [".enc", ".key"]:
        filename = os.path.splitext(choice)[0] + ext
        r = requests.get(f"{CLOUD_SERVER_URL}/download/{target_user}/{filename}")
        if r.status_code == 200:
            with open(os.path.join(save_dir, filename), "wb") as f:
                f.write(r.content)
        else:
            messagebox.showerror("錯誤", f"無法下載 {filename}：{r.text}")
    messagebox.showinfo("完成", f"檔案已下載至 {save_dir}")

def save_api_key(username, api_key):
    with open(f"{username}.txt", "w") as f:
        f.write(api_key)

def load_api_key(username):
    with open(f"{username}.txt", "r") as f:
        return f.read().strip()

OTP_SECRET_DIR = "otp_secrets"
def load_otp_secret(user):
    try:
        with open(f"{OTP_SECRET_DIR}/{user}.otp", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

def get_user_aes_key_path(username):
    return f"aes_key_{username}.bin"

def get_user_dec_key_path(username):
    return f"aes_key_dec_{username}.bin"

def fetch_kms_public_key(username):
    try:
        res = requests.get(f"{SERVER_URL}/get-public-key/{username}")
        if res.status_code == 200:
            with open(KMS_PUBLIC_KEY_PATH, "wb") as f_key:
                f_key.write(res.content)
            print(f"[✓] 已取得 KMS 公鑰")
        else:
            print("[!] 無法取得 KMS 公鑰：", res.text)
    except Exception as e:
        print("[!] 公鑰下載錯誤：", e)

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


original_toplevel_geometry = "300x200"
class SecureClientGUI:
    def __init__(self, root):
        self.root = root
        self.username = None
        self.api_key = None
        self.file_path = None
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
        for i in range(2):
            self.button_frame.grid_columnconfigure(i, weight=1)

        self.register_btn = tk.Button(self.button_frame, text="註冊", command=self.prompt_register)
        self.register_btn.grid(row=0, column=0, padx=5, sticky="ew")

        self.login_btn = tk.Button(self.button_frame, text="登入", command=self.prompt_login)
        self.login_btn.grid(row=0, column=1, padx=5, sticky="ew")
        

        self.encrypt_btn = tk.Button(self.button_frame, text="加密檔案", command=self.prepare_encrypt)
        self.decrypt_btn = tk.Button(self.button_frame, text="解密檔案", command=self.prepare_decrypt)
        self.upload_btn = tk.Button(self.button_frame, text="上傳雲端", command=self.upload_file)
        self.download_btn = tk.Button(self.button_frame, text="下載雲端", command=self.download_file)
        self.logout_btn = tk.Button(self.button_frame, text="登出", command=self.prompt_logout)

        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=2, column=0, pady=10, sticky="nsew")
        self.input_frame.grid_rowconfigure(0, weight=1)
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.drag_label = tk.Label(self.input_frame, text="請拖曳檔案到這裡或點擊選擇", bg="#f0f0f0",
                                    relief="ridge", width=40, height=5)
        self.drag_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.drag_label.drop_target_register(DND_FILES)
        self.drag_label.dnd_bind('<<Drop>>', self.handle_drop)
        self.drag_label.bind("<Button-1>", self.select_file)
        self.drag_label.grid_remove()
        

    def handle_drop(self, event):
        if event.data:
            self.file_path = event.data.strip('{}')
            filename = os.path.basename(self.file_path)
            self.status_label.config(text=f"已選擇檔案：{filename}", fg="blue")
            self.handle_file(self.file_path)

    def select_file(self, event=None):
        filetypes = [("Text and Encrypted Files", "*.txt *.enc")]
        path = filedialog.askopenfilename(title="選擇檔案", filetypes=filetypes)
        if path:
            self.file_path = path
            filename = os.path.basename(self.file_path)
            self.status_label.config(text=f"已選擇檔案：{filename}", fg="blue")
            self.handle_file(path)

    def handle_file(self, path):
        filename, ext = os.path.splitext(path)
        ext = ext.lower()

        if self.mode == "encrypt":
            if ext != ".txt":
                messagebox.showwarning("錯誤", "請選擇 .txt 檔案進行加密")
                return
            encrypt_and_send_key(self.username, self.api_key)
            key_path = get_user_aes_key_path(self.username)
            success = encrypt_file(path, filename + ".enc", key_path)
            if success:
                messagebox.showinfo("成功", f"已成功加密為 {filename}.enc")

        elif self.mode == "decrypt":
            if ext != ".enc":
                messagebox.showwarning("錯誤", "請選擇 .enc 檔案進行解密")
                return
            key_path = retrieve_and_decrypt_key(self.username, self.api_key)
            if key_path:
                decrypt_file(path, filename + "_plain.txt", key_path)
                messagebox.showinfo("成功", f"已成功解密為 {filename}_plain.txt")

        elif self.mode == "upload":
            if ext != ".enc":
                messagebox.showwarning("錯誤", "僅支援上傳 .enc 檔案")
                return
            upload_to_cloud(self.username, path)

    def prepare_encrypt(self):
        self.mode = "encrypt"
        self.drag_label.config(text="請拖曳 .txt 檔案或點擊選擇")
        self.drag_label.grid()

    def prepare_decrypt(self):
        self.mode = "decrypt"
        self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")
        self.drag_label.grid()

    def upload_file(self):
        self.mode = "upload"
        self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")
        self.drag_label.grid()

    def download_file(self):
        download_from_cloud(self.username)

    def prompt_register(self):
        self.show_auth_input("register")

    def prompt_login(self):
        self.show_auth_input("login")

    def prompt_logout(self):
        self.username = None
        self.api_key = None
        self.status_label.config(text="尚未登入", fg="red")
        self.encrypt_btn.grid_remove()
        self.decrypt_btn.grid_remove()
        self.upload_btn.grid_remove()
        self.download_btn.grid_remove()
        self.logout_btn.grid_remove()
        self.drag_label.grid_remove()
        self.register_btn.grid(row=0, column=0, padx=5, sticky="ew")
        self.login_btn.grid(row=0, column=1, padx=5, sticky="ew")
        


    def show_auth_input(self, mode):
        auth_window = tk.Toplevel(self.root)
        auth_window.title("登入 / 註冊")
        auth_window.geometry("300x300")

        tk.Label(auth_window, text="使用者名稱:", font=("Arial", 14)).pack(pady=(15, 5))
        username_entry = tk.Entry(auth_window, font=("Arial", 14), width=20)
        username_entry.pack(pady=5)

        otp_entry = None
        if mode == "login":
            tk.Label(auth_window, text="OTP 驗證碼:", font=("Arial", 14)).pack(pady=(20, 20))
            otp_entry = tk.Entry(auth_window, font=("Arial", 14), width=20)
            otp_entry.pack(pady=5)

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
                    fetch_kms_public_key(username)
                    self.switch_to_main_view()
                    auth_window.destroy()
                else:
                    messagebox.showerror("錯誤", res.text)
            elif mode == "login":
                try:
                    api_key = load_api_key(username)
                    otp = otp_entry.get().strip()
                    if not otp:
                        messagebox.showerror("錯誤", "請輸入 OTP 驗證碼")
                        return
                    otp_secret = load_otp_secret(username)
                    if not otp_secret:
                        messagebox.showerror("錯誤", "找不到 OTP 秘鑰，請先註冊。")
                        return
                    import pyotp
                    if not pyotp.TOTP(otp_secret).verify(otp):
                        messagebox.showerror("錯誤", "OTP 驗證失敗")
                        return
                    self.username = username
                    self.api_key = api_key
                    self.status_label.config(text=f"已登入：{username}", fg="green")
                    fetch_kms_public_key(username)
                    self.switch_to_main_view()
                    auth_window.destroy()
                except FileNotFoundError:
                    messagebox.showerror("錯誤", "找不到 API 金鑰，請先註冊。")

        submit_btn = tk.Button(auth_window, text="送出", font=("Arial", 14), command=handle_submit)
        submit_btn.pack(pady=10)

    def switch_to_main_view(self):
        self.register_btn.grid_remove()
        self.login_btn.grid_remove()
        self.encrypt_btn.grid(row=1, column=0, padx=5, sticky="ew")
        self.decrypt_btn.grid(row=1, column=1, padx=5, sticky="ew")
        self.upload_btn.grid(row=1, column=2, padx=5, sticky="ew")
        self.download_btn.grid(row=1, column=3, padx=5, sticky="ew")
        self.logout_btn.grid(row=0, column=0, columnspan=4, pady=10, sticky="ew")
        self.drag_label.grid()
        self.file_path = None

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = SecureClientGUI(root)
    root.mainloop()
