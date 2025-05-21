import os
import base64
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinterdnd2 import DND_FILES, TkinterDnD
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import time

SERVER_URL = "http://localhost:5000"
CLOUD_SERVER_URL = "http://localhost:8800"
KMS_PUBLIC_KEY_PATH = "kms_public.pem"
OTP_SECRET_DIR = "otp_secrets"
space_num = 5

def encrypt_aes_private_key_with_kms_public_key(key_path, username):
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
    return enc_key

def upload_to_cloud(username, enc_path):
    key_path = get_user_aes_key_path(username)
    if not os.path.exists(key_path) or not os.path.exists(KMS_PUBLIC_KEY_PATH):
        messagebox.showerror("錯誤", "找不到金鑰或公鑰檔案")
        return
    
    enc_key = encrypt_aes_private_key_with_kms_public_key(key_path, username)
    enc_filename = os.path.basename(enc_path)
    key_filename = enc_filename.replace(".enc", ".key")
    files = {
        "enc_file": (enc_filename, open(enc_path, 'rb')),
        "enc_key": (key_filename, enc_key)
    }
    res = requests.post(f"{CLOUD_SERVER_URL}/upload", data={"user": username}, files=files)
    print("res is ", res.text)
    if res.status_code == 200:
        messagebox.showinfo("成功", "已上傳到雲端")
        # ACL MOD: record this file->user grant in KMS
        fn = os.path.basename(enc_path)
        acl_res = requests.post(f"{SERVER_URL}/acl/add", json={"owner": username, "file":  fn, "user": username})
        if acl_res.status_code != 200:
            print("ACL grant failed:", acl_res.text)
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
    file_list = [x for x in file_list if not x.endswith('.key')]
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
        #ACL MOD: check permission
        acl_check = requests.post(f"{SERVER_URL}/acl/check", json={"owner": target_user,"user": username, "file": choice})
        if acl_check.status_code != 200:
            messagebox.showerror("錯誤", f"無權限下載 {choice}：{acl_check.text}")
            return

        r = requests.get(f"{CLOUD_SERVER_URL}/download/{target_user}/{filename}")
        if r.status_code == 200:
            with open(os.path.join(save_dir, filename), "wb") as f:
                f.write(r.content)
        else:
            messagebox.showerror("錯誤", f"無法下載 {filename}：{r.text}")
    messagebox.showinfo("完成", f"檔案已下載至 {save_dir}")

def save_api_key(username, api_key):
    with open("user_api_keys.txt", "a") as f:
        f.write(f'{username}: {api_key}\n')

def load_api_key(username):
    path = "user_api_keys.txt"
    with open(path, "r") as f:
        for line in f:
            if ":" not in line:
                continue
            user, key = line.split(":", 1)
            if user == username:
                return key
    return ""

OTP_SECRET_DIR = "otp_secrets"
def load_otp_secret(user):
    try:
        with open(f"{OTP_SECRET_DIR}/{user}.otp", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

def get_user_aes_key_path(username):
    return f"aes_key_{username}.bin"

# def get_user_dec_key_path(username):
#     return f"kms_key_dec_{username}.bin"

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
    # key_path : stores the AES private key which is encrypt by KMS private key
    
    with open(input_path, 'rb') as f:
        data = f.read()
    with open('kms_private_key_from_server.bin', 'rb') as f:
        kms_private_key = f.read()
    #kms_private_key = base64.b64decode(kms_encrypt)
    kms_private_key = serialization.load_pem_private_key(
        kms_private_key, ## with byte
        password=None,
    )
    try:
        with open(key_path, 'rb') as f:
            key = f.read()
    except:
        messagebox.showerror("錯誤", "未上傳密鑰或密鑰不存在，\n若要解密雲端上檔案，請先上傳密鑰再上傳檔案")
        return
    try:
        decrypted_key = kms_private_key.decrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(decrypted_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except:
        messagebox.showerror("錯誤", "密鑰錯誤，\n若要解密雲端上檔案，請先上傳密鑰再上傳檔案")
        return
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    

def encrypt_and_send_key(username, api_key):
    key_path = get_user_aes_key_path(username)
    key = os.urandom(32)
    with open(key_path, 'wb') as f:
        f.write(key)
    key_for_save = encrypt_aes_private_key_with_kms_public_key(key_path, username)
    with open(f'aes_key_enc_{username}.bin', 'wb') as f:
        f.write(key_for_save)

def retrieve_and_decrypt_key(username, api_key):
    res = requests.post(f"{SERVER_URL}/get-key", json={"user": username, "key": api_key})
    if res.status_code == 200:
        dec_key = res.json()['decrypted_key'] #KMS private key
        dec_key_bytes = base64.b64decode(dec_key)
        #key_path = get_user_dec_key_path(username)
        key_path = 'kms_private_key_from_server.bin' ## after encrypt, KMS server would send this KMS private key to valid user
        with open(key_path, 'wb') as f:
            f.write(dec_key_bytes)
        return key_path
    else:
        print("[!] Failed to retrieve key")
        return None

#this class is used to let user input file name and authorized user to update authority
class INFO(simpledialog.Dialog):
    def body(self, master):
        messagebox.showinfo("hint", "可下載用戶名請用逗點隔開，中間請不要加空格")
        tk.Label(master, text="檔案名稱：").grid(row=0)
        tk.Label(master, text="可下載用戶名：").grid(row=1)

        self.entry1 = tk.Entry(master)
        self.entry2 = tk.Entry(master)

        self.entry1.grid(row=0, column=1)
        self.entry2.grid(row=1, column=1)
        return self.entry1  # focus

    def apply(self):
        self.result = (self.entry1.get(), self.entry2.get())


original_toplevel_geometry = "300x200"
class SecureClientGUI:
    def __init__(self, root):
        self.root = root
        self.username = None
        self.api_key = None
        self.file_path = None
        self.mode = None
        self.decrypt_key_path = "" # store the key download from the cloud server

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
        
        self.status_label.grid(row=0, column=0, columnspan=2, pady=50, sticky="ew")

        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
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
        self.change_auth_btn = tk.Button(self.button_frame, text="更改權限", command=self.change_auth)
        self.logout_btn = tk.Button(self.button_frame, text="登出", command=self.prompt_logout)

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=2, column=0, pady=10, sticky="ne")

        self.drag_label = tk.Label(self.input_frame, text="請拖曳檔案到這裡\n或點擊選擇", bg="#f0f0f0",
                                    relief="ridge", width=25, height=5)
        self.drag_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.drag_label.drop_target_register(DND_FILES)
        self.drag_label.dnd_bind('<<Drop>>', self.handle_drop)
        self.drag_label.bind("<Button-1>", self.select_file)
        self.drag_label.grid_remove()

        self.decrypt_key_frame = tk.Frame(root)
        self.decrypt_key_frame.grid(row=2, column=1, pady=10, sticky="nw")

        self.drag_key_label = tk.Label(self.decrypt_key_frame, text="若要解密從雲端下載之他人檔案\n請上傳密鑰", bg="#f0f0f0",
                                    relief="ridge", width=25, height=5)
        self.drag_key_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.drag_key_label.drop_target_register(DND_FILES)
        self.drag_key_label.dnd_bind('<<Drop>>', self.handle_key_drop)
        self.drag_key_label.bind("<Button-1>", self.select_key_file)
        self.drag_key_label.grid_remove()
        

    def handle_drop(self, event):
        if event.data:
            self.file_path = event.data.strip('{}')
            filename = os.path.basename(self.file_path)
            self.status_label.config(text=f"已選擇檔案：{filename}", fg="blue")
            self.drag_label.config(text=f"已選擇檔案：{filename}")
            time.sleep(0.5)
            self.handle_file(self.file_path)

    def select_file(self, event=None):
        filetypes = [("Text and Encrypted Files", "*.txt *.enc")]
        path = filedialog.askopenfilename(title="選擇檔案", filetypes=filetypes)
        if path:
            self.file_path = path
            filename = os.path.basename(self.file_path)
            self.status_label.config(text=f"已選擇檔案：{filename}", fg="blue")
            self.drag_label.config(text=f"已選擇檔案：{filename}")
            time.sleep(0.5)
            self.handle_file(path)

    def handle_key_drop(self, event):
        if event.data:
            path = event.data.strip('{}')
            filename, ext = os.path.splitext(path)
            if ext != ".key":
                messagebox.showerror("錯誤", f"請選擇 .key 檔案做為密鑰，您目前上傳 {ext} 檔案")
                return
            else:
                self.decrypt_key_path = path
                filename, ext = os.path.splitext(path)
                self.drag_key_label.config(text=f"已選擇檔案: {path.split('/')[-1]}")

    def select_key_file(self, event=None):
        filetypes = [("Text and Encrypted Files", "*.key")]
        path = filedialog.askopenfilename(title="選擇檔案", filetypes=filetypes)
        if path:
            self.decrypt_key_path = path
            filename, ext = os.path.splitext(path)
            self.drag_key_label.config(text=f"已選擇檔案: {path.split('/')[-1]}")

            

    def handle_file(self, path):
        filename, ext = os.path.splitext(path)
        ext = ext.lower()

        if self.mode == "encrypt":
            if ext != ".txt":
                messagebox.showwarning("錯誤", "請選擇 .txt 檔案進行加密")
                self.drag_label.config(text="請拖曳 .txt 檔案或點擊選擇")
                return
            encrypt_and_send_key(self.username, self.api_key)
            key_path = get_user_aes_key_path(self.username)
            success = encrypt_file(path, filename + ".enc", key_path)
            if success:
                messagebox.showinfo("成功", f"已成功加密為 {filename}.enc")
            self.drag_label.config(text="請拖曳 .txt 檔案或點擊選擇")

        elif self.mode == "decrypt":
            retrieve_and_decrypt_key(self.username, self.api_key)
            if ext != ".enc":
                messagebox.showwarning("錯誤", "請選擇 .enc 檔案進行解密")
                return
            key_path = f'aes_key_enc_{self.username}.bin'
            if len(self.decrypt_key_path):
                decrypt_file(path, filename + "_plain.txt", self.decrypt_key_path)
                messagebox.showinfo("成功", f"已成功解密為 {filename}_plain.txt")
                self.decrypt_key_path = ""
                self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")
                self.drag_key_label.config(text="若要解密從雲端下載之他人檔案\n請上傳密鑰")

            elif key_path:
                decrypt_file(path, filename + "_plain.txt", key_path)
                messagebox.showinfo("成功", f"已成功解密為 {filename}_plain.txt")
                self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")
                self.drag_key_label.config(text="若要解密從雲端下載之他人檔案\n請上傳密鑰")

        elif self.mode == "upload":
            if ext != ".enc":
                messagebox.showwarning("錯誤", "僅支援上傳 .enc 檔案")
                self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")
                return
            upload_to_cloud(self.username, path)
            self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")

    def prepare_encrypt(self):
        self.mode = "encrypt"
        self.drag_label.config(text="請拖曳 .txt 檔案或點擊選擇")
        self.decrypt_key_frame.grid_remove()
        self.input_frame.grid(row=2, column=0, pady=10, sticky="ne")
        self.drag_label.grid()
        text = self.status_label.cget("text")
        if "加密" not in text:
            text = text.split(' ')[0] + space_num * " " + "模式: 加密"
        self.status_label.config(text=text)
        

    def prepare_decrypt(self):
        self.mode = "decrypt"
        self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")
        self.drag_label.grid()
        self.decrypt_key_frame.grid()
        self.drag_key_label.grid()
        text = self.status_label.cget("text")
        if "解密" not in text:
            text = text.split(' ')[0] + space_num * " " + "模式: 解密"
        self.status_label.config(text=text)

    def upload_file(self):
        self.mode = "upload"
        self.drag_label.config(text="請拖曳 .enc 檔案或點擊選擇")
        self.decrypt_key_frame.grid_remove()
        self.input_frame.grid(row=2, column=0, pady=10, sticky="ne")
        self.drag_label.grid()
        text = self.status_label.cget("text")
        if "上傳" not in text:
            text = text.split(' ')[0] + space_num * " " + "模式: 上傳"
        self.status_label.config(text=text)

    def download_file(self):
        self.decrypt_key_frame.grid_remove()
        self.input_frame.grid(row=2, column=0, pady=10, sticky="ne")
        self.drag_label.grid()
        text = self.status_label.cget("text")
        if "下載" not in text:
            text = text.split(' ')[0] + space_num * " " + "模式: 下載"
        self.status_label.config(text=text)
        download_from_cloud(self.username)

    def change_auth(self):
        self.decrypt_key_frame.grid_remove()
        self.input_frame.grid(row=2, column=0, pady=10, sticky="ne")
        self.drag_label.grid()

        dialog = INFO(self.root, title="更改檔案權限")
        if dialog.result:
            filename, auth = dialog.result
            res = requests.post(f"{SERVER_URL}/acl/add", json={"owner": self.username, "file":  filename, "user": auth})
        
        text = self.status_label.cget("text")
        if "更改權限" not in text:
            text = text.split(' ')[0] + space_num * " " + "模式: 更改權限"
        self.status_label.config(text=text)


    def prompt_register(self):
        #self.show_auth_input("register")
        # ==== NEW: only register, no auto-login ====
        reg_window = tk.Toplevel(self.root)
        reg_window.title("註冊")
        reg_window.geometry("300x200")

        tk.Label(reg_window, text="使用者名稱:", font=("Arial", 14)).pack(pady=(15,5))
        username_entry = tk.Entry(reg_window, font=("Arial",14), width=20)
        username_entry.pack(pady=5)

        def handle_register():
            username = username_entry.get().strip().lower()
            if not username:
                messagebox.showerror("錯誤", "請輸入帳號"); return
            res = requests.post(f"{SERVER_URL}/register", json={"user": username})
            if res.status_code == 200:
                save_api_key(username, res.json()["api_key"])
                self.fetch_otp_assets(username)
                messagebox.showinfo("成功", "註冊成功！請使用登入按鈕進行登入。")
                reg_window.destroy()
            else:
                messagebox.showerror("錯誤", res.text)

        tk.Button(reg_window, text="註冊", font=("Arial",14),
                  command=handle_register).pack(pady=20)
    
    def fetch_otp_assets(self, username):
        ## Download <username>.otp and <username>_otp.png
        ## into the client's otp_secrets/ directory.
        os.makedirs(OTP_SECRET_DIR, exist_ok=True)
        for fn in (f"{username}.otp", f"{username}_otp.png"):
            url = f"{SERVER_URL}/otp-secrets/{fn}"
            r = requests.get(url)
            if r.status_code == 200:
                with open(os.path.join(OTP_SECRET_DIR, fn), "wb") as f:
                    f.write(r.content)
                print(f"Saved {fn} to {OTP_SECRET_DIR}/")
            else:
                print(f"Could not download {fn}: {r.status_code} {r.text}")

    def prompt_login(self):
        #self.show_auth_input("login")
        # ==== NEW: only login, with OTP validation ====
        login_window = tk.Toplevel(self.root)
        login_window.title("登入")
        login_window.geometry("300x250")

        tk.Label(login_window, text="使用者名稱:", font=("Arial",14)).pack(pady=(15,5))
        username_entry = tk.Entry(login_window, font=("Arial",14), width=20)
        username_entry.pack(pady=5)

        tk.Label(login_window, text="OTP 驗證碼:", font=("Arial",14)).pack(pady=(20,5))
        otp_entry = tk.Entry(login_window, font=("Arial",14), width=20)
        otp_entry.pack(pady=5)

        def handle_login():
            username = username_entry.get().strip().lower()
            otp      = otp_entry.get().strip()
            if not username or not otp:
                messagebox.showerror("錯誤", "請輸入使用者名稱和 OTP 驗證碼"); return

            api_key    = load_api_key(username)
            otp_secret = load_otp_secret(username)
            if not api_key or not otp_secret:
                messagebox.showerror("錯誤", "找不到帳號或 OTP 秘鑰，請先註冊。"); return

            import pyotp
            if not pyotp.TOTP(otp_secret).verify(otp):
                messagebox.showerror("錯誤", "OTP 驗證失敗"); return

            # On successful login:
            self.username = username
            self.api_key  = api_key
            self.status_label.config(text=f"已登入：{username}     請選擇模式", fg="green")
            fetch_kms_public_key(username)
            self.switch_to_main_view()
            login_window.destroy()

        tk.Button(login_window, text="登入", font=("Arial",14),
                  command=handle_login).pack(pady=20)

    def prompt_logout(self):
        self.username = None
        self.api_key = None
        self.status_label.config(text="尚未登入", fg="red")
        self.encrypt_btn.grid_remove()
        self.decrypt_btn.grid_remove()
        self.upload_btn.grid_remove()
        self.download_btn.grid_remove()
        self.change_auth_btn.grid_remove()
        self.logout_btn.grid_remove()
        self.drag_label.grid_remove()
        self.drag_key_label.grid_remove()
        self.register_btn.grid(row=0, column=0, padx=5, sticky="ew")
        self.login_btn.grid(row=0, column=1, padx=5, sticky="ew")
        


    # def show_auth_input(self, mode):
    #     auth_window = tk.Toplevel(self.root)
    #     auth_window.title("登入 / 註冊")
    #     auth_window.geometry("300x300")

    #     tk.Label(auth_window, text="使用者名稱:", font=("Arial", 14)).pack(pady=(15, 5))
    #     username_entry = tk.Entry(auth_window, font=("Arial", 14), width=20)
    #     username_entry.pack(pady=5)

    #     otp_entry = None
    #     if mode == "login":
    #         tk.Label(auth_window, text="OTP 驗證碼:", font=("Arial", 14)).pack(pady=(20, 20))
    #         otp_entry = tk.Entry(auth_window, font=("Arial", 14), width=20)
    #         otp_entry.pack(pady=5)

    #     def handle_submit():
    #         username = username_entry.get().strip().lower()
    #         if not username:
    #             messagebox.showerror("錯誤", "請輸入帳號")
    #             return

    #         if mode == "register":
    #             res = requests.post(f"{SERVER_URL}/register", json={"user": username})
    #             if res.status_code == 200:
    #                 api_key = res.json()["api_key"]
    #                 save_api_key(username, api_key)
    #                 self.username = username
    #                 self.api_key = api_key
    #                 self.status_label.config(text=f"已登入：{username}", fg="green")
    #                 fetch_kms_public_key(username)
    #                 self.switch_to_main_view()
    #                 auth_window.destroy()
    #             else:
    #                 messagebox.showerror("錯誤", res.text)
    #         elif mode == "login":
    #             try:
    #                 api_key = load_api_key(username)
    #                 otp = otp_entry.get().strip()
    #                 if not otp:
    #                     messagebox.showerror("錯誤", "請輸入 OTP 驗證碼")
    #                     return
    #                 otp_secret = load_otp_secret(username)
    #                 if not otp_secret:
    #                     messagebox.showerror("錯誤", "找不到 OTP 秘鑰，請先註冊。")
    #                     return
    #                 import pyotp
    #                 if not pyotp.TOTP(otp_secret).verify(otp):
    #                     messagebox.showerror("錯誤", "OTP 驗證失敗")
    #                     return
    #                 self.username = username
    #                 self.api_key = api_key
    #                 self.status_label.config(text=f"已登入：{username}", fg="green")
    #                 fetch_kms_public_key(username)
    #                 self.switch_to_main_view()
    #                 auth_window.destroy()
    #             except FileNotFoundError:
    #                 messagebox.showerror("錯誤", "找不到 API 金鑰，請先註冊。")

    #     submit_btn = tk.Button(auth_window, text="送出", font=("Arial", 14), command=handle_submit)
    #     submit_btn.pack(pady=10)

    def switch_to_main_view(self):
        self.register_btn.grid_remove()
        self.login_btn.grid_remove()
        self.encrypt_btn.grid(row=1, column=0, padx=5, sticky="ew")
        self.decrypt_btn.grid(row=1, column=1, padx=5, sticky="ew")
        self.upload_btn.grid(row=1, column=2, padx=5, sticky="ew")
        self.download_btn.grid(row=1, column=3, padx=5, sticky="ew")
        self.change_auth_btn.grid(row=1, column=4, padx=5, sticky="ew")
        self.logout_btn.grid(row=0, column=0, columnspan=5, pady=10, sticky="ew")
        self.decrypt_key_frame.grid_remove()
        self.input_frame.grid(row=2, column=0, pady=10, sticky="ne")
        self.drag_label.grid()
        self.file_path = None

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = SecureClientGUI(root)
    root.mainloop()
