# Requires: pip install pyotp qrcode
from flask import Flask, request, jsonify, abort
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64, os, secrets, pyotp, qrcode
from functools import wraps
from flask import send_file
from flask import send_from_directory
from kms_keygen import generate_kms_key_pair

app = Flask(__name__)

API_KEYS_FILE = "kms_api_key.txt"
RSA_KEY_DIR = "rsa_keys"
AES_KEY_DIR = "aes_keys"
OTP_SECRET_DIR = "otp_secrets"
KMS_PUBLIC_KEY_PATH = "kms_public.pem"
os.makedirs(RSA_KEY_DIR, exist_ok=True)
os.makedirs(AES_KEY_DIR, exist_ok=True)
os.makedirs(OTP_SECRET_DIR, exist_ok=True)

def load_api_keys(path=API_KEYS_FILE):
    d = {}
    if not os.path.exists(path):
        return d
    with open(path, "r") as f:
        for line in f:
            if ":" not in line:
                continue
            user, key = line.split(":", 1)
            d[user.strip().lower()] = key.strip()
    return d

def save_api_key(user, key):
    with open(API_KEYS_FILE, "a") as f:
        f.write(f"{user} : {key}\n")

def save_otp_secret(user, secret):
    with open(f"{OTP_SECRET_DIR}/{user}.otp", "w") as f:
        f.write(secret)

def load_otp_secret(user):
    try:
        with open(f"{OTP_SECRET_DIR}/{user}.otp", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

def require_api_key(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        data = request.get_json()
        user = data.get("user", "").strip().lower()
        key = data.get("key", "").strip()

        if not user or not key:
            abort(401, description="Missing credentials or OTP")
        
        expected_key = API_KEY.get(user)
        if not expected_key or expected_key != key:
            abort(401, description="Invalid API key")
        return fn(*args, **kwargs)
    return wrapped


API_KEY = load_api_keys()


ACL_FILE = "kms_acl.txt"   # ACL MOD

def load_acl():
    ##Returns a dict {filename: [user, ...], …}
    acl = {}
    if not os.path.exists(ACL_FILE):
        return acl
    with open(ACL_FILE) as f:
        for line in f:
            fn, users = line.strip().split(":", 1)
            acl[fn] = users.split(",")
    return acl

def save_acl(acl):
    with open(ACL_FILE, "w") as f:
        for fn, users in acl.items():
            f.write(f"{fn}:{','.join(users)}\n")

def add_acl_entry(filename, user):
    acl = load_acl()
    acl.setdefault(filename, [])
    if user not in acl[filename]:
        acl[filename].append(user)
    save_acl(acl)

@app.route('/acl/add', methods=['POST'])
def acl_add():
    data = request.get_json()
    owner = data.get("owner").strip().lower()
    fn   = data.get("file")   .strip()  # ACL MOD
    user = data.get("user")   .strip().lower()
    if not fn or not user:
        return jsonify({"error": "Missing file or user"}), 400
    acl_key = f"{owner}_{fn}"
    add_acl_entry(acl_key, user)    # ACL MOD
    return jsonify({"status": "granted"})

@app.route('/acl/check', methods=['POST'])
def acl_check():
    data     = request.get_json()
    owner    = data.get("owner").strip().lower()
    fn       = data.get("file")  .strip()  # ACL MOD
    user     = data.get("user")  .strip().lower()
    #acl      = load_acl()
    acl_key = f"{owner}_{fn}"
    #allowed  = acl.get(fn, [])
    allowed = load_acl().get(acl_key, [])
    if user in allowed:
        return jsonify({"allowed": True})
    else:
        return jsonify({"allowed": False}), 403


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user = data.get("user", "").strip().lower()
    if not user:
        return jsonify({"error": "Missing username"}), 400
    if user in API_KEY:
        return jsonify({"error": "User already exists"}), 409

    api_key = secrets.token_urlsafe(32)
    save_api_key(user, api_key)

    # Generate and save OTP secret
    otp_secret = pyotp.random_base32()
    save_otp_secret(user, otp_secret)

    # Generate OTP QR Code
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(user, issuer_name="KMS Server")
    qr = qrcode.make(otp_uri)
    qr_path = f"{OTP_SECRET_DIR}/{user}_otp.png"
    qr.save(qr_path)

    API_KEY[user] = api_key
    print(f"[✓] Registered user {user}")
    return jsonify({
        "api_key": api_key,
        "otp_uri": otp_uri,
        "qr_code_link": f"http://localhost:5000/otp-qr/{user}"
    })


@app.route('/otp-qr/<user>', methods=['GET'])
def get_qr_code(user):
    user = user.strip().lower()
    qr_path = f"{OTP_SECRET_DIR}/{user}_otp.png"
    if not os.path.exists(qr_path):
        return jsonify({"error": "QR code not found"}), 404
    return send_file(qr_path, mimetype='image/png')

@app.route('/otp-secrets/<filename>', methods=['GET'])
def download_otp_file(filename): # interact with the fetch_otp_assets in client's handle login
    try:
        return send_from_directory(OTP_SECRET_DIR, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


@app.route('/store-key', methods=['POST'])
@require_api_key
def store_key():
    data = request.get_json()
    user = data["user"].strip().lower()
    b64_enc_key = data.get("enc_key")
    if not b64_enc_key:
        return jsonify({"error": "Missing enc_key"}), 400

    bin_data = base64.b64decode(b64_enc_key)
    with open(f"{AES_KEY_DIR}/{user}.bin", "wb") as f:
        f.write(bin_data)

    return jsonify({"status": "stored"})

@app.route('/get-key', methods=['POST'])
@require_api_key
def get_key():
    data = request.get_json()
    user = data.get("user", "").strip().lower()

    priv_path = "kms_private.pem"

    if not os.path.exists(priv_path):
        return jsonify({"error": "KMS private key not found for user"}), 500

    with open(priv_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    print("private_key")
    print(type(private_key))
    
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    #decrypted_key_b64 = base64.b64encode(decrypted_key).decode('utf-8')
    decrypted_key_b64 = base64.b64encode(pem_bytes).decode('utf-8')
    return jsonify({"decrypted_key": decrypted_key_b64})

@app.route('/get-public-key/<user>', methods=['GET'])
def get_public_key(user):
    user = user.strip().lower()
    pub_path = KMS_PUBLIC_KEY_PATH
    if not os.path.exists(pub_path):
        return jsonify({"error": "Public key not found"}), 404
    return send_file(pub_path, mimetype="application/x-pem-file")

if __name__ == "__main__":
    generate_kms_key_pair()
    app.run(port=5000, debug=True)
