# Requires: pip install pyotp qrcode
from flask import Flask, request, jsonify, abort
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64, os, secrets, pyotp, qrcode
from functools import wraps
from flask import send_file

app = Flask(__name__)

API_KEYS_FILE = "kms_api_key.txt"
RSA_KEY_DIR = "rsa_keys"
AES_KEY_DIR = "aes_keys"
OTP_SECRET_DIR = "otp_secrets"
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

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{RSA_KEY_DIR}/{user}_private.pem", "wb") as f:
        f.write(priv_pem)
    with open(f"{RSA_KEY_DIR}/{user}_public.pem", "wb") as f:
        f.write(pub_pem)

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

    key_path = f"{AES_KEY_DIR}/{user}.bin"
    priv_path = f"{RSA_KEY_DIR}/{user}_private.pem"

    if not os.path.exists(key_path):
        return jsonify({"error": "AES key not found for user"}), 404
    if not os.path.exists(priv_path):
        return jsonify({"error": "RSA key not found for user"}), 500

    with open(key_path, 'rb') as f:
        enc_key = f.read()
    with open(priv_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    decrypted_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted_key_b64 = base64.b64encode(decrypted_key).decode('utf-8')
    return jsonify({"decrypted_key": decrypted_key_b64})

if __name__ == "__main__":
    app.run(port=5000, debug=True)
