from flask import Flask, request, send_file, jsonify, abort
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from functools import wraps

app = Flask(__name__)

# Load one API key (from keygen)
# with open("kms_api_key.txt", "r") as f:
#     API_KEY = f.read().strip()

# def require_api_key(fn):
#     @wraps(fn)
#     def wrapped(*args, **kwargs):
#         key = request.headers.get("X-API-Key")
#         if not key or key != API_KEY:
#             abort(401, description="Invalid or missing API key")
#         return fn(*args, **kwargs)
#     return wrapped

def load_api_keys(path="kms_api_key.txt"):
    """
    Reads lines like "Alice : <key>" and returns a dict:
      { "alice" : "<key>", "bob" : "<key2>", ... }
    Usernames are lowercased for case‐insensitive lookup.
    """
    d = {}
    with open(path, "r") as f:
        for line in f:
            if ":" not in line:
                continue
            user, key = line.split(":", 1)
            d[user.strip().lower()] = key.strip()
    return d

# Load once at startup
API_KEY = load_api_keys()

@app.route('/get-key', methods=['POST'])
#@require_api_key
def get_key():
    data = request.get_json()
    user = data.get("user", "").strip().lower()
    key  = data.get("key", "").strip()

    # 1) check that they provided both fields
    if not user or not key:
        return jsonify({"error":"user and key required"}), 400
    # 2) look up the “correct” key for that user
    expected = API_KEY.get(user)
    if expected is None:
        return jsonify({"error":"unknown user"}), 403
    # 3) compare
    if key != expected:
        return jsonify({"error":"invalid API key"}), 401
    
    print(f"authorized user {user} with key {key}")

    # — now they’re authenticated, go ahead and unwrap the AES key —
    with open("aes_key_enc.bin", 'rb') as f:
        enc_key = f.read()

    with open("kms_private.pem", "rb") as f:
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

    response = {
        'status': 200,
        'decrypted_key': decrypted_key_b64
    }

    return jsonify(response)

if __name__ == "__main__":
    app.run(port=5000)

