from flask import Flask, request, send_file, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = Flask(__name__)

@app.route('/get-key', methods=['POST'])
def get_key():
    data = request.get_json()

    print("data from user is:")
    print(data)

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

