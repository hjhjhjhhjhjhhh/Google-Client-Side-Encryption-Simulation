import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

# Load the same API key we generated
with open("alice.txt","r") as f:
    API_KEY = f.read().strip()

def encrypt_file(input_path, output_path, key_path):
    with open(input_path, 'rb') as f:
        data = f.read()

    with open(key_path, 'rb') as f:
        key = f.read()

    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    with open(output_path, 'wb') as f:
        f.write(nonce + ciphertext)

    print(f"Encrypted data saved to {output_path}")

def decrypt_file(input_path, output_path, key_path):
    with open(input_path, 'rb') as f:
        filedata = f.read()

    with open(key_path, 'rb') as f:
        key = f.read()

    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")

    nonce = filedata[:12]
    ciphertext = filedata[12:]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted data saved to {output_path}")

if __name__ == '__main__':
    # 1) locally encrypt
    encrypt_file('test.txt', 'test.enc', 'aes_key.bin')
    data = {'user': 'alice', 'key' : API_KEY} ## TODO change to other user
    # 2) fetch wrapped key
    response = requests.post('http://localhost:5000/get-key', json=data, headers={"X-API-Key": API_KEY})

    if response.status_code == 200:
        data = response.json()
        response_json = response.json()
        decrypted_key = base64.b64decode(response_json['decrypted_key'])
        
        with open('aes_key_dec.bin', 'wb') as f:
            f.write(decrypted_key)
    else:
        raise Exception(f"Failed to retrieve key from KMS: {response.text}")
    
    decrypt_file('test.enc', 'plain.txt', 'aes_key_dec.bin')
