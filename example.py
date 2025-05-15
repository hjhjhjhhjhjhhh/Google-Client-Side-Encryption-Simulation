from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import os

def generate_key_file(path):
    key = os.urandom(32)  # 256-bit AES key
    with open(path, 'wb') as f:
        f.write(key)
    print(f"Key saved to {path}")


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

def encrypt_aes_key_with_kms_public(aes_key_path, public_key_path, encrypted_key_path):
    with open(aes_key_path, 'rb') as f:
        aes_key = f.read()

    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(encrypted_key_path, 'wb') as f:
        f.write(encrypted_key)

def decrypt_aes_key_with_kms_private(aes_enc_key_path, private_key_path, decrypted_key_path):
    with open(aes_enc_key_path, 'rb') as f:
        enc_key = f.read()
    
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    decrypted_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(decrypted_key_path, 'wb') as f:
        f.write(decrypted_key)


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

# Encrypt any file
generate_key_file('aes_key.bin')
# encrypt_file('test.txt', 'test.enc', 'aes_key.bin')
encrypt_aes_key_with_kms_public('aes_key.bin', 'kms_public.pem', 'aes_key_enc.bin')
# decrypt_aes_key_with_kms_private('aes_key_enc.bin', 'kms_private.pem', 'aes_key_dec.bin')
# decrypt_file('test.enc', 'plain.txt', 'aes_key_dec.bin')
