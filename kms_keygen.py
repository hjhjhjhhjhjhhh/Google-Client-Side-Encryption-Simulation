from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Export keys to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # You can use BestAvailableEncryption(b"password") for password protection
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save to files
with open("kms_private.pem", "wb") as priv_file:
    priv_file.write(private_pem)

with open("kms_public.pem", "wb") as pub_file:
    pub_file.write(public_pem)

print("Keys saved to kms_private.pem and kms_public.pem")
