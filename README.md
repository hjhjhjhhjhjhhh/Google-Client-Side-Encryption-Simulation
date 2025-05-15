
# Google-Client-Side-Encryption-Simulation  

### Member (check: collaborator)
- [x] 簡秉霖
- [x] 尤茂為
- [x] 何存益
- [x] 張育安
- [ ] 蔡昌諭  

### Temporary structure
```
client/
├── encrypt_file.py         # Encrypt file (AES-GCM), wrap key (RSA)
├── decrypt_file.py         # Decrypt file using unwrapped AES key
├── user_cert/              # Directory to store user certificate & private key

kms/
├── app.py                  # Flask KMS API for key management
├── acl.json                # Simple ACL configuration
├── stored_keys/            # Directory to store encrypted keys for files

auth/
├── generate_cert.py        # Generate certificate (RSA)
├── otp_verify.py           # 2FA verification (PyOTP)
├── issue_token.py          # Token issuance (JWT)
```

### Key Pair Generation and Certificate Creation

> Generate public/private RSA key pairs for users. Public key will send to CA for certificate.
> 
- Execute auth/generate_cert.py to generate RSA key pair.
    - create user_cert/user_private_key.pem and  user_cert/user_public_key.pem
- KMS use user’s public key to encrypt the DEK and register the user

### Client-Side Encryption of Files

- Encrypt the file locally before upload it to the KMS server. Encrypt the Data Encryption Key with user’s public key.
> 
- Execute client/encrypted_file.py to encrypt a file
    - encrypte the file, generate encrypted_file
    - DEK is encrypted with user’s public key
    - encrypted file and wrapped DEK are uploaded to the KMS server

###  Key Management and Server Interaction (KMS)

> Manage encrypted files and wrapped DEKS, validate user, control access base on ACL
> 
- execute kms/app.py to start KMS Flash Server
    - listens for requests to upload encrypted files and wrapped keys
    - stores files and manages access through ACL
- When user request for wrapped keys
    - verifies user’s certificate and auth.

### User Authentication (OTP via Google Authenticator)

> Authenticate users securely using **two-factor authentication (2FA)** before granting access to keys.
> 
- execute auth/otp_verify.py to generate OTP for user authentication
- The system verify the OTP before allowing access to KMS server

### Request Decryption Key from KMS

> Request the wrapped key (DEK) from KMS using the user's certificate and authorization token
> 
- Execute client/request_key.py to send POST request to KMS server (/get-key endpoint)
    - request include user’s certificate and authorication token

### Client-Side Decryption of the File

> Decrypt the file using the decrypted DEK (received from KMS) on the client-side.
> 
- execute client/decrypted_file.py 
    - first decrypt the wrapped DEK using user’s private RSA key
    - second, use the decrypted DEK to decrypt the file
