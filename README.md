# KMS_V1

### How to use  
1. Generate user's aes key once  
   ```sh
   python kms_keygen.py
   ```
   &ensp;&ensp; This will produce `kms_private.pem` `kms_public.pem` and `kms_api_key.txt`

2. Activate the server, this will generate two directories named `rsa_keys` and `aes_keys` 
   ```sh
   python kms_server.py
   ```
   &ensp;&ensp; `rsa_keys` : Stores RSA key pairs generated during user registration via the /register endpoint.  
   &ensp;&ensp;&ensp; - The private is saved as `{user}_private.pem`.  
   &ensp;&ensp;&ensp; - The private is saved as `{user}_public.pem`.  
   &ensp;&ensp; `aes_keys` : Stores AES keys encrypted with the user's RSA public key.  
   &ensp;&ensp;&ensp; - /store-key : Receives AES key encrypted with the user's RSA public key, decodes and saves it as `{user}.bin`  
   &ensp;&ensp;&ensp; - /get-key : Reads the encrypted AES key from `{user}.bin`, decrypts it using the user's RSA private key.  

3. Create test.txt and add some content to it  
   ```sh
   touch test.txt && echo "hello world" > test.txt
   ```
4. Activate the client
   ```sh
   python client.py
   ```
   &ensp;&ensp; Upon launch, enter your name to register or login.

   &ensp;&ensp;   Features:

   &ensp;&ensp;   Encrypt: You can select or drag a .txt file to encrypt.

   &ensp;&ensp;   Decrypt: You can select or drag a .enc file to decrypt.

5. User Authentication qr-code after registration
- After registering successfully, access your authentication QR code at:

Example: Visit http://localhost:5000/otp-qr/{user_name} to scan the QR code.

### Reference
All the process follow spec P.5 (Procedure of Google CSE)

### TO-DO
- Currently kms server treats all the user as authorized user, need some other authentication.
- Supports secure file sharing between users.
