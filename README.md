# KMS_V1

### How to use
1. Generate user's aes key
   ```sh
   python kms_keygen.py
   ```

2. Activate the server
   ```sh
   python kms_server.py
   ```

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

Example: If your username is hello, visit http://localhost:5000/otp-qr/hello to scan the QR code.

### Reference
All the process follow spec P.5 (Procedure of Google CSE)

### TO-DO
- Currently kms server treats all the user as authorized user, need some other authentication.
- After registration, the server will distribute KMS_API_KEY to user and record into kms_api_key.txt with {user : api_key}
