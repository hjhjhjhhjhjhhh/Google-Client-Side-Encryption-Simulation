# KMS_V1

### How to use
1. Activate the server
   ```sh
   python kms_server.py
   ```

2. Create test.txt and add some content to it  
   ```sh
   touch test.txt && echo "hello world" > test.txt
   ```
3. Activate the client
   ```sh
   python client.py
   ```
   &ensp;&ensp; Upon launch, enter your name to register or login.

   &ensp;&ensp;   Features:

   &ensp;&ensp;   Encrypt: You can select or drag a .txt file to encrypt.

   &ensp;&ensp;   Decrypt: You can select or drag a .enc file to decrypt.

### Reference
All the process follow spce P.5 (Procedure of Google CSE)

### TO-DO
- Currently kms server treats all the user as authorized user, need some other authentication.
- After registration, the server will distribute KMS_API_KEY to user and record into kms_api_key.txt with {user : api_key}
