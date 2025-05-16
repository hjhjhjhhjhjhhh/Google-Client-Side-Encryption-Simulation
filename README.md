# KMS_V1

### How to use
1. ```sh
   python kms_keygen.py
   ```
   &ensp;&ensp;This will generate `kms_private.pem` and `kms_public.pem` and `kms_api_key.txt`  
2. ```sh
   python example.py
   ```  
   &ensp;&ensp;This will generate `aes_key.bin` and `aes_key_enc.bin`, where `aes_key_enc.bin` is `aes_key.bin` encrypted by `kms_public.pem` 
3. &ensp;&ensp;Activate the server
   ```sh
   python kms_server.py
   ```
4. Create test.txt and add some content to it  
   ```sh
   touch test.txt && echo "hello world" > test.txt
   ```
   ```sh
   python client.py
   ```
   &ensp;&ensp;You should see `plain.txt` with identical content generated

### Reference
All the process follow spce P.5 (Procedure of Google CSE)

### TO-DO
- Currently kms server treats all the user as authorized user, need some other authentication.
- After registration, the server will distribute KMS_API_KEY to user and record into kms_api_key.txt with {user : api_key}
