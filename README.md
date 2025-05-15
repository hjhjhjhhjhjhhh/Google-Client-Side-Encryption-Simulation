# KMS_V1

### How to use
1. ```sh
   python kms_keygen.py
   ```
   &ensp;&ensp;This will generate `kms_private.pem` and `kms_public.pem`  
2. ```sh
   pyhton example.py
   ```  
   &ensp;&ensp;This will generate `aes_key.bin` and `aes_key_enc.bin`, where `aes_key_enc.bin` is `aes_key.bin` encrypted by `kms_public.pem`  
3. &ensp;&ensp;Activate the server
   ```sh
   python kms_server.py
   ```
4. ```sh
   touch test.txt
   ```
   &ensp;&ensp;Add some content into `test.txt`
   ```sh
   python client.py
   ```
   &ensp;&ensp;You should see `plain.txt` with identical content generated

### Reference
All the process follow spce P.5 (Procedure of Google CSE)

### TO-DO
- Currently kms server treats all the user as authorized user, need some other authentication.
