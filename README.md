# KMS_V1

### How to use
1. run `kms_keygen.py`, this will generate `kms_private.pem` and `kms_public.pem`  
2. run `example.py`, this will generate `aes_key.bin` and `aes_key_enc.bin`, where `aes_key_enc.bin` is `aes_key.bin` encrypted by `kms_public.pem`  
3. `python kms_server.py`  
4. prepare a `test.txt` and run `client.py`, you should see `plain.txt` with identical content generated

### Reference
All the process follow spce P.5 (Procedure of Google CSE)

### TO-DO
- Currently kms server treats all the user as authorized user, need some other authentication.