# DEMO  
## Prerequisite    
> Open three terminal  
- Activate the cloud Server  
```sh
cd cloud_server  
python cloud_server.py # Activate the cloud server
```
- Activate KMS server  
```sh
cd kms_server  
python kms_server_otp.py  #Activate the kms server with otp
```
- Open Client GUI
```sh
cd client
python client.py
```
- Register and Login in by the QRcode in /client/otp_secrets  
## User Behavior (1 user)  
### Normal Encrypt & Decrypt w/o Cloud
1. UserA encrypt fileA.txt
2. UserA decrypt fileA.enc
3. Success
## User Behavior (2 user)  
### Same User Encrypt Encrypt & Decrypt w/ Cloud  
1. UserA encrypt fileA.txt
2. Upload fileA.enc to cloud server, update the ACL on kms server    
3. Download fileA.enc and obtain encrypted AES key
4. Decrypt fileA.enc by the key decrypted by kms private key
5. Success
### UserB fetch the fileA upload by UserA  
1. UserA encrypt fileA.txt
2. Upload fileA.enc to cloud server, update the ACL on kms server  
3. UserA granted UserB permission to access fileA (update ACL)
4. UserB requests fileA.enc of UserA from the cloud server.
5. UserB pass the permission check, download fileA
6. UserB decrypt fileA by the key obtain from cloud server
7. Success
### UserB fetch the fileA upload by UserA (fail)  
1. UserA encrypt fileA.txt
2. Upload fileA.enc to cloud server, update the ACL on kms server
3. UserB requests fileA.enc of UserA from the cloud server.
4. Since UserB is not on userA_fileA's ACL
5. Permission Denied
## User Behavior (3 user)  
1. UserA encrypt fileA.txt
2. Upload fileA.enc to cloud server, update the ACL on kms server
3. UserA granted UserB, UserC permission to access fileA (update ACL)
4. UserB, UserC requests fileA.enc of UserA from the cloud server  
5. UserB, UserC pass the permission check, download fileA
6. UserB, UserC decrypt fileA by the key obtain from cloud server
7. Success  
