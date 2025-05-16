## User Registration Interface for KMS Server

### 1. Ensure the Existence of the KMS Server Keys
Before running the registration interface, make sure the KMS server keys exist. If not, generate them using:
```
python kms_keygen.py
```

If either kms_private.pem or kms_public.pem is missing, the registration script will show the following message:

```
[INFO] Please run 'python kms_keygen.py' to generate KMS keys before registering users.
```



### 2. Run the Registration Interface

Launch the registration interface:
```
python registration_interface.py
```
### 3. Register a New User

Fill in the registration form:
```
Username: Unique identifier

Password: Secure password (hashed with SHA-256)

Email: Must be a valid email address
```
### 4. Verify User Data

User data will be stored in the user_data/ directory with the following format:
```
Username: <username>
Email: <email>
Password: <hashed_password>
API Key: <api_key>
```

The API key will also be appended to kms_api_key.txt for server reference.



## To-Do
- Add password strength validation
- Enhance UI with more modern design
