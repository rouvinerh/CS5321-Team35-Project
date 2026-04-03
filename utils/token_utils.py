import jwt
import time
 
SECRET = "sts-signing-secret"
ALGORITHM = "HS256"
 
def sign_token(payload):
    p = payload.copy()
    p["iat"] = int(time.time())
    p["exp"] = int(time.time()) + 3600
    return jwt.encode(p, SECRET, algorithm=ALGORITHM)
 
def verify_token(token):
    return jwt.decode(token, SECRET, algorithms=[ALGORITHM], options={"verify_aud": False})