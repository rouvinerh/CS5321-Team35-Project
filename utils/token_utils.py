import jwt
import time
import hmac
import hashlib
import json

SECRET = "sts-signing-secret-for-cs5321-netsec-project"
ALGORITHM = "HS256"

def sign_token(payload):
    p = payload.copy()
    p["iat"] = int(time.time())
    p["exp"] = int(time.time()) + 3600
    return jwt.encode(p, SECRET, algorithm=ALGORITHM)

def verify_token(token):
    return jwt.decode(token, SECRET, algorithms=[ALGORITHM], options={"verify_aud": False})

def sign_capability(cap_dict):
    msg = json.dumps(cap_dict, sort_keys=True).encode()
    return hmac.new(SECRET.encode(), msg, hashlib.sha256).hexdigest()

def verify_capability_sig(capability):
    expected = sign_capability(capability["cap"])
    if capability["sig"] != expected:
        raise ValueError("Invalid capability signature")