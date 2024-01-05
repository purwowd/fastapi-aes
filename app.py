from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from fastapi import FastAPI, HTTPException
import base64

app = FastAPI()

KEY = get_random_bytes(16)

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt(plain_text):
    plain_text = pad(plain_text)
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(plain_text.encode('utf-8'))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt(iv, cipher_text):
    iv = base64.b64decode(iv)
    cipher_text = base64.b64decode(cipher_text)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(cipher_text).decode('utf-8'))
    return pt

@app.post("/encrypt/")
async def encrypt_data(plain_text: str):
    iv, ct = encrypt(plain_text)
    return {"iv": iv, "cipher_text": ct}

@app.post("/decrypt/")
async def decrypt_data(iv: str, cipher_text: str):
    try:
        pt = decrypt(iv, cipher_text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"plain_text": pt}
