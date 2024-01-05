from fastapi import FastAPI, HTTPException, Body
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

from model import EncryptRequest, DecryptRequest    

app = FastAPI()

def generate_key_iv():
    return os.urandom(32), os.urandom(16)

key, iv = generate_key_iv()
backend = default_backend()
cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)

def validate_token(token: str) -> bool:
    return token == "secret"

def encrypt(plain_text: str) -> str:
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode()

def decrypt(encrypted_data: bytes) -> str:
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode()

@app.post("/encrypt/")
async def encrypt_data(request: EncryptRequest = Body(...)):
    if not validate_token(request.token):
        raise HTTPException(status_code=403, detail="Invalid token")
    encrypted_data = encrypt(request.plain_text)
    return {"encrypted_data": encrypted_data}

@app.post("/decrypt/")
async def decrypt_data(request: DecryptRequest = Body(...)):
    if not validate_token(request.token):
        raise HTTPException(status_code=403, detail="Invalid token")
    decrypted_data = decrypt(base64.b64decode(request.encrypted_data))
    return {"plain_text": decrypted_data}
