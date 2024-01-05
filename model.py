from pydantic import BaseModel

class EncryptRequest(BaseModel):
    token: str
    plain_text: str

class DecryptRequest(BaseModel):
    token: str
    encrypted_data: str
