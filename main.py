import os
import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()


PUBLIC_KEY = os.environ.get("PUBLIC_KEY", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA")
AUDIENCE  = os.environ.get("AUDIENCE", "")
ISUSER =  "https://idp.exam.local"

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
async def verify(body: TokenRequest):
    if not PUBLIC_KEY or not AUDIENCE:
        return JSONResponse(status_code=500, content={"valid": False, "error": "server Misconfig"})
    
    try:
        claims = jwt.decode(
            body.token,
            PUBLIC_KEY,
            audience=AUDIENCE,
            issuer=ISUSER,
            algorithms=["RS256"],
            options={
                "require": ["exp", "iss", "aud", "sub", "email"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True 
            }
        )

        return JSONResponse(status_code=200, content={
            "valid": True,
            "email": claims.get("email", ""),
            "sub": claims.get("sub", ""),
            "aud": claims.get("aud", "")
        })
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Token expired"})
    except jwt.InvalidAudienceError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Invalid audience"})
    except jwt.InvalidIssuerError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Invalid issuer"})
    except jwt.InvalidSignatureError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Invalid signature"})
    except jwt.DecodeError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Malformed token"})
    except Exception as e:
        return JSONResponse(status_code=401, content={"valid": False, "error": str(e)})
    
@app.get("/")
async def root():
    return {"status": "ok"}