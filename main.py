import os
import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()


AUDIENCE  = os.environ.get("AUDIENCE", "")
ISUSER =  "https://idp.exam.local"

def normalize_pem(raw: str) -> str:
    """Fix PEM keys however Render/env vars may have mangled them."""
    if not raw:
        return ""
    raw = raw.replace("\\n", "\n").strip()
 
    # Already has proper newlines and headers — good to go
    if "-----BEGIN PUBLIC KEY-----" in raw and "\n" in raw:
        return raw
 
    # Has headers but newlines collapsed into spaces
    if "-----BEGIN PUBLIC KEY-----" in raw:
        body = raw.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()
        body = "".join(body.split())   # strip all whitespace
        body = "\n".join(body[i:i+64] for i in range(0, len(body), 64))
        return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"
 
    # Raw base64 body only — wrap it
    body = "".join(raw.split())
    body = "\n".join(body[i:i+64] for i in range(0, len(body), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"

PUBLIC_KEY = normalize_pem(os.environ.get("PUBLIC_KEY", ""))


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