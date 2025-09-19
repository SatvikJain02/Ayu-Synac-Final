import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import os

# --- 1. APPLICATION SETUP ---
app = FastAPI(
    title="AYU-Sync API",
    description="Final prototype with user profiles and OTP simulation.",
    version="7.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8081", "http://localhost:8081", "null"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 2. SECURITY & USER MANAGEMENT ---
SECRET_KEY = "sih-secret-key-for-ayu-sync-profiles"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory user database, now with more fields
USERS_DB = [
    {"name": "Test User", "contact": "testuser", "password": "testpassword"}
]

class UserSignup(BaseModel):
    name: str
    contact: str # This will be used as the username
    password: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or not any(user['contact'] == username for user in USERS_DB):
            raise credentials_exception
        user = next((user for user in USERS_DB if user['contact'] == username), None)
        return user
    except JWTError:
        raise credentials_exception

@app.post("/signup", summary="Register a new user")
async def signup_user(user_data: UserSignup):
    if any(u['contact'] == user_data.contact for u in USERS_DB):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This contact is already registered"
        )
    USERS_DB.append(user_data.dict())
    return {"message": "User created successfully. Please log in."}

@app.post("/token", summary="Get Authentication Token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = next((u for u in USERS_DB if u['contact'] == form_data.username), None)
    
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Include user's name in the token payload
    access_token = create_access_token(
        data={"sub": user["contact"], "name": user["name"]}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- 3. DATA LOADING ---
data_df: Optional[pd.DataFrame] = None

@app.on_event("startup")
def load_data():
    global data_df
    try:
        script_dir = os.path.dirname(__file__)
        csv_path = os.path.join(script_dir, "sih_data.csv")
        data_df = pd.read_csv(csv_path)
        print("Successfully loaded data from sih_data.csv.")
    except Exception as e:
        print(f"FATAL ERROR: Could not load data from CSV: {e}")

# --- 4. API ENDPOINTS ---
@app.get("/lookup", summary="Improved Terminology Lookup")
async def lookup_term(filter: str, current_user: dict = Depends(get_current_user)) -> List[Dict[str, str]]:
    if data_df is None: raise HTTPException(status_code=500, detail="Server data not loaded.")
    if not filter: return []
    
    search_term = filter.lower()
    mask = (data_df['NAMASTE_Term'].str.lower().str.contains(search_term, na=False)) | \
           (data_df['ICD11_Term'].str.lower().str.contains(search_term, na=False))
    matches = data_df[mask]
    
    return [{"namaste_term": r['NAMASTE_Term'], "namaste_code": r['NAMASTE_Code'],
             "icd11_term": r['ICD11_Term'], "icd11_code": r['ICD11_Code']} for i, r in matches.iterrows()]

@app.get("/translate", summary="Two-Way Code Translation")
async def translate_code(code: str, current_user: dict = Depends(get_current_user)) -> Dict[str, str]:
    if data_df is None: raise HTTPException(status_code=500, detail="Server data not loaded.")

    namaste_match = data_df[data_df['NAMASTE_Code'] == code]
    if not namaste_match.empty:
        r = namaste_match.iloc[0]
        return {"original_system": "NAMASTE", "original_code": code, "translated_system": "ICD-11",
                "translated_code": r['ICD11_Code'], "translated_display": r['ICD11_Term']}

    icd_match = data_df[data_df['ICD11_Code'] == code]
    if not icd_match.empty:
        r = icd_match.iloc[0]
        return {"original_system": "ICD-11", "original_code": code, "translated_system": "NAMASTE",
                "translated_code": r['NAMASTE_Code'], "translated_display": r['NAMASTE_Term']}

    raise HTTPException(status_code=404, detail="Translation not found")

