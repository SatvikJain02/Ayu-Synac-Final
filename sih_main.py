import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# --- 1. APPLICATION SETUP ---
app = FastAPI(
    title="AYU-Sync API",
    description="An API for medical terminology translation.",
    version="1.0.0"
)

# --- NEW: Added your live Netlify URL to the allowed list ---
origins = [
    "http://localhost:8081",
    "http://127.0.0.1:8081",
    "https://magical-monstera-cb8324.netlify.app", # Your live frontend URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 2. DATA & SECURITY SETUP ---
SECRET_KEY = "sih-secret-key-for-ayu-sync"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory storage for data and users
data_df: Optional[pd.DataFrame] = None
# Start with a default user for easy testing
FAKE_USERS_DB = {
    "testuser": {
        "name": "Test User",
        "contact": "testuser",
        "password": "testpassword"
    }
}

# Pydantic models for data validation
class TokenData(BaseModel):
    username: Optional[str] = None

class UserSignup(BaseModel):
    name: str
    contact: str
    password: str

@app.on_event("startup")
def load_data():
    global data_df
    try:
        # Assumes sih_data.csv is in the same directory
        data_df = pd.read_csv("sih_data.csv")
        print("Successfully loaded data from sih_data.csv.")
    except FileNotFoundError:
        print("ERROR: sih_data.csv not found. API will run without data.")
        data_df = pd.DataFrame(columns=['NAMASTE_Code', 'NAMASTE_Term', 'ICD11_Code', 'ICD11_Term'])

# --- 3. AUTHENTICATION & USER MANAGEMENT ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in FAKE_USERS_DB:
            raise credentials_exception
        return FAKE_USERS_DB[username]
    except JWTError:
        raise credentials_exception

@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup_user(user_data: UserSignup):
    if user_data.contact in FAKE_USERS_DB:
        raise HTTPException(status_code=400, detail="Username (contact) already registered.")
    FAKE_USERS_DB[user_data.contact] = {
        "name": user_data.name,
        "contact": user_data.contact,
        "password": user_data.password
    }
    return {"message": f"User {user_data.name} created successfully."}

@app.post("/token", summary="Get Authentication Token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = FAKE_USERS_DB.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["contact"], "name": user["name"]}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- 4. CORE API ENDPOINTS ---
@app.get("/lookup", summary="Search for a medical term")
async def lookup_term(filter: str, current_user: dict = Depends(get_current_user)):
    if data_df is None or filter is None:
        return []
    
    search_term = filter.lower()
    results = data_df[
        data_df['NAMASTE_Term'].str.lower().str.contains(search_term) |
        data_df['ICD11_Term'].str.lower().str.contains(search_term)
    ]
    
    if results.empty:
        return []

    # Prepare data for JSON response
    response_data = []
    for _, row in results.iterrows():
        response_data.append({
            "namaste_code": row["NAMASTE_Code"],
            "namaste_term": row["NAMASTE_Term"],
            "icd11_code": row["ICD11_Code"],
            "icd11_term": row["ICD11_Term"],
        })
    return response_data

@app.get("/translate", summary="Translate a medical code")
async def translate_code(code: str, current_user: dict = Depends(get_current_user)):
    if data_df is None:
        raise HTTPException(status_code=500, detail="Data not loaded")

    # Search in NAMASTE codes
    namaste_match = data_df[data_df['NAMASTE_Code'].str.lower() == code.lower()]
    if not namaste_match.empty:
        result = namaste_match.iloc[0]
        return {
            "original_system": "NAMASTE", "original_code": result["NAMASTE_Code"],
            "translated_system": "ICD-11", "translated_code": result["ICD11_Code"],
            "translated_display": result["ICD11_Term"]
        }

    # Search in ICD-11 codes
    icd_match = data_df[data_df['ICD11_Code'].str.lower() == code.lower()]
    if not icd_match.empty:
        result = icd_match.iloc[0]
        return {
            "original_system": "ICD-11", "original_code": result["ICD11_Code"],
            "translated_system": "NAMASTE", "translated_code": result["NAMASTE_Code"],
            "translated_display": result["NAMASTE_Term"]
        }

    raise HTTPException(status_code=404, detail="Code not found in either system")
