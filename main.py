from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import sqlite3
import bcrypt
import os
from llama_cpp import Llama

# --- Config
SECRET_KEY = os.getenv("SECRET_KEY", "MySuperPass")
JWT_SECRET = os.getenv("JWT_SECRET", "MyOtherSuperPass")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

# --- Ajouter l'emplacement du modèle souhaitée
MODEL_PATH = "/models/"
DEFAULT_PROMPT = ""

# --- DB setup
db = sqlite3.connect("users.db", check_same_thread=False)
db.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

# --- LLM setup
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

llm = Llama(model_path=MODEL_PATH, n_ctx=2048, n_threads=16)

# --- FastAPI setup
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- Helper functions
def create_access_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def get_user(username: str):
    cursor = db.cursor()
    cursor.execute("SELECT username, password FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    username_db, hashed = user
    if not verify_password(password, hashed):
        return False
    return username_db

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return username

# --- Endpoints
@app.post("/register")
async def register(form_data: OAuth2PasswordRequestForm = Depends()):
    hashed_password = bcrypt.hashpw(form_data.password.encode('utf-8'), bcrypt.gensalt())
    try:
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (form_data.username, hashed_password))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")
    return {"message": "User created"}

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"username": user})
    return {"access_token": access_token, "token_type": "bearer", "username": user}

@app.get("/me")
async def me(current_user: str = Depends(get_current_user)):
    return {"username": current_user}

@app.post("/ask")
async def ask(request: Request):
    api_key = request.headers.get("X-API-Key")
    if api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    data = await request.json()
    prompt = data.get("prompt", "")

    final_prompt = f"{DEFAULT_PROMPT}\n{prompt}"

    try:
        output = llm(final_prompt, max_tokens=256, stop=["</s>"], echo=False)
        response_text = output["choices"][0]["text"].strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model inference failed: {str(e)}")

    return {"response": response_text}
