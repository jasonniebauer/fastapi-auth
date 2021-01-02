from datetime import datetime, timedelta
from typing import Optional

from decouple import config
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = config("secret_key")
ALGORITHM = config("algorithm")
ACCESS_TOKEN_EXPIRE_MINUTES = int(config("access_token_expire_minutes"))


fake_users_db = [
    {
        "id": 1,
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
    {
        "id": 2,
        "username": "devtester",
        "full_name": "John Smith",
        "email": "text@example.com",
        "hashed_password": "$2b$12$bpyWBSP8O5f9PEGd3HnWnul/t/mlQF9Uh89EJKWEzrHHF4kNu2Ava",
        "disabled": False,
    }
]


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # api/v1/token

app = FastAPI()


def verify_password(plain_password, hashed_password):
    """Function to compare plaintext password and hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """Function to hash password."""
    return pwd_context.hash(password)


def get_user(db, username: str):
    """Function to retrieve user from database."""
    for user in db:
        if user["username"] == username:
            return UserInDB(**user)


def authenticate_user(fake_db, username: str, password: str):
    """Function to check if username exists and passwords match."""
    user = get_user(fake_users_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Function to create access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Function to check if current user is authenticated."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> dict:
    """Function to retrieve current active user."""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def check_username_exists(username: str) -> bool:
    """Function to check if username exists in database."""
    # REPLACE WITH DATABASE QUERY
    for user in fake_users_db:
        if user["username"] == username:
            return True
    return False


@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()) -> dict:
    """Function to authenticate user and provide access token."""
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Create an access token with user's username as the subject and
    # the expiration date using the expiration defined
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user", dependencies=[Depends(get_current_active_user)])
async def create_user(user: User) -> dict:
    """Function to create new user in database."""
    if check_username_exists(user.username):
        return {
            "error": "That username is already taken."
        }

    user_dict = user.dict()
    user_dict.update({
        "hashed_password": get_password_hash("secret123")
    })

    # REPLACE WITH DATABASE INSERT
    fake_users_db.append(user_dict)

    return {
        "data": "User created successfully."
    }


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)) -> dict:
    """Function to retrieve details for current active user."""
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)) -> list:
    """Function to retrieve items for current active user."""
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.get("/users/{id}")
async def read_users_me(id: int) -> dict:
    """Function to retrieve user by ID."""
    # REPLACE WITH DATABASE QUERY
    for user in fake_users_db:
        if user["id"] == id:
            return {
                "data": user
            }
    
    return {
        "error": "No user with the supplied ID."
    }