import uuid
from sqlmodel import Field, Session, SQLModel, create_engine, select
from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime, timedelta, timezone
from typing_extensions import Annotated
import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel

import os
import sys

from typing import List

from alibabacloud_dysmsapi20170525.client import Client as Dysmsapi20170525Client
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_dysmsapi20170525 import models as dysmsapi_20170525_models
from alibabacloud_tea_util import models as util_models
from alibabacloud_tea_util.client import Client as UtilClient


class Users(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    username: str = Field(index=True)
    password: str
    nickname: str


class Token(BaseModel):
    access_token: str
    token_type: str


class SuccessResponse(BaseModel):
    detail: str


sqlite_file_name = "./database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ACCESS_KEY_ID = ""
ACCESS_KEY_SECRET = ""
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_client() -> Dysmsapi20170525Client:
    """
    使用AK&SK初始化账号Client
    @return: Client
    @throws Exception
    """
    # 工程代码泄露可能会导致 AccessKey 泄露，并威胁账号下所有资源的安全性。以下代码示例仅供参考。
    # 建议使用更安全的 STS 方式，更多鉴权访问方式请参见：https://help.aliyun.com/document_detail/378659.html。
    config = open_api_models.Config(
        # 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID。,
        access_key_id=ACCESS_KEY_ID,
        # 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_SECRET。,
        access_key_secret=ACCESS_KEY_SECRET
    )
    # Endpoint 请参考 https://api.aliyun.com/product/Dysmsapi
    config.endpoint = f'dysmsapi.aliyuncs.com'
    return Dysmsapi20170525Client(config)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


SessionDep = Annotated[Session, Depends(get_session)]
router = APIRouter()


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)],
                           session: SessionDep):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = session.exec(select(Users).where(Users.username == username)).first()
    if user is None:
        raise credentials_exception
    return user


async def main_async(code):
    client = create_client()
    send_sms_request = dysmsapi_20170525_models.SendSmsRequest(
        sign_name='AIGenius应用',
        template_code='SMS_480130155',
        phone_numbers='15528506015',
        template_param=str({"code": code})
    )
    runtime = util_models.RuntimeOptions()
    try:
        # 复制代码运行请自行打印 API 的返回值
        await client.send_sms_with_options_async(send_sms_request, runtime)
    except Exception as error:
        # 此处仅做打印展示，请谨慎对待异常处理，在工程项目中切勿直接忽略异常。
        # 错误 message
        print(error.message)
        # 诊断地址
        print(error.data.get("Recommend"))
        UtilClient.assert_as_string(error.message)


@router.on_event("startup")
def on_startup():
    create_db_and_tables()


@router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 session: SessionDep) -> Token:
    user = session.exec(select(Users).where(Users.username == form_data.username)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # 验证密码
    if not pwd_context.verify(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")


@router.post("/register", response_model=SuccessResponse)
async def register_for_phone(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                             session: SessionDep) -> SuccessResponse:
    user = session.exec(select(Users).where(Users.username == form_data.username)).first()
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="The username already exists.")
    new_user = Users(
        id=str(uuid.uuid4()),
        username=form_data.username,
        password=pwd_context.hash(form_data.password),
        nickname=form_data.username[:3] + '****' + form_data.username[7:]
    )

    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return SuccessResponse(detail="User registered successfully. Please log in.")


@router.post("/set_nickname", response_model=SuccessResponse)
async def set_for_nickname(new_nickname: str,
                           current_user: Annotated[Users, Depends(get_current_user)],
                           session: SessionDep) -> SuccessResponse:
    current_user.nickname = new_nickname
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return SuccessResponse(detail="Nickname set successfully.")
