import os
from concurrent import futures
from datetime import datetime, timedelta

import grpc
import auth_pb2
import auth_pb2_grpc
import jwt 
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXP_MINUTES = 30

pwd_ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

USER_STORE = {}

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": datetime.now(datetime.timezone.utc),
        "exp": datetime.now(datetime.timezone.utc) + timedelta(minutes=JWT_EXP_MINUTES)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm = JWT_ALGORITHM)
    return token

def decode_token(token:str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
    except Exception:
        raise ValueError("Invalid token")


class AuthServicer(auth_pb2_grpc.AuthServicer):
    def Register(self, request, context):
        username = request.username.strip()
        password = request.password
        if not username or not password:
            return auth_pb2.AuthResp(error = "username and password required")

        if username in USER_STORE:
            return auth_pb2.AuthResp(error = "user already exists")

        hashed_password = pwd_ctx.hash(password)
        USER_STORE[username] = hashed_password
        return auth_pb2.AuthResp(token = "user registered successfully")

    def Login(self, request, context):
        username = request.username.strip()
        password = request.password
        if not username or not password:
            return auth_pb2.AuthResp(error = "username and password required")

        stored_password = USER_STORE.get(username)
        if not stored_password or not pwd_ctx.verify(password, stored_password):
            return auth_pb2.AuthResp(error = "invalid username or password")

        token = create_token(username)
        return auth_pb2.AuthResp(token = token)

    def Validate(self, request, context):
        md = dict(context.invocation_metadata())
        auth = md.get("authorization") or md.get("Authorization")
        if not auth:
            return auth_pb2.ValidateResp(valid = False, error = "authorization token required")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
        else:
            token = auth

        try: 
            payload = decode_token(token)
            username = payload["sub"]
            return auth_pb2.ValidateResp(valid = True, username = payload["sub"])
        except jwt.ExpiredSignatureError:
            return auth_pb2.ValidateResp(valid = False, error = "token has expired")
        except Exception:
            return auth_pb2.ValidateResp(valid = False, error = "invalid token") 

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    auth_pb2_grpc.add_AuthServicer_to_server(AuthServicer(), server)
    serve.add_insecure_port('[::]:50051')
    server.start()
    print("Auth gRPC server running on port 50051")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
