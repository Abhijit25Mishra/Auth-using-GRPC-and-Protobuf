import grpc
import auth_pb2
import auth_pb2_grpc

def run():
    with grpc.insecure_channel("localhost:50051") as ch:
        stub = auth_pb2_grpc.AuthStub(ch)

        r = stub.Register(auth_pb2.RegisterReq(username="testuser", password="testpass"))
        print("Register response:", r)

        login = stub.Login(auth_pb2.LoginReq(username="testuser", password="testpass"))
        print("Login response:", login)

        token = login.token
        if not token:
            print("Login failed, cannot validate")
            return

        md = (("authorization", f"Bearer {token}"),)
        v = stub.Validate(auth_pb2.ValidateReq(), metadata=md)
        print("Validate response:", v)

if __name__ == "__main__":
    run()

        