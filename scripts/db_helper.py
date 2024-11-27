import grpc
from concurrent import futures
import sqlite3

import kvstore_pb2
import kvstore_pb2_grpc
from user_entity import User
from service_entity import Service

class DBHelper:
    def __init__(self):
        self.conn = sqlite3.connect("./db/users.db", check_same_thread=False)
        cursor = self.conn.cursor()
        try:
            cursor.execute("create table users(username UNIQUE, password)")
        except sqlite3.OperationalError:
            print("Table users already exists, continuing with previous data.")
        try:
            cursor.execute("create table services(name UNIQUE, secret_key)")
        except sqlite3.OperationalError:
            print("Table services already exists, continuing with previous data.")

    def fetch_user(self, username):
        cursor = self.conn.cursor()
        query = cursor.execute("select * from users where users.username = ?", (username,))
        try:
            username, password = query.fetchone()
            user = User(username, password)
            return 1, user
        except TypeError:
            return -1, "User doesn't exist."

    def fetch_service(self, service_name):
        cursor = self.conn.cursor()
        query = cursor.execute("select * from services where services.name = ?", (service_name,))
        try:
            service_name, secret_key = query.fetchone()
            service = Service(service_name, secret_key)
            return 1, service
        except TypeError:
            return -1, "Service not found."

    def add_user(self, username, password):
        cursor = self.conn.cursor()
        cursor.execute("insert into users values (?, ?)", (username, password))
        self.conn.commit()
        return "User added successfully."

    def add_service(self, name, secret_key):
        cursor = self.conn.cursor()
        cursor.execute("insert into services values (?, ?)", (name, secret_key))
        self.conn.commit()
        return "Service added successfully."

    def fetch_all(self):
        cursor = self.conn.cursor()
        query = cursor.execute("select * from users")
        users = query.fetchall()
        return users

    def delete_dummy_insert(self):
        cursor = self.conn.cursor()
        cursor.execute("delete from users where username = 'hedi' or username = 'kawkaw'")
        self.conn.commit()
        return "Dummy users deleted successfully."

    def close(self):
        self.conn.close()

class DBServiceServicer(kvstore_pb2_grpc.DBServiceServicer):
    def _init_(self):
        self.db_helper = DBHelper()

    def AddUser(self, request, context):
        result = self.db_helper.add_user(request.username, request.password)
        return kvstore_pb2.AddUserResponse(status=result)

    def FetchUser(self, request, context):
        status, user = self.db_helper.fetch_user(request.username)
        if status == 1:
            return kvstore_pb2.FetchUserResponse(status=status, username=user.username, password=user.password)
        else:
            return kvstore_pb2.FetchUserResponse(status=status, message=user)

    def AddService(self, request, context):
        result = self.db_helper.add_service(request.name, request.secret_key)
        return kvstore_pb2.AddServiceResponse(status=result)

    def FetchService(self, request, context):
        status, service = self.db_helper.fetch_service(request.name)
        if status == 1:
            return kvstore_pb2.FetchServiceResponse(status=status, name=service.name, secret_key=service.secret_key)
        else:
            return kvstore_pb2.FetchServiceResponse(status=status, message=service)

    def FetchAllUsers(self, request, context):
        users = self.db_helper.fetch_all()
        user_list = [kvstore_pb2.User(username=u[0], password=u[1]) for u in users]
        return kvstore_pb2.FetchAllUsersResponse(users=user_list)

    def DeleteDummyUsers(self, request, context):
        result = self.db_helper.delete_dummy_insert()
        return kvstore_pb2.DeleteDummyUsersResponse(status=result)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    kvstore_pb2_grpc.add_DBServiceServicer_to_server(DBServiceServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("DBService gRPC Server started on port 50051.")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()