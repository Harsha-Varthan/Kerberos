import grpc
from concurrent import futures
from Crypto.Cipher import AES
import json
import kvstore_pb2
import kvstore_pb2_grpc


def duplicate_string(string):
    while len(string) < 16:
        string += string
    return string[:16]


class EncryptionServiceServicer():
    def __init__(self, service_name):
        self.service_name = service_name

    def write_to_logs(self, context, line):
        with open("./logs/encryption_logs.txt", "a") as encryption_logs:
            encryption_logs.writelines("[%s] %s\n" % (context, line))

    def encrypt(self, request, context):
        #print(request)
        payload_dict = json.loads(request.payload)
        padded_secret_key = duplicate_string(request.secret_key).encode('utf8')
        padded_initial_vector = duplicate_string(request.master_key).encode('utf8')

        cipher = AES.new(padded_secret_key, AES.MODE_CFB, padded_initial_vector)
        encrypted_payload = cipher.encrypt(json.dumps(payload_dict).encode('utf8')).hex()
        #print("encrypted_payload inside encryption",encrypted_payload)
        #print("encrypted_payload type inside encryption",type(encrypted_payload))
        self.write_to_logs(request.context, f"Encrypted payload: {encrypted_payload}")

        return kvstore_pb2.EncryptResponse(encrypted_payload=encrypted_payload)

    def decrypt(self, request, context):
        payload_bytes = bytes.fromhex(request.encrypted_payload)
        padded_secret_key = duplicate_string(request.secret_key).encode('utf8')
        padded_initial_vector = duplicate_string(request.master_key).encode('utf8')

        cipher = AES.new(padded_secret_key, AES.MODE_CFB, padded_initial_vector)
        decrypted_payload = cipher.decrypt(payload_bytes).decode('utf8').rstrip()
        decrypted_dict = json.loads(decrypted_payload)
        #print(decrypted_dict)
        self.write_to_logs(request.context, f"Decrypted payload: {decrypted_dict}")

        return kvstore_pb2.DecryptResponse(decrypted_payload=json.dumps(decrypted_dict))


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    kvstore_pb2_grpc.add_EncryptionServiceServicer_to_server(EncryptionServiceServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    serve()