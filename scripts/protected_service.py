
import grpc
from concurrent import futures
from datetime import datetime
import json

import kvstore_pb2
import kvstore_pb2_grpc
from EncryptionHelper import EncryptionServiceServicer

# Define master and service secret keys
master_key = "S0m3MA5T3RK3YY"
service_secret_key = "secretsecret"

class ProtectedServiceServicer(kvstore_pb2_grpc.ProtectedServiceServicer):
    def __init__(self):
        self.eh = EncryptionServiceServicer("ProtectedServiceServicer")

    def Authenticate(self, request, context):
        # Decrypt the service ticket
        try:
            print("Received Request", request)
            decrypt_st_plain_request = kvstore_pb2.DecryptRequest(
                encrypted_payload=request.service_name, 
                secret_key=service_secret_key, 
                master_key=master_key,
                context="decrypt_st_plain_request Decryption Request"
            )
            st_plain = self.eh.decrypt(decrypt_st_plain_request, None)
            #st_plain = self.eh.decrypt(request.service_name, service_secret_key, master_key)
            print(st_plain)
        except Exception as e:
            return kvstore_pb2.AuthResponse(
                status=301,
                payload="Unauthorized: Could not decrypt service ticket."
            )
        st_plain_dict = json.loads(st_plain.decrypted_payload)
        print("st_plain_dict", st_plain_dict)
        # Verify the decrypted ticket's username matches the request
        if st_plain_dict['username'] == request.username:
            # Create the AuthResponsePayload with success message and service session key
            
            response_payload = kvstore_pb2.AuthResponsePayload(
                message="Authenticated",
                service_session_key=st_plain_dict['service_session_key']
            )
            print("response_payload", response_payload)
            # Serialize AuthResponsePayload
            serialized_payload = response_payload.SerializeToString()

            # Return a success response with serialized payload
            return kvstore_pb2.AuthResponse(
                status=204,
                payload=serialized_payload
            )
        else:
            return kvstore_pb2.AuthResponse(
                status=301,
                payload=b"Unauthorized"
            )

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    kvstore_pb2_grpc.add_ProtectedServiceServicer_to_server(
        ProtectedServiceServicer(), server
    )
    server.add_insecure_port('[::]:9090')
    server.start()
    print("gRPC server running on port 9090...")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()