import grpc
from concurrent import futures
from datetime import datetime
import random
import string
import json
import base64

import kvstore_pb2
import kvstore_pb2_grpc
from db_helper import DBHelper
from EncryptionHelper import EncryptionServiceServicer

class AuthenticationServiceServicer():
    def __init__(self, masterkey):
        self.db = DBHelper()
        self.masterkey = masterkey
        self.eh = EncryptionServiceServicer(service_name="AuthenticationServiceServicer")

    def duplicate_string(self, input_string):
        while len(input_string) < 16:
            input_string += input_string
        return input_string[:16]

    def login(self, request, context):
        #print(request)
       
        username = request.username
        service = request.service_name
        lifetime_of_tgt = request.lifetime_of_tgt
        #print(service)
        status, response = self.db.fetch_user(username)
        #print(status)
        #print(response)
        if status == 1:
            # Fetch TGS information
            status, tgs_service = self.db.fetch_service("tgs")
            #print(status)
            #print(tgs_service)
            if status != 1:
                return kvstore_pb2.LoginResponse(
                    status=-1, 
                    message="TGS service not found.", 
                    payload=None
                )

            tgs_secret_key = tgs_service.get_secret_key()
            #print(tgs_secret_key)
            # Generate a random session key for the client and TGS
            user_tgs_session_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

            # Create payloads for authentication acknowledgment and ticket-granting ticket
            auth_ack_payload = {
                "service_id": "tgs",
                "timestamp": str(datetime.now()),
                "lifetime": str(lifetime_of_tgt),
                "tgs_session_key": user_tgs_session_key
            }
            tgt_payload = {
                "username": username,
                "service_id": service,
                "timestamp": str(datetime.now()),
                "lifetime": str(lifetime_of_tgt),
                "tgs_session_key": user_tgs_session_key
            }
            #print(auth_ack_payload)
            #print(tgt_payload)

            # Encrypt TGT payload with the TGS secret key
            auth_request = kvstore_pb2.EncryptRequest(
                payload=json.dumps(tgt_payload), 
                secret_key=tgs_secret_key, 
                master_key=self.masterkey,
                context="TGS running succesfull in Authentication Server Code"
            )
            ticket_granting_ticket = self.eh.encrypt(auth_request, None)
            #print("ticket_granting_ticket",ticket_granting_ticket)
            # Encrypt Auth Ack payload with the client secret key
            auth_ack_request = kvstore_pb2.EncryptRequest(
            payload=json.dumps(auth_ack_payload), 
            secret_key=response.get_password(),  # Use the correct password
            master_key=self.masterkey,
            context="Client Authentication Acknowledgment"
        )
            auth_ack = self.eh.encrypt(auth_ack_request, None)
            #print(auth_ack.encrypted_payload)
            #print("ACk")
            
            # Convert encrypted ack and tgt (which are in byte format) to base64-encoded strings
            #auth_ack_base64 = base64.b64encode(auth_ack).decode('utf-8')
            #ticket_granting_ticket_base64 = base64.b64encode(ticket_granting_ticket).decode('utf-8')
            #print(type(auth_ack.encrypted_payload))
            #print(type(auth_ack))
            # Create response payload with encrypted ack and tgt
            payload = kvstore_pb2.AckAndTgtPayload(
                ack=auth_ack.encrypted_payload,
                tgt=ticket_granting_ticket.encrypted_payload
            )
            payload_ack, payload_tgt= {"ack":auth_ack.encrypted_payload}, {"tgt":ticket_granting_ticket.encrypted_payload}
            payload = {"ack":auth_ack.encrypted_payload, "tgt":ticket_granting_ticket.encrypted_payload}
            #print("Encrypted",payload)
            #print(type(payload))
            #print(type(payload_ack))
            #print(type(payload_tgt))
            return kvstore_pb2.LoginResponse(
                status=1,
                message="Login successful",
                payload_ack = auth_ack.encrypted_payload,
                payload_tgt = ticket_granting_ticket.encrypted_payload
            )
        else:
            return kvstore_pb2.LoginResponse(
                status=-1,
                message="User not found.",
                payload=None
            )

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    kvstore_pb2_grpc.add_AuthenticationServiceServicer_to_server(
        AuthenticationServiceServicer(), server
    )
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()