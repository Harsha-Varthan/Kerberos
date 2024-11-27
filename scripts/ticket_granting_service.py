import grpc
from concurrent import futures
import json
import random
import string
from datetime import datetime

import kvstore_pb2
import kvstore_pb2_grpc
from db_helper import DBHelper
from EncryptionHelper import EncryptionServiceServicer

# Define master key and initialize service
masterkey = "S0m3MA5T3RK3YY"

class TicketGrantingServiceServicer(kvstore_pb2_grpc.TicketGrantingServiceServicer):
    #def __init__(self):
    #    self.db = DBHelper()
    #    self.master_key = master_key
    #    self.eh = EncryptionServiceServicer("TicketGrantingServiceServicer")
    def __init__(self, masterkey):
        self.db = DBHelper()
        self.masterkey = masterkey
        self.eh = EncryptionServiceServicer(service_name="TicketGrantingServiceServicer")

    def ProcessTicketGrantingRequest(self, request, context):
        # Parse the input JSON
        try:
            tgr_json = json.loads(request.tgr.replace("'", "\""))
        except json.JSONDecodeError:
            return kvstore_pb2.TicketGrantingResponse(
                status=-1,
                message="Invalid request format.",
                tgs_ack_ticket = "",
                service_ticket = ""
            )

        # Fetch the service requested by the client
        status, fetched_service = self.db.fetch_service(str(tgr_json.get('service_name')))
        if status == -1:
            return kvstore_pb2.TicketGrantingResponse(
                status=-1,
                message=fetched_service,
                tgs_ack_ticket = "",
                service_ticket = ""
            )

        # Process the Ticket Granting Ticket (TGT) and Authenticator
        service_secret_key = fetched_service.get_secret_key()
        if service_secret_key:
            status, fetched_tgs = self.db.fetch_service("tgs")
            if not fetched_tgs:
                return kvstore_pb2.TicketGrantingResponse(
                    status=-1,
                    message="TGS service not found.",
                    tgs_ack_ticket = "",
                    service_ticket = ""
                )
            
            tgs_secret_key = fetched_tgs.get_secret_key()
            #print("tgs_req",request)
            #print("tgs_secret_key", tgs_secret_key)
            #print("master key", self.masterkey)
            decrypt_tgtplain_request = kvstore_pb2.DecryptRequest(
                encrypted_payload=request.tgt, 
                secret_key=tgs_secret_key, 
                master_key=self.masterkey,
                context="TGT_Plain Decryption Request"
            )
            #ticket_granting_ticket_plain = self.eh.decrypt(request.tgt, tgs_secret_key, self.masterkey)
            ticket_granting_ticket_plain = self.eh.decrypt(decrypt_tgtplain_request, None)
            ticket_granting_ticket_plain_dict = json.loads(ticket_granting_ticket_plain.decrypted_payload)
            #print("ticket_granting_ticket_plain", ticket_granting_ticket_plain)
            decrypt_authplain_request = kvstore_pb2.DecryptRequest(
                encrypted_payload=request.authenticator, 
                secret_key=ticket_granting_ticket_plain_dict['tgs_session_key'], 
                master_key=self.masterkey,
                context="Auth_Plain Decryption Request"
            )

            #authenticator_plain = self.eh.decrypt(request.authenticator, ticket_granting_ticket_plain.get('tgs_session_key'), self.masterkey)
            authenticator_plain = self.eh.decrypt(decrypt_authplain_request, None)
            #print("authenticator_plain", authenticator_plain)
            authenticator_plain_dict = json.loads(authenticator_plain.decrypted_payload)
            if authenticator_plain_dict['username'] == ticket_granting_ticket_plain_dict['username']:
                # Generate service session key
                service_session_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
                service_payload = {
                    "username": authenticator_plain_dict['username'],
                    "service_id": tgr_json.get('server_id'),
                    "timestamp": str(datetime.now()),
                    "lifetime_of_ticket": "2",
                    "service_session_key": service_session_key
                }
                service_ticket_request = kvstore_pb2.EncryptRequest(
                    payload=json.dumps(service_payload), 
                    secret_key=service_secret_key, 
                    master_key=self.masterkey,
                    context="Service ticket encryption in TGS"
                )
                #service_ticket_encrypted = self.eh.encrypt(service_payload, service_secret_key, self.masterkey)
                service_ticket_encrypted = self.eh.encrypt(service_ticket_request, None)
                #print("service_ticket_encrypted", service_ticket_encrypted)
                tgs_ack_payload = {
                    "service_id": tgr_json.get('service_id'),
                    "timestamp": str(datetime.now()),
                    "lifetime_of_ticket": "2",
                    "service_session_key": service_session_key
                }
                tgs_ack_request = kvstore_pb2.EncryptRequest(
                    payload=json.dumps(tgs_ack_payload), 
                    secret_key=ticket_granting_ticket_plain_dict['tgs_session_key'], 
                    master_key=self.masterkey,
                    context="TGS Ack request in TGS"
                )
                #tgs_ack_encrypted = self.eh.encrypt(tgs_ack_payload, ticket_granting_ticket_plain.get('tgs_session_key'), self.masterkey)
                tgs_ack_encrypted = self.eh.encrypt(tgs_ack_request, None)
                #print("tgs_ack_encrypted", tgs_ack_encrypted)
                #print(type(tgs_ack_encrypted))
                
                #print(tgs_ack_encrypted.encrypted_payload)
                #print(type(tgs_ack_encrypted.encrypted_payload))
                #service_ticket_encrypted_dict = json.loads(service_ticket_encrypted)
                #print(service_ticket_encrypted_dict)
                #tgs_ack_encrypted_dict = json.loads(tgs_ack_encrypted.encrypted_payload)
                #print(tgs_ack_encrypted_dict)
                #tickets={
                        #"tgs_ack_ticket": tgs_ack_encrypted.encrypted_payload,
                        #"service_ticket": service_ticket_encrypted.encrypted_payload}
                #print(tickets)
                #print(type(tickets))
                self.db.close()
                return kvstore_pb2.TicketGrantingResponse(
                    status=200,
                    message="TGS Ack and Service Ticket sent to client",
                    tgs_ack_ticket = tgs_ack_encrypted.encrypted_payload,
                    service_ticket = service_ticket_encrypted.encrypted_payload
                )
            else:
                return kvstore_pb2.TicketGrantingResponse(
                    status=-2,
                    message="Access Denied",
                    tgs_ack_ticket = "",
                    service_ticket = ""
                )

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    kvstore_pb2_grpc.add_TicketGrantingServiceServicer_to_server(
        TicketGrantingServiceServicer(), server
    )
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()