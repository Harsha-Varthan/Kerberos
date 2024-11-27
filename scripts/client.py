import grpc
import time
from datetime import datetime
import kvstore_pb2
import kvstore_pb2_grpc
from EncryptionHelper import EncryptionServiceServicer
import json

# Set up master key and EncryptionHelper
master_key = "S0m3MA5T3RK3YY"
eh = EncryptionServiceServicer("Client")

# Duplicate string helper for padding
def duplicate_string(input_string):
    while len(input_string) < 16:
        input_string += input_string
    return input_string[:16]

def main():
    # Phase 1: Authenticate with the Authentication Server
    with grpc.insecure_channel('localhost:8989') as channel:
        stub = kvstore_pb2_grpc.KDCServiceStub(channel)
        
        # Collect user input
        user_name = input("Enter user id to authenticate with: ")
        service_id = input("Service ID to authenticate with: ")
        
        # Construct payload and send authentication request
        auth_request = kvstore_pb2.AuthenticateRequest(
            username=user_name,
            service_name=service_id,
            lifetime_of_tgt="2"
        )
        #print(type(auth_request))
        #print(auth_request)
        print("-" * 40)
        print("Authenticating with the server...")
        
        auth_response = stub.Authenticate(auth_request)
        #print(auth_response)
        time.sleep(2)

        # Process authentication response
        if auth_response.status == 200:
            print("Successfully Authenticated.")
            print("-" * 40)
            #print(auth_response)
            #response_payload = auth_response.payload
            ack_sent = auth_response.payload_ack
            #response_payload.get('ack')
            ticket_granting_ticket = auth_response.payload_tgt
            #response_payload.get('tgt')

            # User input for decryption key
            user_secret_key = input("Your Secret Key To Decrypt: ")
            
            # Decrypt the acknowledgment
            decrypt_tgt_request = kvstore_pb2.DecryptRequest(
                encrypted_payload=ack_sent, 
                secret_key=user_secret_key, 
                master_key=master_key,
                context="TGS Decryption Request"
            )
            ack_plain = eh.decrypt(decrypt_tgt_request, None)
            print("-" * 40)
            print("Acknowledgement from Authentication Server")
            
            # Extract TGS session key
            #print(ack_plain)
            #print(type(ack_plain.decrypted_payload))
            ack_plain_dict = json.loads(ack_plain.decrypted_payload)
            #print(ack_plain_dict)
            #print(type(ack_plain_dict))
            #print(ack_plain_dict['tgs_session_key'])
            tgs_session_key = ack_plain_dict['tgs_session_key']
            time.sleep(2)
            print("Ticket Granting Ticket from Authentication Server")
            print(ticket_granting_ticket)
            print("-" * 40)

            # Phase 2: Contact Ticket Granting Server (TGS) for a service ticket
            auth_payload = {"username": user_name, "timestamp": str(datetime.now())}
            encrypt_auth_payload = kvstore_pb2.EncryptRequest(
                payload = json.dumps(auth_payload),
                secret_key=tgs_session_key, 
                master_key=master_key,
                context="TGS Encryption Request"
            )
            #print(encrypt_auth_payload)
            #auth_cipher = eh.encrypt(auth_payload, tgs_session_key, master_key)
            auth_cipher = eh.encrypt(encrypt_auth_payload, None)
            #print(auth_cipher)
            
            # Construct ticket grant request for service
            tgr_payload = {"service_name": service_id, "lifetime_of_ticket": "2"}
            ticket_request = kvstore_pb2.ServiceTicketRequest(
                tgt=ticket_granting_ticket,
                authenticator=auth_cipher.encrypted_payload.encode('utf8'),
                tgr=str(tgr_payload)
            )
            
            print("Contacting Ticket Granting Server...")
            print(ticket_request)
            ticket_response = stub.GetServiceTicket(ticket_request)
            #print(ticket_response)
            tgs_response_payload = ticket_response.tgs_ack_ticket
            
            if ticket_response.status == 200:
                print("Received response payload:", tgs_response_payload)
                
                # Decrypt TGS acknowledgment ticket to get the service session key
                #tgs_ack_ticket = eh.decrypt(tgs_recieved_payload.get('tgs_ack_ticket'), tgs_session_key, master_key)
                decrypt_tgtack_request = kvstore_pb2.DecryptRequest(
                    encrypted_payload=tgs_response_payload, 
                    secret_key=tgs_session_key, 
                    master_key=master_key,
                    context="TGT_Plain Decryption Request"
                )
                tgs_ack_ticket = eh.decrypt(decrypt_tgtack_request, None)
                #print("tgs_ack_ticket_dec", tgs_ack_ticket)
                service_ticket = ticket_response.service_ticket
                tgs_ack_ticket_dict = json.loads(tgs_ack_ticket.decrypted_payload)
                session_key = tgs_ack_ticket_dict['service_session_key']
                
                # Service payload to send to final service
                service_payload = {"service_ticket": service_ticket, "username": user_name}
                print('-' * 40)
                print("Contacting service with payload:", service_payload)
                
                # Here you would connect to the service with a separate gRPC call
                # Assuming there's another service running on localhost:9090 for the final request
                # For example:
                with grpc.insecure_channel('localhost:9090') as service_channel:
                    service_stub = kvstore_pb2_grpc.ProtectedServiceStub(service_channel)
                    #service_stub = YourServiceStub(service_channel)
                    auth_service_protected_request = kvstore_pb2.AuthenticateRequest(
                        username=service_payload['username'],
                        service_name=service_payload['service_ticket'],
                        lifetime_of_tgt="2"
                    )
                    #ticket_request = kvstore_pb2.ServiceTicketRequest(
                    #    tgt=ticket_granting_ticket,
                    #    authenticator=auth_cipher.encrypted_payload.encode('utf8'),
                    #    tgr=str(tgr_payload)
                    #)
                    print(auth_service_protected_request)
                    #service_response = service_stub.Authenticate(service_payload)
                    service_response = service_stub.Authenticate(auth_service_protected_request)
                    print(service_response, session_key)
            else:
                print("TGS Response Message:", tgs_response_payload.message)
        else:
            print("Authentication Failed:", auth_response.message)

if __name__ == "__main__":
    main()