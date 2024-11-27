import grpc
from concurrent import futures
import time
import kvstore_pb2
import kvstore_pb2_grpc
from authentication_server import AuthenticationServiceServicer
from ticket_granting_service import TicketGrantingServiceServicer

master_key = "S0m3MA5T3RK3YY"
AS = AuthenticationServiceServicer(master_key)
TGS = TicketGrantingServiceServicer(master_key)

class KDCService(kvstore_pb2_grpc.KDCService):
    def Authenticate(self, request, context):
        user_name = request.username
        service_name = request.service_name
        lifetime_of_tgt = request.lifetime_of_tgt
        payload = AS.login(request, context)
        #print(payload)
        #print(type(payload))
        status = payload.status

        #print(status)
        if status == 1:
            #print("inside if")
            #print(payload)
            return kvstore_pb2.AuthenticateResponse(status=200, message="Authentication successful", payload_ack = payload.payload_ack, payload_tgt = payload.payload_tgt)
        else:
            return kvstore_pb2.AuthenticateResponse(status=404, message="User not found")

    def GetServiceTicket(self, request, context):
        tgt = request.tgt
        authenticator = request.authenticator
        tgr = request.tgr
        #status, payload = TGS.ProcessTicketGrantingRequest(request, context)
        payload = TGS.ProcessTicketGrantingRequest(request, context)
        #print("payload_kdc",payload)
        status = payload.status
        if status == 200:
            return kvstore_pb2.ServiceTicketResponse(status=200, message="Service ticket generated", tgs_ack_ticket=payload.tgs_ack_ticket, service_ticket = payload.service_ticket)
        elif status == -1:
            return kvstore_pb2.ServiceTicketResponse(status=404, message="Service not found")
        elif status == -2:
            return kvstore_pb2.ServiceTicketResponse(status=304, message="Access Denied")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    kvstore_pb2_grpc.add_KDCServiceServicer_to_server(KDCService(), server)
    server.add_insecure_port('[::]:8989')
    server.start()
    print("gRPC server running on port 8989...")
    server.wait_for_termination()

if __name__ == '__main__':
    serve()