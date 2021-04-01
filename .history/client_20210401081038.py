import socket
import ssl
import time.sleep

class client_ssl:
    def send_hello(self,):
        CA_FILE = "CA.crt"
        KEY_FILE = "Client.key"
        CERT_FILE = "Client.crt"

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.check_hostname = False
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.socket() as sock:
            with context.wrap_socket(sock, server_side=False) as ssock:
                ssock.connect(('127.0.0.1', 5678))
                msg = "do i connect with server ?".encode("utf-8")
                ssock.send(msg)
                msg = ssock.recv(1024).decode("utf-8")
                print(f"receive msg from server : {msg}")
                sleep(10)
                ssock.close()

if __name__ == "__main__":
    client = client_ssl()
    client.send_hello()
