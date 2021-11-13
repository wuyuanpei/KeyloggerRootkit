import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("127.0.0.1", 54321)
s.bind(server_address)

while True:
    data, adress = s.recvfrom(13)
    print("\n Server received:", data.decode('utf-8'), "\n\n")