import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("193.168.1.37", 54321)
s.bind(server_address)

while True:
    data, adress = s.recvfrom(1024)
    print("Server received:", data, "\n")
