import socket
import time
import struct

TIMEOUT = 3  # seconds
PORT = 33434
ICMP = socket.getprotobyname('icmp')
UDP = socket.getprotobyname('udp')

icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP)
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP)

timeout_struct = struct.pack('ll', TIMEOUT, 0)
icmp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout_struct)

host = "google.com"
dest_addr = socket.gethostbyname(host)
ttl = 1

print(f"Tracerouting... {host}({dest_addr})")
while True:
    udp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    udp_sock.sendto(b'', (dest_addr, PORT))
    start_time = time.time()
    no_tries = 3
    success = False
    done = False
    name = ""
    while no_tries > 0:
        try:
            packet, addr = icmp_sock.recvfrom(512)
            success = True
        except socket.error:
            no_tries -= 1
            continue
        if addr[0] == dest_addr:
            done = True
            break
    if success:
        end_time = time.time()
        try:
            name = socket.gethostbyaddr(addr[0])[0]
        except:
            pass
        t = round((end_time - start_time) * 1000, 4)
        print(f"TTL: {ttl} Addr: {name}({addr[0]}) Time: {t}ms")
    else:
        print(f"TTL: {ttl} *  *  *")

    if done:
        break
    ttl += 1

print("Traceroute completed.")