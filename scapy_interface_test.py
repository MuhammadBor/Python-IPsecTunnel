import threading
import socket
import os
import argparse
import netifaces
import struct
import fcntl
import sys
import time

# CUSTOM IMPORTS
from imports.headers import unpack_ipv4ah
from imports.aes import AESCipher
from scapy.all import IP, ICMP, raw, Raw, sr1, wrpcap
from scapy.layers.ipsec import SecurityAssociation, AH
from scapy.utils import PcapWriter

sa_send = SecurityAssociation(AH, spi=0x222,
                         auth_algo='HMAC-SHA1-96', auth_key=b'secret key',
                         tunnel_header=IP(src='192.168.100.6', dst='192.168.100.4'))

sa_recv= SecurityAssociation(AH, spi=0x222,
                         auth_algo='HMAC-SHA1-96', auth_key=b'secret key',
                         tunnel_header=IP(src='192.168.100.4', dst='192.168.100.6'))
# ---------- File Descriptors -----------
def read_from_fd(fd):
    # Read a packet from the file descriptor
    packet_data = os.read(fd, 1024)
    
    return packet_data


def write_to_fd(fd, packet_from_socket):
    os.write(fd, packet_from_socket)


def initiate_tun_fd(dev_name):
    # CONSTANTS
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    # Open TUN device file.
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', dev_name, IFF_TUN | IFF_NO_PI)
    ifs = fcntl.ioctl(tun, TUNSETIFF, ifr)

    return tun

# -------- END : File Descriptors ----------


# ------- Sockets and Networking ---------
def create_sockets(interface_name):
    # Create a RAW Socket to send the traffic
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Raw socket to recv the traffic
    receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    receiver.bind((interface_name, 0))

    return sender, receiver


def send_packets(sock: socket.socket, host_ip: str, dst_ip: str, cipher: AESCipher, fd):
    #ip_h = IPHeader(host_ip, dst_ip)  # create an IP header
    packet_from_fd = read_from_fd(fd)
    while packet_from_fd:
        packet = AHHeader(packet_from_fd, host_ip, dst_ip)
        print("Just before sending: ")
        sock.sendto(raw(packet), (dst_ip, 0))
        packet_from_fd = read_from_fd(fd)


def recv_packets(sock: socket.socket, host_ip: str, dst_ip: str, cipher: AESCipher, fd):
    packet_from_socket = sock.recv(2048)
    while packet_from_socket: 
        recv_packet = unpack_ipv4ah(packet_from_socket)
        # protocol 51 == AH Header
        if recv_packet is None:
            print("None Packet")
        else:
            packet_scapy = recv_packet
            print("############## THis is protocol 51 ##########3")
            IP_layer = packet_scapy[IP]
            #IP_layer.show()
            decrypted_packet = sa_recv.decrypt(IP_layer)
            print("Successfully Decapsuated") 
            print("This is protocol 51 decrypted") 
            # decrypt the packet
            decrypted_packet.show()
            #wrpcap('decaptured_cccc.pcap', decrypted_packet)
            #write to file descriptor so it can be read and sent
            write_to_fd(fd, raw(decrypted_packet))

        packet_from_socket = sock.recv(2048)

# ------- END : Sockets and Networking ---------

def AHHeader(packet_from_fd: bytes, host_ip: str, dst_ip: str):
    try:
        # Create a Scapy packet from the raw data
        original_packet = IP(packet_from_fd)
        # Check if it's an IP packet and not something else like ARP
        if IP in original_packet:
            # Encrypt the original packet with AH, encapsulating it in AH and then in the new outer IP
            encrypted_packet = sa_send.encrypt(original_packet)

            # Return the encrypted packet
            return encrypted_packet

        else:
            raise ValueError("The provided packet is not an IP packet.")

    except Exception as e:
        # Raise an exception with error message
        raise Exception(f"Error processing packet: {str(e)}")
    

# function gets user arguments and returns an object
def user_args():
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Tunnel")

    parser.add_argument("interface", help="Interface to be binded to.")
    parser.add_argument('--destination-ip', '-dst', action='store',type=str, help="Destination IP", required=True)
    parser.add_argument('--encrypt-key', '-key', action='store', type=str,help="Encryption key used for connection", required=True)
    parser.add_argument('--tun-int-name', '-tun', action='store',type=str, help="TUN int name", required=True)
    args = parser.parse_args()

    return args


if __name__ == "__main__":
    # Get user arguments
    args = user_args()

    # Create cipher with key from args
    cipher = AESCipher(args.encrypt_key)
    # Open the tunnel to an IO Stream
    fd = initiate_tun_fd(args.tun_int_name.encode())
    # Create sockets for sending and recieving
    sender, receiver = create_sockets(args.interface)
    # Get the IP from interface name
    host_ip = netifaces.ifaddresses(args.interface)[2][0]['addr']
    print("This is host ip", host_ip)

    # Create threads for sending and receiving packets
    sendT = threading.Thread(target=send_packets, args=(
        sender, host_ip, args.destination_ip, cipher, fd))
    recvT = threading.Thread(target=recv_packets, args=(
        receiver, host_ip, args.destination_ip, cipher, fd))

    # Begin threads
    sendT.setDaemon(True)
    sendT.start()
    recvT.setDaemon(True)
    recvT.start()

    print("Tunnel is open and running...")
    while True:
        try:
            for _ in range(10):
                time.sleep(0.2)
        except KeyboardInterrupt:
            sys.exit(1)

            