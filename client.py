import sys
import socket
import time
import struct
import threading
import os

N = 64
timestamps = {}
lock = threading.Lock()
status = True
packets_to_send = []

def validate_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            w = ord(data[i]) + (ord(data[i + 1]) << 8)
            k = s + w
            s = (k & 0xffff) + (k >> 16)
    return ~s & 0xffff

def create_packet(present_seq,packet_data):
    checksum = validate_checksum(packet_data)
    header = struct.pack('!IHH',present_seq, checksum, 21845)
    return header + packet_data

def create_packets(filename,MSS):
    global packets_to_send
    if os.path.isfile(filename):
        content = ''
        present_seq = 0
        f = open(filename, 'rb')
        byte = f.read(1)
        content += byte
        while content != '':
            if len(content) == MSS or byte == '':
                packets_to_send.append(create_packet(present_seq,content))
                content = ''
                present_seq += 1
            byte = f.read(1)
            content += byte
        packets_to_send.append(create_packet(present_seq, '!E!O!F!'))
        f.close()
    else:
        print 'File not existing.\n'
        sys.exit()

def rdt_send(addr, client_socket, N):
    packets_sent = 0
    while packets_sent < len(packets_to_send):
        if len(timestamps) < N:
            send_packets(addr, client_socket, packets_sent, packets_to_send[packets_sent])
            packets_sent += 1

def send_packets(addr, client_socket, seq_num, data):
    global timestamps, status
    lock.acquire()
    timestamps[seq_num] = time.time()
    try:
        client_socket.sendto(data, addr)
        if seq_num == len(packets_to_send) -1:
            status = False
    except Exception, e:
        print ("Server closed its connection")
        client_socket.close()
        exit()
    lock.release()
    try:
        while seq_num in timestamps:
            lock.acquire()
            if seq_num in timestamps:
                # RTO taken as 0.1
                if (time.time() - timestamps[seq_num]) > 0.1:
                    print 'Time out, Sequence Number = ' + str(seq_num)
                    timestamps[seq_num] = time.time()
                    client_socket.sendto(data, addr)
            lock.release()
    except Exception, e:
        print ("Server closed its connection-- " + str(e))
        client_socket.close()
        exit()

def get_ack_attr(ack_packet):
    ack = struct.unpack('!IHH', ack_packet)
    seq_num = ack[0]
    is_valid = False
    if ack[1] == 0 and ack[2] == 43690:
        is_valid = True
    else:
        print 'Invalid Frame as Header Format doesnt match'
    return is_valid, seq_num

def get_ack(client_socket):
    global timestamps
    try:
        while status or len(timestamps) > 0 :
            if len(timestamps) > 0:
                ack, addr = client_socket.recvfrom(2048)
                is_valid, seq_num = get_ack_attr(ack)
                if is_valid:
                    if seq_num in timestamps:
                        lock.acquire()
                        del (timestamps[seq_num])
                        if seq_num+1 == len(packets_to_send):
                            print 'Last acknowledgement recieved'
                        lock.release()
    except:
        print "Server connection closed"
        client_socket.close()
        exit()

def main():
    global N
    server_hostname = 'localhost'
    server_port = 7735
    filename = 'RFC123.txt'
    MSS = 500
    if len(sys.argv) > 1:
        server_hostname = sys.argv[1]
        server_port = int(sys.argv[2])
        filename = sys.argv[3]
        N = int(sys.argv[4])
        MSS = int(sys.argv[5])
    create_packets(filename,MSS)
    addr = (server_hostname, server_port)
    client_ip = ''
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_port = 9292
    client_socket.bind((client_ip, client_port))
    start = time.time()
    get_ack_thread = threading.Thread(target=get_ack, args=(client_socket,))
    rdt_send_thread = threading.Thread(target=rdt_send,args=(addr, client_socket, N))
    get_ack_thread.start()
    rdt_send_thread.start()
    get_ack_thread.join()
    rdt_send_thread.join()
    print 'Time taken :- ' + str(time.time() - start)

if __name__ == '__main__':
    main()
