import socket
import struct
import random
import sys

def validate_checksum(data,check_sum):
    s = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            w = ord(data[i]) + (ord(data[i + 1]) << 8)
            k = s + w
            s = (k & 0xffff) + (k >> 16)
    cal_check_sum = s & 0xffff
    return cal_check_sum & check_sum

def get_attr(packet_data):
    data = packet_data[8:]
    header = struct.unpack('!IHH', packet_data[0:8])
    seq_num = header[0]
    check_sum = header[1]
    is_valid = False
    check_sum_verified = validate_checksum(data,check_sum)
    if check_sum_verified == 0 and header[2] == 21845:
        is_valid = True
    return is_valid, seq_num, data

def main():
    port = 7735
    file_name = 'RFC123.txt'
    prob = 0.05
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
        file_name = sys.argv[2]
        prob = float(sys.argv[3])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', port))
    prev_seq_num = -1
    f = open(file_name, 'wb')
    flag = True
    while flag:
        packet_data, addr = server_socket.recvfrom(2048)
        is_valid, seq_num, data = get_attr(packet_data)
        if is_valid:
            if random.uniform(0, 1) > prob:
                if seq_num == prev_seq_num + 1:
                    ack = struct.pack('!IHH', seq_num, 0, 43690)
                    server_socket.sendto(ack, addr)
                    if data == '!E!O!F!':
                        flag = False
                        print 'File ended at seq No' + str(seq_num)
                        break
                    f.write(data)
                    prev_seq_num = seq_num
            else:
                print 'Packet Lost at sequence Number =' + str(seq_num)
    print 'File transfer successful'
    f.close()
    server_socket.close()

if __name__ == '__main__':
    main()
