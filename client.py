import sys
import socket
import time
import struct
import threading
import os

COMMAND_LINE_INPUT  = True

N = 10
Window_Lock = threading.Lock()
Retransmit_time = 0.05
Data_Packets = []
Time_Stamp =[]
Last_Ack = -1
In_Transit = 0


def Calculate_CheckSum(data):
    sum_element = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            element_16bits = ord(data[i]) + (ord(data[i + 1]) << 8)
            k = sum_element + element_16bits
            a = (k & 0xffff)
            b = k >> 16
            sum_element = a + b  # carry around addition
    return ~sum_element & 0xffff


def Create_packet(present_sequence,packet_data):
    check_sum = Calculate_CheckSum(packet_data)
    header = struct.pack('!IHH',present_sequence, check_sum, 21845)
    packet = header + packet_data
    return packet

def Make_data_packets(File_name,MSS):
    global Data_Packets

    if os.path.isfile(File_name):

        packet_data = ''
        present_sequence = 0

        file_reader = open(File_name, 'rb')
        read_onebyte = file_reader.read(1)
        packet_data += read_onebyte

        while packet_data != '':
            if len(packet_data) == MSS or read_onebyte == '':
                Data_Packets.append(Create_packet(present_sequence,packet_data)) # send packet by adding header information
                packet_data = ''
                present_sequence += 1
            read_onebyte = file_reader.read(1)
            packet_data += read_onebyte

        packet_data = 'endofframe'
        Data_Packets.append(Create_packet(present_sequence, packet_data))
        file_reader.close()
    else:
        print 'File dosenot exist in the given location. Please Check \n'
        sys.exit()


def rdf_send(Server_Address, Client_Socket, N):
    print 'rdf_send thread started'
    global Data_Packets
    global Last_Ack
    global In_Transit
    global Time_Stamp

    Time_Stamp = [None]*len(Data_Packets)
    while (Last_Ack + 1) < len(Data_Packets):
        Window_Lock.acquire()
        if In_Transit < N and ((Last_Ack + In_Transit + 1) < len(Data_Packets)):            #Send More Packets
            Client_Socket.sendto(Data_Packets[Last_Ack + In_Transit + 1], Server_Address)
            Time_Stamp[Last_Ack + In_Transit + 1] = time.time()
            In_Transit += 1
        if In_Transit > 0:
            if (time.time() - Time_Stamp[Last_Ack + 1]) > Retransmit_time:
                print 'Time out, Sequence Number =' + str(Last_Ack+1)
                In_Transit = 0
        Window_Lock.release()



def Split_Ack_Header(Ack_Data):
    Ack = struct.unpack('!IHH', Ack_Data)
    seq_num = Ack[0]
    if Ack[1] == 0 and Ack[2] == 43690:
        valid_ack = True
    else:
        print 'Invalid Frame as Header Format dosent match'
        valid_ack = False
    return valid_ack, seq_num


def Ack_Receiver(Client_Socket):
    print "Client Thread to Receive Acknowledgements Started \n"
    global Last_Ack
    global In_Transit
    global Time_Stamp
    global Data_Packets

    try:
        while (Last_Ack + 1) < len(Data_Packets):
            if In_Transit > 0:
                Ack_Data, Server_Address = Client_Socket.recvfrom(2048)
                Valid_frame, Sequence_Number = Split_Ack_Header(Ack_Data)
                Window_Lock.acquire()
                if Valid_frame:
                    if Last_Ack+1 == Sequence_Number:
                        Last_Ack += 1
                        In_Transit -= 1
                    else:
                        In_Transit = 0
                else:
                    In_Transit = 0

                Window_Lock.release()

    except:
        print "Server closed its connection"
        Client_Socket.close()
        sys.exit()


def main():

    if COMMAND_LINE_INPUT:
        server_host_name = sys.argv[1]
        server_port = int(sys.argv[2])
        File_name = sys.argv[3]
        N = int(sys.argv[4])
        MSS = int(sys.argv[5])
    else:
        server_host_name = '192.168.179.1'
        server_port = 7735
        File_name = 's.txt'
        N = 10
        MSS = 500

    Server_Address = (server_host_name, server_port)
    #my_ip = socket.gethostbyname(socket.gethostname())
    Client_Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    Client_Port = 1234
    Client_Socket.bind(( '0.0.0.0' , Client_Port))
    print 'running at port' + str(Client_Port) + 'and server ip addr is ' +str(Server_Address)
    Make_data_packets(File_name,MSS)

    startTime = time.time()

    Ack_receiver_thread = threading.Thread(target=Ack_Receiver, args=(Client_Socket,))
    rdf_send_thread = threading.Thread(target=rdf_send,args=(Server_Address, Client_Socket, N))

    Ack_receiver_thread.start()
    rdf_send_thread.start()

    Ack_receiver_thread.join()
    rdf_send_thread.join()
    print 'Ending Program'

    endTime = time.time()
    print 'Total Time Taken:' + str(endTime - startTime)

    if Client_Socket:
        Client_Socket.close()

if __name__ == '__main__':
    main()