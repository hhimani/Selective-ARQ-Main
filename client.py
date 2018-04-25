import sys
import socket
import time
import struct
import threading
import os



COMMAND_LINE_INPUT  = True

N = 1
Retransmit_time = 0.05
N_Transit_Window = {}
Window_Lock = threading.Lock()
Packet_Transferring = True
Last_frame_seq = -1
Data_Packets = []


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

def rdf_send(Server_Address, Client_Socket, File_name, N, MSS):
    global N_Transit_Window
    global Packet_Transferring
    global Last_frame_seq

    sent = 0
    while sent < len(Data_Packets):
        if len(N_Transit_Window) < N:
            Packet_Sender(Server_Address, Client_Socket, sent, Data_Packets[sent])
            sent += 1  # send packet by adding header information


class Packet_Sender(threading.Thread):
    def __init__(self, Server_Address, Client_Socket, Sequence_Number, packet_data):
        threading.Thread.__init__(self)
        self.Server_Address = Server_Address
        self.Client_Socket = Client_Socket
        self.Seq_num = Sequence_Number
        self.data = packet_data
        self.start()


    def run(self):
        global N_Transit_Window
        global Window_Lock
        global Packet_Transferring

        packet = self.data
        Window_Lock.acquire()
        N_Transit_Window[self.Seq_num] = time.time()
        try:
            self.Client_Socket.sendto(packet, self.Server_Address)
            if self.Seq_num == len(Data_Packets) -1:
                Packet_Transferring = False
        except:
            print "Server closed its connection"
            self.Client_Socket.close()
            exit()
        Window_Lock.release()

        try:
            while self.Seq_num in N_Transit_Window:
                Window_Lock.acquire()
                if self.Seq_num in N_Transit_Window:
                    if (time.time() - N_Transit_Window[self.Seq_num]) > Retransmit_time:
                        print 'Time out, Sequence Number =' + str(self.Seq_num)
                        N_Transit_Window[self.Seq_num] = time.time()
                        self.Client_Socket.sendto(packet, self.Server_Address)
                Window_Lock.release()
        except:
            print "Server closed its connection"
            self.Client_Socket.close()
            exit()


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
    global N_Transit_Window
    global Window_Lock
    global Packet_Transferring

    try:
        while Packet_Transferring or len(N_Transit_Window) > 0 :
            if len(N_Transit_Window) > 0:
                Ack_Data, Server_Address = Client_Socket.recvfrom(2048)
                Valid_frame, Sequence_Number = Split_Ack_Header(Ack_Data)
                if Valid_frame:
                    if Sequence_Number in N_Transit_Window:
                        Window_Lock.acquire()
                        del (N_Transit_Window[Sequence_Number])
                        if Sequence_Number+1 == len(Data_Packets):
                            print 'Last Frame Ack Recieved'
                        Window_Lock.release()
    except:
        print "Server closed its connection"
        Client_Socket.close()
        exit()
    print 'Acknowledement thread closing'


def main():

    if COMMAND_LINE_INPUT:
        server_host_name = sys.argv[1]
        server_port = int(sys.argv[2])
        File_name = sys.argv[3]
        N = int(sys.argv[4])
        MSS = int(sys.argv[5])
    else:
        server_host_name = '152.46.18.96'
        server_port = 7736
        File_name = 's.txt'
        N = 10
        MSS = 500

    Make_data_packets(File_name,MSS)
    Server_Address = (server_host_name, server_port)
    my_ip = socket.gethostbyname(socket.gethostname())
    #my_ip = ''
    Client_Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    Client_Port = 1234
    Client_Socket.bind((my_ip, Client_Port))


    startTime = time.time()

    Ack_receiver_thread = threading.Thread(target=Ack_Receiver, args=(Client_Socket,))
    File_packet_sender_thread = threading.Thread(target=rdf_send,args=(Server_Address, Client_Socket, File_name, N, MSS))

    Ack_receiver_thread.start()
    File_packet_sender_thread.start()
    Ack_receiver_thread.join()
    File_packet_sender_thread.join()
    print 'Ending Program'


    endTime = time.time()
    print 'Total Time Taken:' + str(endTime - startTime)

if __name__ == '__main__':
    main()
