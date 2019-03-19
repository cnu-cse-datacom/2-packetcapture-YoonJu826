import socket
import struct

def main():
    recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    print("<<<<<<<< Packet Start >>>>>>>>")    
    while True:
        data = recv_socket.recvfrom(20000)

        #packet string from tuple
        parsing_ethernet_header(data[0][0:14])
        #ethernet function call

        #14 first -> ip part
        protocol_info = parsing_ip_header(data[0][14:34])
        #take first 20 characters for the ip header
        #ip function call
        
        if protocol_info == 6:
            # when 6, tcp
            parsing_tcp_header(data[0][34:54])
            #tcp header part
        
        elif protocol_info == 17:
            # when 17, udp
            parsing_udp_header(data[0][34:42])
            #udp header part
        
def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()
    #6c6c2s 2 char -> 0x + 08 00

    print("========ethernet header========")
    print("src_mac_address: ", ether_src)
    print("dest_mac_address: ", ether_dest)
    print("ip_version: ", ip_header)
    
def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
     ip_header = struct.unpack("!1c 1c 2s 2s 2s 1c 1c 2s 4c 4c", data)
     ip_verlen = ip_header[0].hex()
     ip_ver = int(ip_verlen, 16) >> 4
     ip_header_length = int(ip_verlen, 16) & 0x0f
     ip_service = ip_header[1].hex()
     ip_differentiated_service_codepoint = int(ip_service, 16) >> 2
     ip_explicit_congestion_notification = int(ip_service, 16) >> 11

     ip_total_length = int(ip_header[2].hex(), 16)
     ip_identification = int(ip_header[3].hex(), 16)
    
     ip_flag = "0x"+ip_header[4].hex()
     ip_flags_and_offset = ip_header[4].hex()
     ip_reserved_bit = int(ip_flags_and_offset, 16) >> 15
     ip_not_fragments = int(ip_flags_and_offset, 16) >> 14
     ip_fragments = int(ip_flags_and_offset, 16) >> 13 & 0x1
     #ex) 1110 0000 0000 0000 -> 111 & 0001 --> 1!
     ip_fragments_offset = int(ip_flags_and_offset, 16) & 0x1fff
     
     ip_ttl = int(ip_header[5].hex(), 16)
     ip_protocol = int(ip_header[6].hex(), 16)
     ip_check_sum = "0x"+ip_header[7].hex()
     ip_src = convert_ip_address(ip_header[8:12])
     ip_dst = convert_ip_address(ip_header[12:16])
    
     print("========ip_header========")
     print("ip_version: ", ip_ver)
     print("ip_Length: ", ip_header_length)
     print("differentiated_service_codepoint: ", ip_differentiated_service_codepoint)
     print("explicit_congestion_notification: ", ip_explicit_congestion_notification)
     print("total_length: ", ip_total_length)
     print("identification: ", ip_identification)
     print("flags: ", ip_flag)
     print(">>>reserved_bit: ", ip_reserved_bit)
     print(">>>not_fragments: ", ip_not_fragments)
     print(">>>fragments: ", ip_fragments)
     print(">>>fragments_offset: ", ip_fragments_offset)
     print("Time to live: ", ip_ttl)
     print("protocol: ", ip_protocol)
     print("header_checksum: ", ip_check_sum)
     print("source_ip_address: ", ip_src)
     print("dest_ip_address: ", ip_dst)

     return ip_protocol

def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(str(int(i.hex(), 16)))
    ip_addr = ".".join(ip_addr)
    return ip_addr

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2s 2s 4s 4s 2s 2s 2s 2s", data)
    tcp_src_port = int(tcp_header[0].hex(), 16)
    tcp_dec_port = int(tcp_header[1].hex(), 16)
    tcp_seq_num = int(tcp_header[2].hex(), 16)
    tcp_ack_num = int(tcp_header[3].hex(), 16)
    tcp_header_len = int(tcp_header[4].hex(), 16) &0xf000 
    tcp_len_and_flag = int(tcp_header[4].hex(), 16) &0x0fff
    tcp_reserved = (tcp_len_and_flag >> 9) & 0x1
    tcp_nonce = (tcp_len_and_flag >> 8) & 0x1
    tcp_cwr = (tcp_len_and_flag >> 7) & 0x1
    tcp_ecn = (tcp_len_and_flag >> 6) & 0x1
    tcp_urgent = (tcp_len_and_flag >> 5) & 0x1
    tcp_ack = (tcp_len_and_flag >> 4) & 0x1
    tcp_push = (tcp_len_and_flag >> 3) & 0x1
    tcp_reset = (tcp_len_and_flag >> 2) & 0x1
    tcp_syn = (tcp_len_and_flag >> 1) & 0x1
    tcp_fin = (tcp_len_and_flag) & 0x1
    tcp_window_size_value = int(tcp_header[5].hex(), 16)
    tcp_checksum = int(tcp_header[6].hex(), 16)
    tcp_urgent_pointer = int(tcp_header[7].hex(), 16)

    print("========tcp_header========")
    print("src_port: ", tcp_src_port)
    print("dec_port: ", tcp_dec_port)
    print("seq_num: ", tcp_seq_num)
    print("ack_num: ", tcp_ack_num)
    print("header_len: ", tcp_header_len)
    print("flags: ", tcp_len_and_flag)
    print(">>>reserved: ", tcp_reserved)
    print(">>>nonce: ", tcp_nonce)
    print(">>>cwr: ", tcp_cwr)
    print(">>>ecn: ", tcp_ecn)
    print(">>>urgent: ", tcp_urgent)
    print(">>>ack: ", tcp_ack)
    print(">>>push: ", tcp_push)
    print(">>>reset: ", tcp_reset)
    print(">>>syn: ", tcp_syn)
    print(">>>fin: ", tcp_fin)
    print("window_size_value: ", tcp_window_size_value)
    print("checksum: ", tcp_checksum)
    print("urgent_pointer: ", tcp_urgent_pointer)


def parsing_udp_header(data):
    udp_header = struct.unpack("!2s 2s 2s 2s", data)
    udp_src_port = int(udp_header[0].hex(), 16)
    udp_dst_port = int(udp_header[1].hex(), 16)
    udp_leng = int(udp_header[2].hex(), 16)
    udp_header_checksum = "0x"+udp_header[3].hex()

    print("========udp_header========")
    print("src_port:", udp_src_port)
    print("dst_port:", udp_dst_port)
    print("leng:", udp_leng)
    print("header checksum:", udp_header_checksum)

if __name__ == "__main__":
    main()


