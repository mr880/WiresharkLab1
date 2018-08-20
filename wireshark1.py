# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets),
#2) list distinct source IP addresses and number of packets for each IP address, in descending order
#3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order

import dpkt
import socket
import argparse
import operator
import sys

from collections import OrderedDict

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code
def main():
    number_of_packets = 0             # you can use these structures if you wish
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing
    input_data=dpkt.pcap.Reader(open(filename,'r'))

    # this main loop reads the packets one at a time from the pcap file
    for timestamp, packet in input_data:

        number_of_packets = number_of_packets + 1
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        tcp = ip.data


        if not isinstance(eth.data, dpkt.ip.IP):
            continue


        if inet_to_str(ip.src) not in list_of_ips:
            list_of_ips[inet_to_str(ip.src)] = 1
        else:
            list_of_ips[inet_to_str(ip.src)] += 1


        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            if tcp.dport not in list_of_tcp_ports:
                list_of_tcp_ports[tcp.dport] = 1
            else:
                list_of_tcp_ports[tcp.dport] += 1


            if '%s:%s' % \
                (inet_to_str(ip.src), tcp.dport) not in list_of_ip_tcp_ports:
                list_of_ip_tcp_ports['%s:%s' % \
                    (inet_to_str(ip.src), tcp.dport)] = 1
            else:
                list_of_ip_tcp_ports['%s:%s' % \
                    (inet_to_str(ip.src), tcp.dport)] += 1

    sys.stdout.write("Total number of packets, %s\n" % number_of_packets)
    sys.stdout.write("Source IP addresse, count\n")
    for key, value in sorted(list_of_ips.iteritems(), key=lambda (k,v): (v,k), reverse = True):
        print "%s: %s" % (key, value)
    sys.stdout.write("Destination TCP ports,count\n")
    for key, value in sorted(list_of_tcp_ports.iteritems(), key=lambda (k,v): (v,k), reverse = True):
        print "%s: %s" % (key, value)
    sys.stdout.write("Source IPs/Destination TCP ports,count\n")
    for key, value in sorted(list_of_ip_tcp_ports.iteritems(), key=lambda (k,v): (v,k), reverse = True):
        print "%s: %s" % (key, value)

    # print list_of_ips
    # print list_of_tcp_ports
    # print list_of_ip_tcp_ports



# execute a main function in Python
if __name__ == "__main__":
    main()
