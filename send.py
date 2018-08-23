#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField
from scapy.layers.inet import _IPOption_HDR
from detnetInd_header import MyDetnet
from myTunnel_header import MyTunnel
from time import sleep

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                  IntField("qdepth", 0)]
    def extract_padding(self, p):
                return "", p

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('message', type=str, help="The message to include in packet")
    parser.add_argument('--detnet_identifire', type=int, default=None, help='If unspecified do not include any detnet header otherwise, send with the detnet itentifire')
    parser.add_argument('count', type=int, help="Number of packets need to be sent")
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    detnet_identifire = args.detnet_identifire
    iface = get_if()

    if (detnet_identifire is not None):
        print "sending the packets with detnet header".format(iface, str(detnet_identifire))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / MyDetnet(detnet_identifire=detnet_identifire) / IP(dst=addr, options = IPOption_MRI(count=0, swtraces=[])) / UDP(dport=4321, sport=1234) / args.message
    else:
        print "sending on interface {} to IP addr {}".format(iface, str(addr))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr, options = IPOption_MRI(count=0, swtraces=[])) / UDP(dport=4321, sport=1234) / args.message

    pkt.show2()
#    hexdump(pkt)
#    print "len(pkt) = ", len(pkt)
    try:
      for i in range(args.count):
        sendp(pkt, iface=iface)
        sleep(1)
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()
ptions = IPOption_MRI(count=0,
            swtraces=[])
