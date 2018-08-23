from scapy.all import *
import sys, os

TYPE_DETNET = 0x9999
TYPE_IPV4 = 0x0800

class MyDetnet(Packet):
    name = "MyDetnet"
    fields_desc = [
        ShortField("pid", 0),
        ShortField("detnet_identifire", 0)
    ]
    def mysummary(self):
        return self.sprintf("pid=%pid%, detnet_identifire=%detnet_identifire%")


bind_layers(Ether, MyDetnet, type=TYPE_DETNET)
bind_layers(MyDetnet, IP, pid=TYPE_IPV4)
