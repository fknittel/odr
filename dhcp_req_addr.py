#!/usr/bin/python
# Copyright (C) 2010 Fabian Knittel <fabian.knittel@avona.com>
# Released under the GNU GPLv3 or later

from pydhcplib.dhcp_packet import DhcpPacket
from pydhcplib.dhcp_network import DhcpClient
from pydhcplib.type_strlist import strlist
from pydhcplib.type_ipv4 import ipv4
from pydhcplib.type_hwmac import hwmac
import random
import sys
import copy

def print_packet(packet):
    # This avoids destroying the packet by a buggy display method.
    p = copy.deepcopy(packet)
    print 'parameter_request_list: %s' % p.GetOption("parameter_request_list")
    print 'server_identifier: %s' % p.GetOption("server_identifier")
    print 'xid: %s' % repr(p.GetOption("xid"))
    #print p.str()

class AddressRequestor(DhcpClient):
    BROADCAST_IP = ipv4([255,255,255,255])
    AR_INIT = 1
    AR_DISCOVER = 2
    AR_REQUEST = 3
    AR_DONE = 4

    def __init__(self, **kwargs):
	"""The 'local_ip' is a valid IP address owned by the requestor in the
        network in which a new IP address is to be allocated.  The network
        must provide a DHCP server.
        The new IP address will be requested for 'mac_addr'.
        """
        self.__local_ip = kwargs["local_ip"]
        DhcpClient.__init__(self, str(self.__local_ip), 67, 67)
        #DhcpClient.__init__(self, "255.255.255.255", 67, 67)
        self.__mac_addr = kwargs["mac_addr"]
        if "server_ips" in kwargs:
            self.__server_ips = kwargs["server_ips"]
        else:
            self.__server_ips = [self.BROADCAST_IP]
        self.__xid = [random.randint(0, 255) for i in range(4)]
        self.__state = self.AR_INIT
        self.BindToAddress()

    def start_request(self):
        disc_packet = self.generate_discover()
        self.send_to_server(disc_packet)
        self.__state = self.AR_DISCOVER

        self.__waiting = True
        self.__result = None
        while self.__waiting:
            print "Waiting for next packet ..."
            self.GetNextDhcpPacket()
        return self.__result
        
    def generate_discover(self):
        packet = DhcpPacket()
        packet.AddLine("op: BOOTREQUEST")
        packet.AddLine("htype: 1")
        packet.AddLine("hlen: 6")
        packet.AddLine("hops: 1")
        packet.SetOption("xid", self.__xid)
        packet.AddLine("parameter_request_list: subnet_mask,router,domain_name_server,domain_name")
        packet.AddLine("dhcp_message_type: DHCP_DISCOVER")

        ## Set broadcast flag. (RFC 1531, p.10)
        #packet.SetOption("flags", [128, 0])

        # We're the gateway.
        packet.SetOption("giaddr", self.__local_ip.list())

        # Request IP address, etc. for the following MAC address.
        packet.SetOption("chaddr", self.__mac_addr.list() + 10*[0])

        return packet

    def generate_request(self, offer_packet):
        packet = DhcpPacket()
        packet.AddLine("op: BOOTREQUEST")
        packet.AddLine("dhcp_message_type: DHCP_REQUEST")
        for opt in ["htype", "hlen", "xid", "flags", "yiaddr", "siaddr",
                "giaddr", "chaddr", "server_identifier"]:
            packet.SetOption(opt, offer_packet.GetOption(opt))
        packet.SetOption("request_ip_address", offer_packet.GetOption("yiaddr"))
        return packet

    def send_to_server(self, packet):
        for server_ip in self.__server_ips:
            print "Sending packet to %s ..." % str(server_ip)
            self.SendDhcpPacketTo(packet, str(server_ip), 67)

    def is_our_xid(self, packet):
        # return packet.GetOption('xid') == self.__xid:
        if packet.GetOption('xid') == self.__xid:
            return True
        else:
            print "Ignoring answer with xid %s" % repr(packet.GetOption('xid'))
            return False

    def retrieve_server_ip(self, packet):
        if self.BROADCAST_IP in self.__server_ips or len(self.__server_ips) > 1:
            print "Attempting to find server ip ..."
            try:
                self.__server_ips = [ipv4(packet.GetOption(
                        'server_identifier'))]
            except:
                pass
    def HandleDhcpOffer(self, offer_packet):
        if not self.is_our_xid(offer_packet) or \
                self.__state != self.AR_DISCOVER:
            return
        print "Received offer:"
        req_packet = self.generate_request(offer_packet)
        self.retrieve_server_ip(req_packet)
        self.__state = self.AR_REQUEST
        self.send_to_server(req_packet)

    def HandleDhcpAck(self, packet):
        if not self.is_our_xid(packet) or \
                self.__state != self.AR_REQUEST:
            return
        self.__state = self.AR_DONE
        self.__waiting = False
        self.__result = {}
        self.__result['domain'] = ''.join(map(chr,
                packet.GetOption('domain_name')))

        translate_ips = {
                'yiaddr':'ip-address',
                'subnet_mask':'subnet-mask',
                'router':'gateway',
            }
        for opt_name in translate_ips:
            val = packet.GetOption(opt_name)
            if len(val) == 4:
                self.__result[translate_ips[opt_name]] = str(ipv4(val)),

        dns = []
        self.__result['dns'] = dns
        dns_list = packet.GetOption('domain_name_server')
        while len(dns_list) >= 4:
            dns.append(str(ipv4(dns_list[:4])))
            dns_list = dns_list[4:]

    def HandleDhcpNack(self, packet):
        if not self.is_our_xid(packet):
            return
        self.__waiting = False

def random_mac():
  return "52:54:00:fb:%02x:%02x" % (random.randint(0,255), random.randint(0,255))

while True:
    #mac = random_mac()
    mac = "52:54:00:fb:38:8b"
    print "Requesting for %s ..." % mac
    client = AddressRequestor(mac_addr=hwmac(mac),
            local_ip=ipv4("192.168.102.5"), server_ips=[ipv4("192.168.101.2")])
    result = client.start_request()
    if not result:
        print "FAILED"
    else:
        print result
    break

