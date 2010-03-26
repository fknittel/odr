#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sw=4 et:

# dhcprequestor.py -- Requests an IP address on behalf of a given MAC address.
#
# Copyright (C) 2010 Fabian Knittel <fabian.knittel@avona.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pydhcplib.dhcp_packet import DhcpPacket
from pydhcplib.dhcp_network import DhcpClient
from pydhcplib.type_strlist import strlist
from pydhcplib.type_ipv4 import ipv4
from pydhcplib.type_hwmac import hwmac
import random

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
        self.__mac_addr = kwargs["mac_addr"]
        if "server_ips" in kwargs and kwargs["server_ips"] is not None:
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

def request_ip(mac_addr, local_ip, server_ips=None):
    if server_ips is not None:
        server_ips = [ipv4(addr) for addr in server_ips]
    client = AddressRequestor(mac_addr=hwmac(mac_addr),
            local_ip=ipv4(local_ip),
            server_ips=server_ips)
    result = client.start_request()
    return result
