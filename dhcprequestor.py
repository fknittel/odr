#!/usr/bin/python
# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# dhcprequestor.py -- Requests an IP address on behalf of a given MAC address.
#
# Copyright © 2010 Fabian Knittel <fabian.knittel@avona.com>
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

import random
import weakref
import time
import logging
import socket
import errno

from pydhcplib.dhcp_packet import DhcpPacket
from pydhcplib.dhcp_network import DhcpClient
from pydhcplib.type_ipv4 import ipv4
from pydhcplib.type_hwmac import hwmac


class DhcpAddressRequest(object):
    AR_DISCOVER = 1
    AR_REQUEST = 2

    def __init__(self, **kwargs):
        self._requestor = kwargs["requestor"]
        self._timeout_mgr = kwargs["timeout_mgr"]
        self._success_handler = kwargs["success_handler_clb"]
        self._failure_handler = kwargs["failure_handler_clb"]
        self._local_ip = ipv4(kwargs["local_ip"])
        self._local_port = kwargs.get("local_port", 67)
        self._mac_addr = hwmac(kwargs["mac_addr"])
        self._server_ips = kwargs["server_ips"]
        self._max_retries = kwargs.get("max_retries", 2)
        self._timeout = kwargs.get("timeout", 5)

        self.log = logging.getLogger('dhcpaddrreq')

        self._xid = ipv4([random.randint(0, 255) for i in range(4)])

        # Packet resending and timeout.
        self._timeout_time = None
        self._last_packet = None

        self._state = self.AR_DISCOVER

        self.log.debug('xid %d created' % self.xid)
        self._requestor.add_request(self)
        self._send_packet(self._generate_discover())

    def __del__(self):
        self.log.debug('xid %d destroyed' % self.xid)

    @property
    def xid(self):
        return self._xid.int()

    def _generate_discover(self):
        packet = DhcpPacket()
        packet.AddLine("op: BOOTREQUEST")
        packet.AddLine("htype: 1")
        packet.AddLine("hlen: 6")
        packet.AddLine("hops: 1")
        packet.SetOption("xid", self._xid.list())
        packet.AddLine("parameter_request_list: subnet_mask,router,domain_name_server,domain_name")
        packet.AddLine("dhcp_message_type: DHCP_DISCOVER")

        ## Set broadcast flag. (RFC 1531, p.10)
        #packet.SetOption("flags", [128, 0])

        # We're the gateway.
        packet.SetOption("giaddr", self._local_ip.list())

        # Request IP address, etc. for the following MAC address.
        packet.SetOption("chaddr", self._mac_addr.list() + 10*[0])

        return packet

    def _generate_request(self, offer_packet):
        packet = DhcpPacket()
        packet.AddLine("op: BOOTREQUEST")
        packet.AddLine("dhcp_message_type: DHCP_REQUEST")
        for opt in ["htype", "hlen", "xid", "flags", "yiaddr", "siaddr",
                "giaddr", "chaddr", "server_identifier"]:
            packet.SetOption(opt, offer_packet.GetOption(opt))
        packet.SetOption("request_ip_address", offer_packet.GetOption("yiaddr"))
        return packet

    def _retrieve_server_ip(self, packet):
        if len(self._server_ips) > 1:
            self.log.debug("Attempting to find server ip")
            try:
                self._server_ips = [ipv4(packet.GetOption(
                        'server_identifier'))]
            except:
                pass
            else:
                self.log.debug("Found server ip %s" % self._server_ips.str())

    def _send_packet(self, packet):
        self._last_packet = packet
        self._packet_retries = 0
        self._send_to_server(packet)

    def _resend_packet(self):
        self._packet_retries += 1
        self._send_to_server(self._last_packet)

    def _send_to_server(self, packet):
        self._timeout_time = time.time() + self._timeout
        self._timeout_mgr.add_timeout_object(self)
        for server_ip in self._server_ips:
            self.log.debug("Sending packet in state %d to %s [%d/%d]" % (
                    self._state, str(server_ip), self._packet_retries + 1,
                    self._max_retries + 1))
            self._requestor.SendDhcpPacketTo(packet, str(server_ip), 67)

    def handle_dhcp_offer(self, offer_packet):
        if self._state != self.AR_DISCOVER:
            return
        self.log.debug("Received offer")
        self._timeout_mgr.del_timeout_object(self)
        req_packet = self._generate_request(offer_packet)
        self._retrieve_server_ip(req_packet)
        self._state = self.AR_REQUEST
        self._send_packet(req_packet)

    def handle_dhcp_ack(self, packet):
        if self._state != self.AR_REQUEST:
            return
        self.log.debug("Received ACK")
        self._timeout_mgr.del_timeout_object(self)
        self._requestor.del_request(self)
        result = {}
        result['domain'] = ''.join(map(chr,
                packet.GetOption('domain_name')))

        translate_ips = {
                'yiaddr':'ip-address',
                'subnet_mask':'subnet-mask',
                'router':'gateway',
            }
        for opt_name in translate_ips:
            val = packet.GetOption(opt_name)
            if len(val) == 4:
                result[translate_ips[opt_name]] = str(ipv4(val))

        dns = []
        result['dns'] = dns
        dns_list = packet.GetOption('domain_name_server')
        while len(dns_list) >= 4:
            dns.append(str(ipv4(dns_list[:4])))
            dns_list = dns_list[4:]

        self._success_handler(result)

    def handle_dhcp_nack(self, packet):
        self._timeout_mgr.del_timeout_object(self)
        self._requestor.del_request(self)
        self._failure_handler()

    @property
    def timeout_time(self):
        return self._timeout_time

    def handle_timeout(self):
        self.log.debug("handling timeout for %d" % self.xid)
        if self._packet_retries >= self._max_retries:
            self._requestor.del_request(self)
            self.log.debug("Timeout for reply to packet in state %d" % \
                    self._state)
            self._failure_handler()
        elif self._last_packet is not None:
            self._resend_packet()


class DhcpLocalAddressBindFailed(Exception):
    """For some reason, the requested local address / port combination could not
    be bound to.
    """

class DhcpLocalAddressNotAvailable(DhcpLocalAddressBindFailed):
    """The requested local address / port combination was not available.
    """


class DhcpAddressRequestor(DhcpClient):
    def __init__(self, **kwargs):
        DhcpClient.__init__(self, kwargs["listen_address"],
                kwargs.get("listen_port", 67), 67)

        self.log = logging.getLogger('dhcpaddrrequestor')
        self.__requests = {}

        try :
            self.dhcp_socket.bind((self.listen_address, self.listen_port))
        except socket.error, msg:
            err = msg.args[0]
            if err == errno.EADDRNOTAVAIL:
                raise DhcpLocalAddressNotAvailable(
                        self.listen_address, self.listen_port)
            else:
                raise DhcpLocalAddressBindFailed(
                        self.listen_address, self.listen_port, msg)

        self.log.debug('listening on %s:%d for DHCP responses' % (
                self.listen_address, self.listen_port))

    def add_request(self, request):
        self.log.debug("adding xid %d" % request.xid)
        self.__requests[request.xid] = request

    def del_request(self, request):
        self.log.debug("deleting xid %d" % request.xid)
        del self.__requests[request.xid]

    def check_timeouts(self):
        t = time.time()
        for request in self.__requests.values()[:]:
            if t > request.timeout_time:
                request.handle_timeout()

    def _handle_packet(self, clb_name, packet):
        xid = ipv4(packet.GetOption('xid'))
        if xid.int() not in self.__requests:
            self.log.debug("Ignoring answer with xid %s" % repr(xid.int()))
            return

        request = self.__requests[xid.int()]
        clb = getattr(request, clb_name)
        clb(packet)

    def HandleDhcpOffer(self, packet):
        self._handle_packet('handle_dhcp_offer', packet)

    def HandleDhcpAck(self, packet):
        self._handle_packet('handle_dhcp_ack', packet)

    def HandleDhcpNack(self, packet):
        self._handle_packet('handle_dhcp_nack', packet)

    @property
    def socket(self):
        return self.dhcp_socket

    def handle_socket(self):
        self.GetNextDhcpPacket(timeout = 0)

class DhcpAddressRequestorManager(object):
    def __init__(self, request_factory):
        self._requestors_by_ip = {}
        self._request_factory = request_factory
        self.log = logging.getLogger('dhcpaddrrequestormgr')

    def add_requestor(self, requestor):
        if requestor.listen_address in self._requestors_by_ip:
            self.log.error('attempt to listen on IP %s multiple times' % \
                    requestor.listen_address)
            return
        self._requestors_by_ip[requestor.listen_address] = requestor

    def add_request(self, local_ip, **kwargs):
        if not local_ip in self._requestors_by_ip:
            self.log.error('request for unsupported local IP %s' % local_ip)
            return
        requestor = self._requestors_by_ip[local_ip]
        request = self._request_factory(requestor=weakref.proxy(requestor),
                local_ip=local_ip, **kwargs)
        requestor.add_request(request)

