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
import IN
import errno

from pydhcplib.dhcp_packet import DhcpPacket
from pydhcplib.type_ipv4 import ipv4
from pydhcplib.type_hwmac import hwmac


class DhcpAddressRequest(object):
    """Represents the request for an IP address (and additional settings
    relevant for the target network) based on a MAC address.

    To perform the above task, DHCP packets are sent and received.  For each
    packet, the class pretends to be a DHCP relay so that all answers can be
    received and responded to, although the requested IP address is completely
    different from the one that the packets are received on.

    The DHCP requests are targeted at specific DHCP server IP addresses.

    As soon as the request has completed, has failed or has timed out, the
    apropriate call back handler is called.
    """

    AR_DISCOVER = 1
    AR_REQUEST = 2

    def __init__(self, **kwargs):
        """Sets up the address request.

        Creates a new XID.  Each address request has such a unique (randomly
        chosen) identifier.

        @param requestor: Instance of the requestor, where the request is
                tracked and where the listening socket is maintained.
        @param timeout_mgr: Instance of the timeout manager.
        @param success_handler_clb: Call-back that is called as soon as the
                request has succeeded.
        @param failure_handler_clb: Call-back that is called as soon as the
                request has failed or timed out.
        @param local_ip: IP address from which all DHCP requests originate and
                on which the responses are received.  Is used within the DHCP
                packets.
        @param mac_addr: The Ethernet MAC address for which an IP address is
                requested.
        @param server_ips: A list of IP addresses to which the DHCP requests
                should be sent.
        @param max_retries: The maximum number of retries after timeouts.
                Defaults to 2 retries.
        @param timeout: Number of seconds to wait for a DHCP response before
                timing out and/or retrying the request.  Defaults to 5 seconds.
        """
        self._requestor = kwargs["requestor"]
        self._timeout_mgr = kwargs["timeout_mgr"]
        self._success_handler = kwargs["success_handler_clb"]
        self._failure_handler = kwargs["failure_handler_clb"]
        self._local_ip = ipv4(kwargs["local_ip"])
        self._mac_addr = hwmac(kwargs["mac_addr"])
        self._server_ips = kwargs["server_ips"]
        self._max_retries = kwargs.get("max_retries", 2)
        self._timeout = kwargs.get("timeout", 5)

        self.log = logging.getLogger('dhcpaddrreq')

        self._xid = ipv4([random.randint(0, 255) for i in range(4)])

        # When will the packet time out?
        self._timeout_time = None
        # What was the contents of the last packet?  (Used for retry.)
        self._last_packet = None

        self._state = self.AR_DISCOVER

        self.log.debug('xid %d created' % self.xid)
        self._requestor.add_request(self)
        self._send_packet(self._generate_discover())

    def __del__(self):
        self.log.debug('xid %d destroyed' % self.xid)

    @property
    def xid(self):
        """@return: Returns the unique identifier of the DHCP request.
        """
        return self._xid.int()

    def _generate_discover(self):
        """Generates a DHCP DISCOVER packet.
        """
        packet = DhcpPacket()
        packet.AddLine("op: BOOTREQUEST")
        packet.AddLine("htype: 1")
        packet.AddLine("hlen: 6")
        packet.AddLine("hops: 1")
        packet.SetOption("xid", self._xid.list())
        packet.AddLine("parameter_request_list: subnet_mask,router,domain_name_server,domain_name")
        packet.AddLine("dhcp_message_type: DHCP_DISCOVER")

        # We're the gateway.
        packet.SetOption("giaddr", self._local_ip.list())

        # Request IP address, etc. for the following MAC address.
        packet.SetOption("chaddr", self._mac_addr.list() + 10*[0])

        return packet

    def _generate_request(self, offer_packet):
        """Generates a DHCP REQUEST packet.
        """
        packet = DhcpPacket()
        packet.AddLine("op: BOOTREQUEST")
        packet.AddLine("dhcp_message_type: DHCP_REQUEST")
        for opt in ["htype", "hlen", "xid", "flags", "yiaddr", "siaddr",
                "giaddr", "chaddr", "server_identifier"]:
            packet.SetOption(opt, offer_packet.GetOption(opt))
        packet.SetOption("request_ip_address", offer_packet.GetOption("yiaddr"))
        return packet

    def _retrieve_server_ip(self, packet):
        """In case we're sending the requests to more than one DHCP server,
        attempt to determine which DHCP server answered, so that we can restrict
        our future requests to only one server.
        """
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
        """Method to initially send a packet.
        """
        self._last_packet = packet
        self._packet_retries = 0
        self._send_to_server(packet)

    def _resend_packet(self):
        """Method to re-send the packet that was sent last.
        """
        self._packet_retries += 1
        self._send_to_server(self._last_packet)

    def _send_to_server(self, packet):
        """Method that does the actual packet sending.  The packet is sent once
        for each DHCP server destination.
        """
        self._timeout_time = time.time() + self._timeout
        self._timeout_mgr.add_timeout_object(self)
        for server_ip in self._server_ips:
            self.log.debug("Sending packet in state %d to %s [%d/%d]" % (
                    self._state, str(server_ip), self._packet_retries + 1,
                    self._max_retries + 1))
            self._requestor.send_packet(packet, str(server_ip), 67)

    def handle_dhcp_offer(self, offer_packet):
        """Called by the requestor as soon as a DHCP OFFER packet is received
        for our XID.

        In case the packet matches what we currently expect, the packet is
        parsed and a matching DHCP REQUEST packet is generated.
        """
        if self._state != self.AR_DISCOVER:
            return
        self.log.debug("Received offer")
        self._timeout_mgr.del_timeout_object(self)
        req_packet = self._generate_request(offer_packet)
        self._retrieve_server_ip(req_packet)
        self._state = self.AR_REQUEST
        self._send_packet(req_packet)

    def handle_dhcp_ack(self, packet):
        """Called by the requestor as soon as a DHCP ACK packet is received for
        our XID.

        In case the packet matches what we currently expect, the packet is
        parsed and the success handler called.

        The request instance (self) is removed from the requestor and will
        therefore be destroyed soon.
        """
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
        """Called by the requestor as soon as a DHCP NACK packet is received for
        our XID.

        In case the packet matches what we currently expect, the failure handler
        is called.

        The request instance (self) is removed from the requestor and will
        therefore be destroyed soon.
        """
        if self._state != self.AR_REQUEST:
            return
        self.log.debug("Received NACK")
        self._timeout_mgr.del_timeout_object(self)
        self._requestor.del_request(self)
        self._failure_handler()

    @property
    def timeout_time(self):
        """\
        @return: Point in time (in seconds since the UNIX epoch) of the
                timeout of the last packet that was sent.
        """
        return self._timeout_time

    def handle_timeout(self):
        """Called in case the timeout_time has passed without a proper DHCP
        response.  Handles resend attempts up to a certain maximum number of
        retries.

        In case the maximum number of retries have been attempted, the failure
        handler is called.  Additionally, the request instance (self) is removed
        from the requestor and will therefore be destroyed soon.
        """
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


class DhcpAddressRequestor(object):
    """A DhcpAddressRequestor instance represents a UDP socket listening for
    DHCP responses on a specific IP address and port on a specific network
    device.

    Specific requests are added to a requestor instance and use the requestor
    to send DHCP requests.  The requestor maps DHCP responses back to a specific
    request via the request's XID.

    Provides attribute listen_device, listen_address and add_request method for
    use by the requestor manager.

    Provides socket and handle_socket for use by the socket loop.
    """

    # Maps dhcp_message_type to a request's message type handler.
    _DHCP_TYPE_HANDLERS = {
        2:'handle_dhcp_offer',
        5:'handle_dhcp_ack',
        6:'handle_dhcp_nack',
    }

    def __init__(self, listen_address='', listen_port=67, listen_device=None):
        """\
        @param listen_address: IP address as string to listen on.
        @param listen_port: Local DHCP listening port. Defaults to 67.
        @param listen_device: Device name to bind to.
        """
        self.listen_address = listen_address
        self.listen_device = listen_device
        self.listen_port = listen_port

        self.log = logging.getLogger('dhcpaddrrequestor')
        self._requests = {}

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.listen_device is not None:
            self._socket.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE,
                    self.listen_device + '\0')

        try :
            self._socket.bind((self.listen_address, self.listen_port))
        except socket.error, msg:
            err = msg.args[0]
            if err == errno.EADDRNOTAVAIL:
                raise DhcpLocalAddressNotAvailable(
                        self.listen_address, self.listen_port,
                        self.listen_device)
            else:
                raise DhcpLocalAddressBindFailed(
                        self.listen_address, self.listen_port,
                        self.listen_device, msg)

        self.log.debug('listening on %s:%d@%s for DHCP responses' % (
                self.listen_address, self.listen_port, self.listen_device))

    def add_request(self, request):
        """Adds a new DHCP address request to this requestor.

        @param request: The request that should be added.
        """
        self.log.debug("adding xid %d" % request.xid)
        self._requests[request.xid] = request

    def del_request(self, request):
        """Removes a DHCP address request that was previously added.

        @param request: The request that should be removed.
        """
        self.log.debug("deleting xid %d" % request.xid)
        del self._requests[request.xid]


    @property
    def socket(self):
        """@return: Returns the listening socket.
        """
        return self._socket

    def handle_socket(self):
        """Retrieves the next, waiting DHCP packet, parses it and calls the
        handler of the associated request.
        """
        data, source_address = self._socket.recvfrom(2048)
        if len(data) == 0:
            self.log.warning("unexpectedly received EOF!")
            return
        packet = DhcpPacket()
        packet.source_address = source_address
        packet.DecodePacket(data)

        if (not packet.IsDhcpPacket()) or \
                (not packet.IsOption("dhcp_message_type")):
            self.log.debug("Ignoring invalid packet")
            return

        dhcp_type = packet.GetOption("dhcp_message_type")[0]
        if dhcp_type not in self._DHCP_TYPE_HANDLERS:
            self.log.debug("Ignoring packet of unexpected DHCP type %d" % \
                    dhcp_type)
            return
                        
        xid = ipv4(packet.GetOption('xid'))
        if xid.int() not in self._requests:
            self.log.debug("Ignoring answer with xid %s" % repr(xid.int()))
            return

        request = self._requests[xid.int()]
        clb_name = self._DHCP_TYPE_HANDLERS[dhcp_type]
        if not hasattr(request, clb_name):
            self.log.error("request has no callback '%s'" % clb_name)
            return

        clb = getattr(request, clb_name)
        clb(packet)

    def send_packet(self, packet, dest_ip, dest_port):
        data = packet.EncodePacket()
        self._socket.sendto(data, (dest_ip, dest_port))


class DhcpAddressRequestorManager(object):
    """Provides a simple mechanism for initiating a DHCP address request.  The
    new request is associated with the requestor that has a matching originating
    IP address.

    For this purpose it holds a list of all available requestors.
    """
    def __init__(self, request_factory):
        """@param request_factory: Factory method that will construct the
                specific address request.
        """
        self._requestors_by_device_and_ip = {}
        self._request_factory = request_factory
        self.log = logging.getLogger('dhcpaddrrequestormgr')

    def add_requestor(self, requestor):
        """@param requestor: Instance of a requestor that should be added to
                the list of known requestors.
        """
        listen_pair = (requestor.listen_device, requestor.listen_address)
        if listen_pair in self._requestors_by_device_and_ip:
            self.log.error('attempt to listen on IP %s@%s multiple times' % (
                    requestor.listen_address, requestor.listen_device))
            return
        self._requestors_by_device_and_ip[listen_pair] = requestor

    def add_request(self, device, local_ip, **kwargs):
        """Constructs and adds a new DHCP address request.  Uses the local_ip
        to select a matching requestor.  Uses the request factory method to
        create the actual request.

	@param device: Network device name from where the request should
                originate.
        @param local_ip: IP address where the request should originate from.
        @param **kwargs: Additional keyword arguments needed by the request
                factory method.
        """
        listen_pair = (device, local_ip)
        if listen_pair not in self._requestors_by_device_and_ip:
            self.log.error('request for unsupported local IP %s@%s' % (local_ip,
                    device))
            return
        requestor = self._requestors_by_device_and_ip[listen_pair]
        request = self._request_factory(requestor=weakref.proxy(requestor),
                local_ip=local_ip, **kwargs)
        requestor.add_request(request)

