#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sts=4 sw=4 et:

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
import socket
import select
import weakref
import machasher
import re

class DhcpAddressRequest(object):
    AR_DISCOVER = 1
    AR_REQUEST = 2

    def __init__(self, **kwargs):
        self._requestor = kwargs["requestor"]
        self._success_handler_clb = kwargs["success_handler_clb"]
        self._failure_handler_clb = kwargs["failure_handler_clb"]
        self._local_ip = kwargs["local_ip"]
        self._local_port = kwargs.get("local_port", 67)
        self._mac_addr = kwargs["mac_addr"]
        self._server_ips = kwargs["server_ips"]
        self._max_retries = kwargs.get("max_retries", 2)
        self._timeout = kwargs.get("timeout", 5)

        self._xid = [random.randint(0, 255) for i in range(4)]

        # Packet resending and timeout.
        self._timeout_time = None
        self._last_packet = None

        self._state = self.AR_DISCOVER
        self._send_packet(self._generate_discover())
        self._requestor.add_request(self)

    @property
    def xid(self):
        return self._xid

    @property
    def timeout_time(self):
        return self._timeout_time

    def _generate_discover(self):
        packet = DhcpPacket()
        packet.AddLine("op: BOOTREQUEST")
        packet.AddLine("htype: 1")
        packet.AddLine("hlen: 6")
        packet.AddLine("hops: 1")
        packet.SetOption("xid", self._xid)
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
            print "Attempting to find server ip ..."
            try:
                self._server_ips = [ipv4(packet.GetOption(
                        'server_identifier'))]
            except:
                pass

    def _send_packet(self, packet):
        self._last_packet = packet
        self._packet_retries = 0
        self._send_to_server(packet)

    def _resend_packet(self):
        self._packet_retries += 1
        self._send_to_server(self._last_packet)

    def _send_to_server(self, packet):
        self._timeout_time = time.time() + self._timeout
        for server_ip in self._server_ips:
            print "Sending packet in state %d to %s ... [%d/%d]" % (
                    self._state, str(server_ip), self._packet_retries + 1,
                    self._max_retries + 1)
            self._requestor.SendDhcpPacketTo(packet, str(server_ip), 67)

    def handle_dhcp_offer(self, offer_packet):
        if self._state != self.AR_DISCOVER:
            return
        print "Received offer:"
        req_packet = self._generate_request(offer_packet)
        self._retrieve_server_ip(req_packet)
        self._state = self.AR_REQUEST
        self._send_packet(req_packet)

    def handle_dhcp_ack(self, packet):
        if self._state != self.AR_REQUEST:
            return
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

        self._success_handler_clb(result)

    def handle_dhcp_nack(self, packet):
        self._requestor.del_request(self)
        self._failure_handler_clb()

    def handle_timeout(self):
        if self._packet_retries >= self._max_retries:
            self._requestor.del_request(self)
            print "Timeout for reply to packet in state %d" % \
                    self._state
            self._failure_handler_clb()
        elif self._last_packet is not None:
            self._resend_packet()

class DhcpAddressRequestor(DhcpClient):
    def __init__(self, **kwargs):
        self.local_ip = kwargs["local_ip"]
        self.local_port = kwargs.get("local_port", 67)
        DhcpClient.__init__(self, str(self.local_ip), self.local_port, 67)
        self.__requests = {}
        self.BindToAddress()

    def add_request(self, request):
        self.__requests[request.xid] = request

    def del_request(self, request):
        del self.__requests[request.xid]

    def check_timeouts(self):
        t = time.time()
        for request in self.__requests.values()[:]:
            if t > request.timeout_time:
                request.handle_timeout()

    def _handle_packet(self, clb_name, packet):
        xid = packet.GetOption('xid')
        if xid not in self.__requests:
            print "Ignoring answer with xid %s" % repr(xid)
            return

        request = self.__requests[xid]
        clb = getaddr(request, clb_name)
        clb(offer_packet)

    def HandleDhcpOffer(self, offer_packet):
        self._handle_packet('handle_dhcp_offer', offer_packet)

    def HandleDhcpAck(self, packet):
        self._handle_packet('handle_dhcp_ack', offer_packet)

    def HandleDhcpNack(self, packet):
        self._handle_packet('handle_dhcp_nack', offer_packet)

    @property
    def socket(self):
        return self.dhcp_socket

    def handle_socket(self):
        self.GetNextDhcpPacket(timeout = 0)

class DhcpAddressRequestorManager(object):
    def __init__(self, request_factory):
        self._requestors_by_ip = {}
        self._request_factory = request_factory

    def add_requestor(self, requestor):
        self._requestors_by_ip[requestor.local_ip] = requestor

    def add_request(self, local_ip, **kwargs):
        if not local_ip in self._requestors_by_ip:
            raise RuntimeError('request for unsupported local IP %s' % local_ip)
        requestor = self._requestors_by_ip[local_ip]
        request = self._request_factory(requestor=weakref.proxy(requestor),
                **kwargs)
        requestor.add_request(request)

class CommandConnection(object):
    def __init__(self, sloop, socket):
        self._sloop = sloop
        self._socket = socket

    def __del__(self):
        self._socket.close()

    @property
    def socket(self):
        return self._socket

    def handle_socket(self):
        # We assume that everything is sent in one single chunk.
        try:
            data = self._socket.read()
            params = {}
            for p in data.split(' '):
                k, v = p.split('=')
                params[k] = v
        except IOError, e:
            print "IOError in cmd handle"
            return
        self.handle_command(params)

    def handle_command(self, params):
        """The handle_command function is called as soon as a command was
        received and parsed by CommandConnection.  A sub-class should implement
        the stub function and process the command.
        """

class OpenVpnCmdConn(CommandConnection):
    CC_RET_FAILURE = 1
    CC_RET_SUCCESS = 2

    USERNAME_RE = r'^(?P<username>[^/@]+)(/(?P<resource>[^/@]+))?@(?P<domain>[^/@]+)(/(?P<realm>[^/@]+))?$'

    def __init__(self, sloop, socket, request_realm_data_clb, add_request_clb,
            full_username_to_mac_clb):
        super(OpenVpnCmdConn, self).__init__(sloop, socket)
        self._request_realm_data = request_realm_data_clb
        self._add_request = add_request_clb
        self._full_username_to_mac = full_username_to_mac_clb
        self._ret_fn = None
        self._wrote_ret = False

    def __del__(self):
        if self._ret_fn is not None and not self._wrote_ret:
            self._write_ret(self.CC_RET_FAILURE)
        CommandConnection.__del__(self)

    def _write_ret(self, val):
        ret_fp = open(self._ret_fn, 'wb')
        ret_fp.write('%d' % val);
        ret_fp.close()
        self._wrote_ret = True

    def _success_handler(self, res):
        conf_fp = open(self._config_fn, 'wb')
        conf_fp.write('ifconfig-push %s %s\n' % (res['ip-address'],
                res['subnet-mask']))
        conf_fp.write('vlan-pvid %d\n' % self._realm_data.vid)
        conf_fp.write('push "ip-win32 dynamic"\n')
        conf_fp.write('push "route-gateway %s"\n' % (res['gateway']))
        conf_fp.write('push "redirect-gateway def1"\n')
        for dns_ip in res['dns']:
            conf_fp.write('push "dhcp-option DNS %s"\n' % dns_ip)
        conf_fp.write('push "dhcp-option DOMAIN %s"\n' % res['domain'])
        conf_fp.close()

        self._write_ret(self.CC_RET_SUCCESS)

    def _failure_handler(self):
        self._write_ret(self.CC_RET_FAILURE)

    def handle_command(self, params):
        try:
            self._full_username = params['full_username']
            self._ret_fn = params['ret_file_name']
            self._config_fn = params['config_file_name']
        except KeyError, e:
            print "command is missing a parameter: %s" % e.args
            return

        m = re.match(self.USERNAME_RE, self._full_username)
        if m is None:
            print "username in unexpected format: %s" % self._full_username
            return
        self._realm = m.group('realm')

        self._mac_addr = self._full_username_to_mac(self._full_username)

        self._realm_data = self._request_realm_data(realm=self._realm)

        self._add_request(success_handler_clb=self._success_handler,
                failure_handler_clb=self._failure_handler,
                mac_addr=hwmac(mac_addr),
                local_ip=ipv4(realm_data.requestor_ip),
                server_ips=realm_data.dhcp_server_ips)

class CommandConnectionListener(object):
    ACCEPT_QUEUE_LEN = 32

    def __init__(self, sloop, socket_path, cmd_conn_factory):
        self._sloop = sloop
        self._factory = cmd_conn_factory

        # TODO: Set proper permissions
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.setblocking(False)
        if os.path.exists(socket_path):
            os.remove(socket_path)
        self._socket.bind(socket_path)
        self._socket.listen(self.ACCEPT_QUEUE_LEN)

    def __del__(self):
        self._socket.close()

    @property
    def socket(self):
        return self._socket

    def handle_socket(self):
        try:
            socket = self._socket.accept()
        except IOError, e:
            print "Received exception %s while accepting new cmd conn" % repr(e)
            return
        conn = self._factory(sloop, socket)
        self._sloop.add_socket_handler(conn)

class SocketLoop(object):
    def __init__(self):
        self._socket_handlers = {}
        self._idle_handlers = []
        self._run = True
        self.timeout = 0.5

    def run(self):
        while self._run:
            sockets = self._socket_handlers.keys()
            ready_input_sockets, _, _ = select.select(sockets, [], [],
                    self.timeout)
            for ready_input_socket in ready_input_sockets:
                socket_handler = self._socket_handlers[ready_input_socket]
                socket_handler.handle_socket()
            for idle_handler in self._idle_handlers:
                idle_handler()

    def add_socket_handler(self, socket_handler):
        self._socket_handlers[socket_handler.socket] = socket_handler

    def del_socket_handler(self, socket_handler):
        del self._socket_handlers[socket_handler.socket]

    def add_idle_handler(self, idle_handler):
        self._idle_handlers.append(idle_handler)

    def quit(self):
        self._run = True

class TimeoutManager(object):
    def __init__(self):
        self._timeout_objects = []

    def add_timeout_object(self, timeout_object):
        self._timeout_objects.append(timeout_object)

    def del_timeout_object(self, timeout_object):
        self._timeout_objects.remove(timeout_object)

    def check_timeouts(self):
        old_tos = self._timeout_objects
        self._timeout_objects = []
        t = time.time()
        for timeout_object in old_tos:
            if timeout_object.timeout > t:
                self.add_timeout_object(timeout_object)
            else:
                timeout_object.handle_timeout()

    def __call__(self):
        self.check_timeouts()

class RealmData(object):
    def __init__(self, realm):
        self.realm = realm

        self.dhcp_local_port = DHCP_LOCAL_PORT
        if realm == 'fsmi-sec':
            self.vid = 386
            self.requestor_ip = "10.0.97.141"
            self.dhcp_server_ips = ["10.0.97.133"]
        elif realm == 'fsmi':
            self.vid = 808
            self.requestor_ip = "10.0.98.141"
            self.dhcp_server_ips = ["10.0.98.133"]
        elif realm == 'fsmi-prio':
            self.vid = 1
            self.requestor_ip = "10.0.99.141"
            self.dhcp_server_ips = ["10.0.99.133"]
        else:
            sys.stderr.write("E: Unknown realm %s.\n" % realm)
            sys.exit(1)

def get_realm_data(realm):
    realm_data = RealmData(realm)
    return realm_data

def main():
    UNIX_SOCKETS = ['/tmp/bla.sock']
    LISTENING_IPS = ['127.0.0.1']

    sloop = SocketLoop()
    timeout_mgr = TimeoutManager()
    sloop.add_idle_handler(timeout_mgr)

    requestor_mgr = DhcpAddressRequestorManager(
            request_factory=DhcpAddressRequest)

    def create_vpn_cmd_conn(sloop, socket):
        return OpenVpnCmdConn(sloop, socket,
                request_realm_data_clb=get_realm_data,
                add_request_clb=requestor_mgr.add_request,
                full_username_to_mac_clb=machasher.hash_login_to_mac)

    for unix_socket_fn in UNIX_SOCKETS:
        cmd_listener = CommandConnectionListener(weakref.proxy(sloop),
                unix_socket_fn, create_vpn_cmd_conn)
        sloop.add_socket_handler(cmd_listener)

    for listening_ip in LISTENING_IPS:
        requestor = DhcpAddressRequestor(local_ip=listening_ip)
        sloop.add_socket_handler(requestor)
        requestor_mgr.add_requestor(requestor)

    loop.run()
