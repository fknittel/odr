# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# radius.py -- Manages RADIUS interactions for connection accounting.
#
# Copyright © 2010 Philipp Kern <pkern@debian.org>
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

import pyrad.packet
from odr.listeningsocket import ListeningSocket

# TODO:
#  - Is Alive actually Interim-Update?


class InvalidRadiusAccountingTypeException(Exception):
    pass


class RadiusAccountingRequest(object):
    def __init__(self, radius_client, openvpn_client, packet_type):
        if packet_type not in ['Start', 'Alive', 'Stop']:
            raise InvalidRadiusAccountingTypeException, \
                'Invalid packet type: %s' % packet_type

        self._packet_id = pyrad.packet.Packet.CreateID()
        self._packet = pyrad.packet.AcctPacket()
        self._populate_packet(openvpn_client)

    def _populate_packet(self, client, packet_type):
        packet = self._packet
        packet['Acct-Status-Type'] = packet_type
        packet['User-Name'] = client.user_name
        packet['Calling-Station-Id'] = client.remote_ip
        packet['Framed-IP-Adress'] = client.local_ip
        # NAS-Identifier aus Config lesen?
        # TODO: NAS-IP-Address: Host-IP

    def set_terminate_cause(self, cause):
        """Sets the value of the Acct-Terminate-Cause field.  Most
        of the possible values are specified in RFC2866, some samples
        include "User Request", "Lost Carrier" and "Idle Timeout".
        """
        self._packet['Acct-Terminate-Cause'] = cause


# PLEASE NOTE (XXX): The use of ListeningSocket for both DHCP and RADIUS
# implies the use of IPv4 only.
class RadiusSocket(ListeningSocket):
    def __init__(self, radius_client, listen_address='', listen_port=0,
            listen_device=None):
        super(RadiusSocket, self).__init__(listen_address, listen_port,
                listen_device)
        self.radius_client = radius_client

    def handle_socket(self):
        """Retrieves the next, waiting RADIUS packet.
        """
        data, source_address = self.socket.recvfrom(2048)
        if len(data) == 0:
           self.log.warning("unexpectedly received EOF!")
           return
        
        packet = pyrad.packet.DecodePacket(data)
        print packet

    def send_packet(self, packet):
        self.socket.sendto(packet.RequestPacket(), server)

class RadiusClient(object):
    def __init__(self, timeout_mgr, socket_loop):
        self.log = logging.getLogger('radiusclient')
        self.timeout_mgr = timeout_mgr
        self._socket_loop = socket_loop
        self.radius_socket = RadiusSocket(self)
        socket_loop.add_socket_handler(self.reply_handler)

    def add_server(self, server, **options):
        self.servers[server.name] = options

    def send_request(self, client, accounting_type):
        server_name = client.realm_data.radius_accounting
        if server_name is None:
            # If there's no server, exit here without doing anything useful.
            return

        try:
            server = self.servers[server_name]
        except:
            self.log.exception('Specified server %s not found in '\
                    'configuration.' % server_name)
            return

        request = RadiusAccountingRequest(self, client, accounting_type, server)
        self.radius_socket.send_packet(request)

    def handle_connect(self, client):
        self.send_request(client, 'Start')

    def handle_refresh(self, client):
        self.send_request(client, 'Alive')

    def handle_disconnect(self, client):
        self.send_request(client, 'Stop')

