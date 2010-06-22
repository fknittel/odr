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

import socket
import IN
import pyrad.packet
from odr.listeningsocket import ListeningSocket


class RadiusAccountingRequest(object):
    class __init__(self, **kwargs):
        self._packet_id = pyrad.packet.Packet.CreateID()


class RadiusReplyHandler(ListeningSocket):
    def __init__(self, listen_address='', listen_port=0, listen_device=None):
        super(RadiusReplyHandler, self).__init__(listen_address, listen_port,
                listen_device)

    def handle_socket(self):
        """Retrieves the next, waiting RADIUS packet.
        """
        data, source_address = self.socket.recvfrom(2048)
        if len(data) == 0:
           self.log.warning("unexpectedly received EOF!")
           return
        
        packet = pyrad.packet.DecodePacket(data)
        print packet

class RadiusClient(object):
    def __init__(self, socket_loop):
        self.log = logging.getLogger('radiusclient')
        self._socket_loop = socket_loop
        self.reply_handler = RadiusReplyHandler()
        socket_loop.add_socket_handler(self.reply_handler)

    def _prepare_accounting_packet(self, client):
        packet = pyrad.packet.AcctPacket()
        packet['User-Name'] = client.user_name
        packet['Calling-Station-Id'] = client.remote_ip
        packet['Framed-IP-Adress'] = client.local_ip

    def handle_connect(self, client):
        packet['Acct-Status-Type'] = 'Start'
        pass

#        $req->set_attr('User-Name' => $user);
#        $req->set_attr('Framed-Protocol' => 'PPP');
#        $req->set_attr('NAS-Port' => 1234);
#        $req->set_attr('NAS-Identifier' => 'dukath-www');
#        $req->set_attr('NAS-IP-Address' => $myip);
#        $req->set_attr('Calling-Station-Id' => "$ip");
#        $req->set_attr('Acct-Status-Type', 'Stop');
#        $req->set_attr('Acct-Delay-Time', 0);
#        $req->set_code('Accounting-Request');
#        $req->set_attr('Class', "dukath");
#        $req->set_attr('Acct-Session-Id', "$sessionid");
#        $req->set_attr('Framed-IP-Address', "$ip");
#        $req->set_attr('Acct-Session-Time', $sessiontime);
#        $req->set_attr('Acct-Input-Octets', $inoctets);
#        $req->set_attr('Acct-Output-Octets', $outoctets);
#        $req->set_attr('Acct-Input-Packets', $inpackets);
#        $req->set_attr('Acct-Output-Packets', $outpackets);
#        $req->set_attr('Acct-Terminate-Cause', 'User-Request');
#

    def handle_refresh(self, client):
        packat['Acct-Status-Type'] = 'Alive'

    def handle_disconnect(self, client):
        packet['Acct-Status-Type'] = 'Stop'
        # ggf. 'Acct-Terminate-Cause'


def init_plugin(socket_loop):
    return RadiusClient(socket_loop)

