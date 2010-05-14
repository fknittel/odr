# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# ovpn.py - Provides OpenVPN constants.
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

import os
import socket
import logging
from Queue import Queue
from odr.linesocket import LineSocket
from odr.weakmethod import WeakBoundMethod


CC_RET_FAILED = 0
CC_RET_SUCCEEDED = 1
CC_RET_DEFERRED = 2


def write_deferred_ret_file(fp, val):
    fp.seek(0)
    fp.write('%d' % val);
    fp.flush()
    os.fsync(fp.fileno())


class OvpnClientConnData(object):
    __slots__ = ['__weakref__', 'common_name', 'real_address',
            'virtual_address', 'bytes_rcvd', 'bytes_sent', 'connected_since',
            'server']

    def __init__(self, **kwargs):
        self.common_name = kwargs.get('common_name', None)
        self.real_address = kwargs.get('real_address', None)
        self.virtual_address = kwargs.get('virtual_address', None)
        self.bytes_rcvd = kwargs.get('bytes_rcvd', None)
        self.bytes_sent = kwargs.get('bytes_sent', None)
        self.connected_since = kwargs.get('connected_since', None)
        self.server = kwargs.get('server', None)

    def __str__(self):
        return '%s on %s' % (self.common_name, self.server)

    def __repr__(self):
        return "<OvpnClientConnData common_name=%s, ...>" % self.common_name


class OvpnServer(object):
    def __init__(self, name, mgmt_sock_file, sloop):
        self._name = name
        self._mgmt_sock_file = mgmt_sock_file
        self._sloop = sloop

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._mgmt_sock_file)
        self._socket = LineSocket(sock)

        self._idle_state = _OvpnIdleState()
        self._state_queue = Queue()
        self._state = self._idle_state

    def __del__(self):
        self._socket.close()

    def __eq__(self, other):
        return self._name == other._name

    @property
    def name(self):
        return self._name

    def __str__(self):
        return self.name

    @property
    def socket(self):
        """@return: Returns the listening socket.
        """
        return self._socket

    def handle_socket(self):
        lines = self._socket.recvlines()
        if lines is None:
            # EOF - clean-up.
            self._sloop.del_socket_handler(self)
            return

        for line in lines:
            # Feed each line to the current state.  If the state indicates
            # completion, return to idle state.
            if not self._state.handle_line(line):
                self._next_state()

    def _send_cmd(self, cmd):
        self._socket.send(cmd.replace('\n', '\\n') + '\n')

    def _next_state(self):
        if self._state_queue.empty():
            self._state = self._idle_state
        self._state = self._state_queue.get()

    def _add_state(self, new_state):
        if self._state_queue.empty():
            self._state = new_state
        self._state_queue.put(new_state)

    def disconnect_client(self, client):
        """Disconnects the specified client from this OpenVPN server instance.

        @param client: OvpnClient instance representing the client that should
                be disconnected.
        """
        self._add_state(_OvpnDisconnectClientsState(self, lambda res:None))

    def poll_client_list(self, list_done_clb):
        """Polls the list of clients connected to this server.  On completion,
        the callback is called with the complete list as parameter.  In case
        of an error, the callback is called with None instead of the list.

        @param: list_done_clb The callback function to call on completion or
                error.
        """
        self._add_state(_OvpnListClientsState(self, list_done_clb))


class _OvpnStateInterface(object):
    def handle_line(self, line):
        raise RuntimeError('called purely virtual handle_line method of %s' % \
                repr(self))


class _OvpnIdleState(_OvpnStateInterface):
    """The default state of the management console.  Takes all lines, ignores
    them and wants to continue forever.
    """
    def handle_line(self, line):
        return True


class _OvpnListClientsState(_OvpnStateInterface):
    """Uses an OpenVPN management socket to asynchronously request the client
    list.
    """

    def __init__(self, ovpn, list_done_clb):
        self._ovpn = ovpn
        self._list_done = list_done_clb

        self._clients = []
        self._ovpn._send_cmd('status 2')

    def _parse_client_line(self, line):
        cl = OvpnClientConnData(server=self._ovpn)
        d = line.split(',')
        cl.common_name = d[1]
        cl.real_address = d[2]
        cl.virtual_address = d[3]
        cl.bytes_rcvd = int(d[4])
        cl.bytes_sent = int(d[5])
        cl.connected_since = int(d[7])
        self._clients.append(cl)

    def handle_line(self, line):
        if line.startswith('CLIENT_LIST,'):
            self._parse_client_line(line)
        elif line == 'END\n':
            self._list_done(self._clients)
            return False
        return True


class _OvpnDisconnectClientsState(_OvpnStateInterface):
    """Uses an OpenVPN management socket to asynchronously disconnect a client.
    """

    def __init__(self, ovpn, common_name, done_clb):
        self._done = done_clb
        ovpn._send_cmd('kill %s' % common_name)

    def handle_line(self, line):
        if line.startswith('SUCCESS:'):
            self._done(True)
            return False
        elif line.startswith('ERROR:'):
            self._done(False)
            return False
        return True
