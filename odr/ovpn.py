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
import errno
from odr.queue import StateQueue
from odr.linesocket import LineSocket


CC_RET_FAILED = 0
CC_RET_SUCCEEDED = 1
CC_RET_DEFERRED = 2


def write_deferred_ret_file(fp, val):
    """Write one of the deferral values to the deferred return value file.

    @param fp: File pointer of the deferred return value file.
    @param val: One of the CC_RET_* constants.
    """
    fp.seek(0)
    fp.write('%d' % val);
    fp.flush()
    os.fsync(fp.fileno())


def determine_daemon_name(script_name):
    """We identify the OpenVPN server instance calling us by either looking at
    an environment variable or by trying to deduce the name from the way we
    were called.

    @param script_name: The regular base filename of this Python script.
    @return: Returns the OpenVPN server instance name or None.
    """
    import sys

    if 'daemon_name' in os.environ:
        return os.environ['daemon_name']

    b = os.path.basename(sys.argv[0])
    if b.startswith('%s_' % script_name):
        return b[len(script_name) + 1:]

    return None


class OvpnClientConnData(object):
    """Represents a single client connection within an OpenVPN server's client
    list.
    """

    def __init__(self, **kwargs):
        self.common_name = kwargs.get('common_name', None)
        self.virtual_address = kwargs.get('virtual_address', None)
        self.server = kwargs.get('server', None)

    def __str__(self):
        return '%s on %s' % (self.common_name, self.server)

    def __repr__(self):
        return "<OvpnClientConnData common_name=%s, ...>" % self.common_name


class OvpnServer(object):
    """Represents a single OpenVPN server and allows communication with the
    server (via the management console).
    """
    def __init__(self, sloop, name, socket_fn):
        """\
        @param sloop: Instance of the socket loop.
        @param name: Freely choosable, unique identifier of the server.
        @param socket_fn: Path to the management console's UNIX socket.
        """
        self._sloop = sloop
        self._name = name
        self._socket_fn = socket_fn

        self.log = logging.getLogger('ovpnsrv')
        self._socket = None

        self.connect_to_mgmt()

    @property
    def connected(self):
        return self._socket is not None

    def connect_to_mgmt(self):
        if self.connected:
            self.log.debug('replacing connection to management console')
            self.close_mgmt()

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self._socket_fn)
        except socket.error, e:
            self.log.error('connection to OpenVPN server "%s" failed: %s' % (
                    self.name, e))
            sock.close()
            return

        self.log.debug('connected to OpenVPN server "%s" at "%s"' % (
                self.name, self._socket_fn))
        self._socket = LineSocket(sock)
        self._sloop.add_socket_handler(self)

        self._cmd_state = StateQueue(idle_state=_OvpnIdleState())
        self._cmd_state.add(_OvpnWaitConnectState(self, self._on_connected))

    def close_mgmt(self):
        self._sloop.del_socket_handler(self)
        self._socket.close()
        self._socket = None
        self._cmd_state.clear()

    def _on_connected(self, hello_msg):
        if not hello_msg.startswith('>INFO:'):
            self.log.error('connection to OpenVPN server "%s" failed: "%s"' % (
                    self.name, hello_msg))
            self.close_mgmt()
            return
        self.log.debug('connected to OpenVPN server "%s"' % self.name)

    def __del__(self):
        if self.connected:
            # Note:  We're obviously no longer managed by the sloop, otherwise
            # we wouldn't be getting collected.  Therefore no need to remove us
            # from the sloop.
            self._socket.close()

    def __cmp__(self, other):
        return cmp(self._name, other._name)

    def __hash__(self):
        return hash(self._name)

    def __str__(self):
        return self.name

    @property
    def name(self):
        return self._name

    @property
    def socket(self):
        """@return: Returns the listening socket.
        """
        return self._socket

    def handle_socket(self):
        lines = self._socket.recvlines()
        if lines is None:
            # EOF - clean-up.
            self.log.error('received EOF on socket for OpenVPN server "%s"' % \
                    self.name)
            self.close_mgmt()
            return

        for line in lines:
            # Feed each line to the current state.  If the state indicates
            # completion, move to next state.
            if not self._cmd_state.current.handle_line(line):
                self._cmd_state.current_done()

    def _send_cmd(self, cmd):
        try:
            self._socket.send(cmd.replace('\n', '\\n') + '\n')
        except socket.error, e:
            if e.args[0] == errno.EPIPE:
                self.log.error('socket for OpenVPN server "%s" was ' \
                        'unexpectedly closed' % self.name)
                self.close_mgmt()
            else:
                raise

    def disconnect_client(self, common_name):
        """Disconnects the specified client from this OpenVPN server instance.

        @param common_name: Common name of the client that should be
                disconnected.
        """
        if not self.connected:
            self.log.debug('ignoring disconnect_client call, as "%s" has no ' \
                    'active management connection.' % self.name)
            return
        self.log.debug('disconnecting client %s from OpenVPN server "%s"' % \
                (common_name, self.name))
        self._cmd_state.add(_OvpnDisconnectClientsState(self, common_name,
                lambda res:None))

    def poll_client_list(self, list_done_clb):
        """Polls the list of clients connected to this server.  On completion,
        the callback is called with the complete list as parameter.  In case
        of an error, the callback is called with None instead of the list.

        @param: list_done_clb The callback function to call on completion or
                error.
        """
        if not self.connected:
            self.log.debug('ignoring poll_client_list call, as "%s" has no ' \
                    'active management connection.' % self.name)
            return
        self.log.debug('polling user list from OpenVPN server "%s"' % \
                self.name)
        self._cmd_state.add(_OvpnListClientsState(self, list_done_clb))


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


class _OvpnWaitConnectState(_OvpnStateInterface):
    """Waits for an OpenVPN management socket to to connect.
    """

    def __init__(self, ovpn, done_clb):
        self._done = done_clb

    def handle_line(self, line):
        self._done(line)
        return False


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
        if d[3] != '':
            cl.virtual_address = d[3]
        else:
            cl.virtual_address = None
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


class OvpnServerSupervisor(object):
    """Makes sure the associated OpenVPN server has an active management
    connection.
    """
    def __init__(self, timeout_mgr, server, timeout):
        self._timeout_mgr = timeout_mgr
        self._server = server
        self._timeout = timeout
        self.log = logging.getLogger('ovpnserversup')
        self._add_myself()
        self.log.debug('watching server connection %s' % self._server)

    def _add_myself(self):
        import time
        self._timeout_time = time.time() + self._timeout
        self._timeout_mgr.add_timeout_object(self)

    def __del__(self):
        self.log.debug('no longer watching server connection %s' % self._server)

    @property
    def timeout_time(self):
        return self._timeout_time

    def handle_timeout(self):
        if not self._server.connected:
            self._server.connect_to_mgmt()
        self._add_myself()

