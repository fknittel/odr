#!/usr/bin/python
# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# cmdconnection.py
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

import logging
import socket
import os

class LineSocket(object):
    def __init__(self, socket):
        self._socket = socket
        self._in_buf = ''

    def __del__(self):
        self.close()

    def close(self):
        self._socket.close()

    def recv_lines(self):
        """@return: Returns None in case of EOF, otherwise a list of lines.
        """
        new_data = self._socket.recv(1024)
        self._in_buf += new_data
        lines = self._in_buf.split('\n')
        if new_data == '' and len(lines) == 1 and lines[0] == '':
            # Received EOF and no data left in _in_buf.  Indicate EOF to caller.
            return None
        self._in_buf = lines.pop()
        return lines

    def send(self, msg):
        self._socket.send(msg)

    def fileno(self):
        return self._socket.fileno()

class CommandConnection(object):
    def __init__(self, sloop, socket):
        self._sloop = sloop
        self._socket = LineSocket(socket)

    def __del__(self):
        self._socket.close()

    @property
    def socket(self):
        return self._socket

    def handle_socket(self):
        cmds = self._socket.recv_lines()
        if cmds is not None:
            for cmd in cmds:
                self.handle_command(cmd)
        else:
            self._sloop.del_socket_handler(self)

    def send_cmd(self, cmd):
        self._socket.send(cmd + '\n')

    def handle_command(self,  cmd):
        """The handle_command function is called as soon as a command was
        received and parsed by CommandConnection.  A sub-class should implement
        the stub function and process the command.
        """

class CommandConnectionListener(object):
    ACCEPT_QUEUE_LEN = 32

    def __init__(self, sloop, cmd_conn_factory, socket_path,
                socket_perm_mode=0600):
        self._sloop = sloop
        self._factory = cmd_conn_factory

        self.log = logging.getLogger('cmdconnlistener')
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.setblocking(False)
        if os.path.exists(socket_path):
            os.remove(socket_path)
        self.log.debug('listening on socket %s' % socket_path)
        self._socket.bind(socket_path)
        os.chmod(socket_path, socket_perm_mode)
        self._socket.listen(self.ACCEPT_QUEUE_LEN)

    def __del__(self):
        self._socket.close()

    @property
    def socket(self):
        return self._socket

    def handle_socket(self):
        try:
            socket, _ = self._socket.accept()
        except IOError, e:
            print "Received exception %s while accepting new cmd conn" % repr(e)
            return
        self.log.debug('received a new connection')
        socket.setblocking(False)
        conn = self._factory(self._sloop, socket)
        self._sloop.add_socket_handler(conn)
