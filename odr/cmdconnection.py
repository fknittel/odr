# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# cmdconnection.py -- Module for simple line-based client-server communication
#         via UNIX domain sockets.
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

import logging
import socket
import os
import IN
import struct


class LineSocket(object):
    """The LineSocket class wraps around a regular socket object.  Instead of
    byte blobs, the class allows lines to be received.
    """

    def __init__(self, socket):
        """@param socket: The socket that is used to receive the line data from.
        """
        self._socket = socket
        self._in_buf = ''

    def __del__(self):
        self.close()

    def close(self):
        """Close the underlying socket.  Further access to the socket is not
        allowed.
        """
        self._socket.close()

    def recv_lines(self):
        """Receives data from the socket.  The received data is buffered until a
        complete line can be retrieved.  Each call of this method will return
        the next completed line.

        @return: Returns None in case of EOF, otherwise the next completed
        line.
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
        """Sends data via the underlying socket.
        @param msg: The byte string to send via the socket.
        """
        self._socket.send(msg)

    def fileno(self):
        """@return: Returns the file descriptor number of the underlying socket.
        """
        return self._socket.fileno()


def unpack_cmd(cmd_line):
    """Parse the command line and return the parsed data or None.
    @param cmd_line: Single-line command.
    @return: Returns a tuple of command name and parameter dictionary.
    """
    try:
        params = {}
        l = cmd_line.split('\0')
        cmd = l.pop(0)
        for p in l:
            k, v = p.split('=')
            params[k] = v
    except:
        return None, {}
    return (cmd, params)

def pack_cmd(cmd, params):
    """Packs a command name and a dictionary of parameters into a command line.
    @param cmd: The command name.
    @param params: A dictionary of parameters.
    @return: Returns the command line.
    """
    for e in [cmd] + params.keys() + params.values():
        if ('\n' in e) or ('\0' in e):
            raise ValueError('attempted to pack invalid command or parameters')
    return '\0'.join([cmd] + ['%s=%s' % i for i in params.iteritems()])

class CommandConnection(object):
    """Represents the connection to a single client.  The class should be used
    as a base-class.  Sub-classes will implement the stub methods to provide the
    actual functionality.

    The communication is line based.  Each command is on a single line and ends
    with a new-line character.
    """

    def __init__(self, sloop, socket):
        """\
        @param sloop: Instance of the socket loop.
        @param socket: Socket that will be used for communication.
        """
        self._sloop = sloop
        self._socket = LineSocket(socket)

    def __del__(self):
        self._socket.close()

    @property
    def socket(self):
        """@return: Returns the underlying socket.
        """
        return self._socket

    def _parse_command(self, cmd_line):
        """Splits the command-line and hands off the parsed data to the
        child class' handle_cmd method.
        @param cmd_line: The command line string to parse.
        """
        self.log.debug('parsing command "%s"' % cmd_line)
        cmd, params = unpack_cmd(cmd_line)
        if cmd is None:
            self.log.warning('failed to parse command "%s"' % cmd_line)
            return
        self.handle_cmd(cmd, params)


    def handle_socket(self):
        """Part of the interface expected by the socket loop.  Should be called
        as soon as the socket has data waiting to be read.  The method will
        process any pending data and parse the commands of full received
        command lines.

        In case of EOF, the socket will be removed from the socket loop and this
        instance will get destroyed.
        """
        cmd_lines = self._socket.recv_lines()
        if cmd_lines is not None:
            for cmd_line in cmd_lines:
                self._parse_command(cmd_line)
        else:
            self.log.debug('closing cmd socket due to EOF')
            self._sloop.del_socket_handler(self)

    def send_cmd(self, cmd, params={}):
        """Used to send responses back to the client.  Sends the specified
        command as a single-line.

        @param cmd: Command to send. Should not contain a new-line or a zero
                character.
        @param params: Parameters to send. Should not contain a new-line or a
                zero character.
        """
        self._socket.send(pack_cmd(cmd, params) + '\n')

    def handle_command(self,  cmd):
        """The handle_command function is called as soon as a command was
        received and parsed by CommandConnection.  A sub-class should implement
        the stub function and do the actual command processing.
        """


class CommandConnectionListener(object):
    """Listens on a POSIX Local IPC Socket (AKA Unix domain socket) and uses a
    factory function to create an instance that takes care of each new socket
    connection.
    """

    ACCEPT_QUEUE_LEN = 32

    def __init__(self, sloop, cmd_conn_factory, socket_path,
                socket_perm_mode=0666, auth_check=None):
        """Opens the POSIX Local IPC Socket.  If the file already exists, it
        is deleted first.  The file permissions are set according to the
        socket_perm_mode parameter.

        @param sloop: Instance of the socket loop.
        @param cmd_conn_factory: Factory method that gets called with the
                socket loop instance and the new socket for each new connection.
        @param socket_path: Path to the POSIX Local IPC Socket.
        @param socket_perm_mode: File access permissions to be set for the
                file socket.
        """
        self._sloop = sloop
        self._socket_path = socket_path
        self._factory = cmd_conn_factory
        self._auth_check = auth_check

        self.log = logging.getLogger('cmdconnlistener')
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.setblocking(False)
        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)
        self.log.debug('listening on socket %s' % self._socket_path)
        self._socket.bind(self._socket_path)
        os.chmod(self._socket_path, socket_perm_mode)
        self._socket.listen(self.ACCEPT_QUEUE_LEN)

    def __del__(self):
        self._socket.close()

    @property
    def socket(self):
        """@return: Returns the listening socket.
        """
        return self._socket

    def handle_socket(self):
        """Part of the interface expected by the socket loop.  Should be called
        as soon as the socket has a new connection waiting.  Uses the factory
        method passed in at creation time to create a new handler instance for
        each socket.
        """
        try:
            sock, _ = self._socket.accept()
        except IOError, e:
            print "Received exception %s while accepting new cmd conn" % repr(e)
            return
        self.log.debug('received a new connection')
        sock.setblocking(False)
        if self._auth_check is not None:
            pid, uid, gid = getsockpeercred(sock)
            if not self._auth_check(sock=sock, pid=pid, uid=uid, gid=gid):
                self.log.info('rejecting command connection to %s from ' \
                        'PID %d (UID %d, GID %d)' % (self._socket_path, pid,
                                uid, gid))
                sock.close()
                return
        conn = self._factory(sloop=self._sloop, sock=sock)
        self._sloop.add_socket_handler(conn)


def getsockpeercred(sock):
    """Retrieves the credentials of a peer which is connected via a AF_UNIX
    socket.

    @param sock: The socket connection.
    @return: Returns a triple with the peer's PID, UID and GID.
    """
    # XXX: We assume that the structure contains 3 32 bit integers.  We would
    # need to know the system's sizes of pid_t, uid_t and gid_t to be sure.
    # (SO_PEERCRED returns a struct ucred.)
    return struct.unpack('3I', sock.getsockopt(socket.SOL_SOCKET,
            IN.SO_PEERCRED, 3 * 4))
