# vim:set fileencoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# linesocket.py -- Module for simple line-based communication via sockets.
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


class LineSocket(object):
    """The LineSocket class wraps around a regular socket object.  Instead of
    byte blobs, the class allows lines to be received.
    """

    def __init__(self, socket):
        """@param socket: The socket that is used to receive the line data from
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

    def recvlines(self):
        """Receives data from the socket.  The received data is buffered until
        a complete line can be retrieved.  Each call of this method will return
        the next completed line(s).

        @return: Returns None in case of EOF, otherwise the list of completed
            lines.
        """
        new_data = self._socket.recv(1024)
        self._in_buf += new_data.replace('\r\n', '\n')
        lines = self._in_buf.split('\n')
        # Add back new-line character to all but the last lines.
        for l in range(len(lines) - 1):
            lines[l] = lines[l] + '\n'
        if new_data == '':
            # Received EOF.  Return any incomplete lines.
            self._in_buf = ''
            if len(lines) == 1 and lines[0] == '':
                return None
        else:
            # Store incomplete line-fragment.
            self._in_buf = lines.pop()
        return lines

    def send(self, msg):
        """Sends data via the underlying socket.
        @param msg: The byte string to send via the socket.
        """
        return self._socket.send(msg)

    def fileno(self):
        """@return: Returns the file descriptor number of the underlying socket
        """
        return self._socket.fileno()
