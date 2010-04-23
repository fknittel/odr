# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# socketloop.py - Provides a socket/select-based event loop.
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

import select
import traceback
import logging

class SocketLoop(object):
    """Maintains a list of socket handlers.  Each handler may have a single
    socket.  Waits for activity on all known sockets and in case of activity for
    a certain socket, calls the socket's handler.

    Additionally, there are idle handlers that get called after socket activity
    processing or once after every timeout (if there was no activity at all).
    """
    def __init__(self):
        self._socket_handlers = {}
        self._idle_handlers = []
        self._run = True
        self.timeout = 0.5
        self.log = logging.getLogger('socketloop')

    def run(self):
        """Runs the socket select loop until the quit method is called.
        """
        while self._run:
            # We currently only care about read events. (Read events also cover
            # connect events on listening sockets.)
            ready_input_sockets, _, _ = select.select(self.sockets, [], [],
                    self.timeout)
            for ready_input_socket in ready_input_sockets:
                socket_handler = self._socket_handlers[ready_input_socket]
                try:
                    socket_handler.handle_socket()
                except:
                    self.log.exception('socket handler failed')

            for idle_handler in self._idle_handlers:
                try:
                    idle_handler()
                except:
                    self.log.exception('idle handler failed')

    def add_socket_handler(self, socket_handler):
        """Add an additional socket handler.
        @param socket_handler: The socket handler instance to add.
        """
        self._socket_handlers[socket_handler.socket] = socket_handler

    def del_socket_handler(self, socket_handler):
        """Remove a previously added socket handler.
        @param socket_handler: The socket handler instance to remove.
        """
        del self._socket_handlers[socket_handler.socket]

    def add_idle_handler(self, idle_handler):
        """Add an idle handler.
        @param idle_handler: The idle handler instance to add.
        """
        self._idle_handlers.append(idle_handler)

    @property
    def sockets(self):
        """@return: Returns the list of sockets that we have handlers for.
        """
        return self._socket_handlers.keys()

    def quit(self):
        """Request that the select loop be exited soon.  Sets a flag that will
        be checked for in the select loop.
        """
        self._run = True
