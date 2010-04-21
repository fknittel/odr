#!/usr/bin/python
# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# socketloop.py
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

import select
import traceback
import logging

class SocketLoop(object):
    def __init__(self):
        self._socket_handlers = {}
        self._idle_handlers = []
        self._run = True
        self.timeout = 0.5
        self.log = logging.getLogger('socketloop')

    def run(self):
        while self._run:
            args = [self.sockets, [], [], self.timeout]
            ready_input_sockets, _, _ = select.select(*args)
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
        self._socket_handlers[socket_handler.socket] = socket_handler

    def del_socket_handler(self, socket_handler):
        del self._socket_handlers[socket_handler.socket]

    def add_idle_handler(self, idle_handler):
        self._idle_handlers.append(idle_handler)

    @property
    def sockets(self):
        return self._socket_handlers.keys()

    def quit(self):
        self._run = True
