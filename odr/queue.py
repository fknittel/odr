# vim:set fileencoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# queue.py
#
# Copyright © 2010 Fabian Knittel <fabian.knittel@lettink.de>
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


class StateQueue(object):
    """Manages a simple FIFO state queue with an idle state in case the queue is
    empty.
    """

    def __init__(self, idle_state):
        """\
        @param idle_state: The state to use while the queue is otherwise empty.
        """
        self._idle = idle_state
        self._queue = []
        self._current = self._idle

    @property
    def current(self):
        """@return: Returns the currently active state.  Might be the idle
            state.
        """
        return self._current

    def add(self, new_state):
        """Add a new state to the FIFO queue.  Might be turned into the active
        state in case the queue is currently empty.
        @param new_state: The new state to add.
        """
        if len(self._queue) == 0:
            self._current = new_state
        else:
            self._queue.append(new_state)

    def current_done(self):
        """Mark the currently active state as done.  Moves to the next state
        in the queue.  Does nothing in case the current state is already the
        idle state.
        """
        if len(self._queue) == 0:
            self._current = self._idle
        else:
            self._current = self._queue.pop(0)

    def clear(self):
        """Clears the queue without waiting for any states to finish.
        """
        self._queue = []
        self._current = self._idle
