# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# timeoutmgr.py -- The module provides a class for managing timeout events.
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

import time


class TimeoutObject(object):
    def __init__(self, timeout_time, timeout_func):
        self.timeout_time = timeout_time
        self._timeout_func = timeout_func

    def handle_timeout(self):
        self._timeout_func()

    def __repr__(self):
        return "<%s wrapping %s>" % (self.__class__, repr(self._timeout_func))


class TimeoutManager(object):
    """The TimeoutManager keeps track of objects that have a timeout time set.
    As soon as a timeout occurs, the affected objects are notified.

    Objects that have timed out are removed from the timeout managers list of
    objects.
    """
    def __init__(self):
        self._timeout_objects = []

    def add_rel_timeout(self, timeout_secs, timeout_func):
        """Adds a timeout event for a time in the near future, measured in
        seconds from the current point of time.  On timeout, the function
        timeout_func is called.

        @param timeout_secs: Relative time in seconds from now at which the
                timeout shall occur.
        @param timeout_func: Function that will be called on timeout.
        @return: Returns a timeout object that can be used to remove the
                timeout event before the actual timeout.
        """
        return self.add_abs_timeout(time.time() + timeout_secs, timeout_func)

    def add_abs_timeout(self, timeout_time, timeout_func):
        """Adds a timeout event for a specific time.  On timeout, the function
        timeout_func is called.

        @param timeout_time: Absolute time (in seconds since the epoch) at
                which the timeout shall occur.
        @param timeout_func: Function that will be called on timeout.
        @return: Returns a timeout object that can be used to remove the
                timeout event before the actual timeout.
        """
        obj = TimeoutObject(timeout_time, timeout_func)
        self.add_timeout_object(obj)
        return obj

    def add_timeout_object(self, timeout_object):
        """Adds a timeout object.  The timeout object must provide the timeout
        time as attribute "timeout_time" and an event handler method
        "handle_timeout".

        @param timeout_object: Object that should be added.
        """
        self._timeout_objects.append(timeout_object)

    def del_timeout_object(self, timeout_object):
        """Removes a timeout object.  The method may be used if an object should
        be removed before it times out.

        @param timeout_object: Object that is to be removed.
        """
        self._timeout_objects.remove(timeout_object)

    def check_timeouts(self):
        """This method should be periodically called to check whether any
        timeouts have occured in the mean-time.

        Objects that have timed out are removed from the list of timeout objects
        and get notified by invoking their "handle_timeout" method.
        """
        old_tos = self._timeout_objects
        self._timeout_objects = []
        t = time.time()
        for timeout_object in old_tos:
            if timeout_object.timeout_time > t:
                self._timeout_objects.append(timeout_object)
            else:
                timeout_object.handle_timeout()

    def __call__(self):
        self.check_timeouts()
