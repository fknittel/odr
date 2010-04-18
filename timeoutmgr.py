#!/usr/bin/python
# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# timeoutmgr.py
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

import time

class TimeoutManager(object):
    def __init__(self):
        self._timeout_objects = []

    def add_timeout_object(self, timeout_object):
        print "adding timeout object %s" % repr(timeout_object)
        self._timeout_objects.append(timeout_object)

    def del_timeout_object(self, timeout_object):
        print "removing timeout object %s" % repr(timeout_object)
        self._timeout_objects.remove(timeout_object)

    def check_timeouts(self):
        old_tos = self._timeout_objects
        self._timeout_objects = []
        t = time.time()
        for timeout_object in old_tos:
            if timeout_object.timeout_time > t:
                self.add_timeout_object(timeout_object)
            else:
                timeout_object.handle_timeout()

    def __call__(self):
        self.check_timeouts()
