# vim:set fileencoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# socketcompat.py -- Provide a few socket constants
#
# Copyright © 2015 Fabian Knittel <fabian.knittel@lettink.de>
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

from __future__ import (absolute_import, division,
        print_function, unicode_literals)

try:
    # pylint: disable=no-name-in-module
    from socket import SO_BINDTODEVICE
except ImportError:
    try:
        # pylint: disable=no-name-in-module
        from IN import SO_BINDTODEVICE
    except ImportError:
        # Fall back to /usr/include/asm-generic/socket.h from the Linux kernel
        SO_BINDTODEVICE = 25

try:
    # pylint: disable=no-name-in-module
    from socket import SO_PEERCRED
except ImportError:
    try:
        # pylint: disable=no-name-in-module
        from IN import SO_PEERCRED
    except ImportError:
        # Fall back to /usr/include/asm-generic/socket.h from the Linux kernel
        SO_PEERCRED = 17
