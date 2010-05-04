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


CC_RET_FAILED = 0
CC_RET_SUCCEEDED = 1
CC_RET_DEFERRED = 2


def write_deferred_ret_file(fp, val):
    fp.seek(0)
    fp.write('%d' % val);
    fp.flush()
    os.fsync(fp.fileno())
