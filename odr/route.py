# vim:set fileencoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# route.py -- Provides network mask calculations.
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

from pydhcplib.type_ipv4 import ipv4


def network_mask(mask_width):
    """Build the network mask matching the specified network mask bit width.

    @return: Returns the network mask as list of integers.
    """
    mask = [255] * max(mask_width / 8, 0)
    if len(mask) < 4:
        mask += [255 - (2**(8 - (mask_width % 8)) - 1)]
    mask += [0] * (4 - len(mask))
    return ipv4(mask).str()

