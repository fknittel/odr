#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sw=4 et:

# machasher.py
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

import hashlib
import sys

def hash_login_to_mac(login):
    # Use a regular secure hash as basis.
    h = hashlib.sha1()
    h.update(login)
    d = h.digest()

    # Spread the digest over the 48 bits of the mac address.
    mac_addr = [0] * 6
    i = 0
    for c in d:
        mac_addr[i] ^= ord(c)
        i = (i + 1) % len(mac_addr)

    # Ensure that the local address bit is set and the broadcast bit is unset.
    mac_addr[0] = (mac_addr[0] & 252) | 2

    return mac_addr

if __name__ == '__main__':
    mac_addr = hash_login_to_mac(sys.argv[1])
    print ("%02x" +":%02x" *5) % tuple(mac_addr)
