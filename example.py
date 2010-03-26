#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sw=4 et:

# example.py -- Demonstates usage of the dhcprequestor module.
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

import sys
# If pydhcplib isn't fully installed, we need to extend the module search path.
sys.path.append('../pydhcplib/pydhcplib')

from dhcprequestor import request_ip

def random_mac():
  return "52:54:00:fb:%02x:%02x" % (random.randint(0,255), random.randint(0,255))

REQUESTOR_IP = "192.168.102.5"
SERVER_IPS = ["192.168.101.2"]
#mac = random_mac()
mac = "52:54:00:fb:38:8b"

print "Requesting IP address for %s ..." % mac
result = request_ip(mac_addr=mac, local_ip=REQUESTOR_IP,
        server_ips=SERVER_IPS)
if result is not None:
    print result
else:
    print "FAILED"
