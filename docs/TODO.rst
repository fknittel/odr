Planned features / unsolved issues / wishlist items
===================================================

* On odrd start: Disconnect all OpenVPN clients that are without
  virtual_address. They were probably in the process of negotiating an address
  via odrd before odrd's restart.

* Do not disconnect clients for which the DHCP refresh does not work at rebind
  time.  Retry a few times before the lease time out and only disconnect if
  all fails and the timeout is reached / would be reached.  (This is important
  to avoid disconnecting clients due to intermittant DHCP server failures.)

* Improve logging:
  + Info messages concerning connects and full_username, IP-address and VLAN-ID.
  + Info messages concerning refreshs and disconnects.
  + Debug logging to stderr, while info and above goes to syslog.

* Refactor ovpn code that requests fresh leases / renews leases. (Avoid
  spreading the code across OvpnClient, OvpnClientManager and OvpnCmdConn)

* Try to implement some mechanism to determine if an IP address is already in
  use (especially by non-OpenVPN users).

  + Use ARP resolve / ARP ping to determine whether an IP address is in use.
  + Communicate with other odr instances to determine whether the
    full_username is known as an active client to someone.
  + If IP active, but full_username unknown to odr instances → non-OpenVPN
    user using the address → request a different address.
    Otherwise the same full_username is active on several instances → kill
    it on the older instance.
  + A delay of at least 10 seconds should be inserted after a DHCPDECLINE,
    before requesting a new address (RFC 2131, p.17).

* Release DHCP leases on coordinated disconnect.

  + Probably not possible, because there's no such thing as a coordinated
    disconnect in OpenVPN.

* Send DHCPREQUEST to all servers that were initially contacted.  This tells
  the servers that are not mentioned in the 'server identifier' field of the
  DHCPREQUEST, that the IP addresses they potentially offered may be freed
  again. (Compare with RFC 2131, page 16, section 3.1, points 3 and 4.)
  (This is optional though, as servers must time-out such offers themselves.)

* Port to Python 3
