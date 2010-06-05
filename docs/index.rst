OpenVPN DHCP requestor
======================

Introduction
------------

The OpenVPN DHCP requestor manages DHCP requests for OpenVPN client connect
events.  This allows easy IP assignment across many OpenVPN servers, as the
assignments are tracked centrally by the DHCP servers, which can also
provide redundancy.  No persistent state needs to be saved across restarts
of the daemon.

Features
--------

* Automatic configuration passing for OpenVPN client connections.

  + Push settings like the client's IP address as obtained by a DHCP
    server.  This allows for IP assignment on all client operating systems,
    as the client does not need to run an own DHCP client.
  + Different realms can be used to put clients into different VLANs,
    thus allowing one server to serve a central VPN hub to multiple secured
    networks.  

* Tracking of client connections, refreshing leases as appropriate.

* Helping OpenVPN to scale.  The IP address tracking is moved from the
  OpenVPN concentrator to the DHCP servers, thus allowing multiple servers
  sharing the same subnet through bridging to be load-balanced easily.
  It does not matter where the client reconnects to, as it will get
  assigned the same IP as before and will be able to continue to communicate
  as before as if nothing happened.

How does it work?
-----------------

Requirements
------------

odr requires Python 2.4 or above and the following libraries:

* pydhcplib
* python-prctl
* python-fdsend
* netifaces

odr does not implement any daemonization.  A daemon tool like runit is thus
strongly recommended.

API Documentation
-----------------

Per-module :mod:`odr` API documentation.

.. toctree::
   :maxdepth: 2

   api/dhcprequestor.rst
   api/cmdconnection.rst
   TODO.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

