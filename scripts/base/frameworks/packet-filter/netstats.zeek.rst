:tocdepth: 3

base/frameworks/packet-filter/netstats.zeek
===========================================
.. zeek:namespace:: PacketFilter

This script reports on packet loss from the various packet sources.
When Bro is reading input from trace files, this script will not
report any packet loss statistics.

:Namespace: PacketFilter
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Constants
#########
========================================================================= ==============================================================
:zeek:id:`PacketFilter::stats_collection_interval`: :zeek:type:`interval` This is the interval between individual statistics collection.
========================================================================= ==============================================================

Redefinitions
#############
============================================ =
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: PacketFilter::stats_collection_interval

   :Type: :zeek:type:`interval`
   :Default: ``5.0 mins``

   This is the interval between individual statistics collection.


