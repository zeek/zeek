:tocdepth: 3

base/frameworks/packet-filter/netstats.bro
==========================================
.. bro:namespace:: PacketFilter

This script reports on packet loss from the various packet sources.
When Bro is reading input from trace files, this script will not
report any packet loss statistics.

:Namespace: PacketFilter
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Constants
#########
======================================================================= ==============================================================
:bro:id:`PacketFilter::stats_collection_interval`: :bro:type:`interval` This is the interval between individual statistics collection.
======================================================================= ==============================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: PacketFilter::stats_collection_interval

   :Type: :bro:type:`interval`
   :Default: ``5.0 mins``

   This is the interval between individual statistics collection.


