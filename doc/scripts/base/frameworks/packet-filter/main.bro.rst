:tocdepth: 3

base/frameworks/packet-filter/main.bro
======================================
.. bro:namespace:: PacketFilter

This script supports how Bro sets its BPF capture filter.  By default
Bro sets a capture filter that allows all traffic.  If a filter
is set on the command line, that filter takes precedence over the default
open filter and all filters defined in Bro scripts with the
:bro:id:`capture_filters` and :bro:id:`restrict_filters` variables.

:Namespace: PacketFilter
:Imports: :doc:`base/frameworks/analyzer </scripts/base/frameworks/analyzer/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/packet-filter/utils.bro </scripts/base/frameworks/packet-filter/utils.bro>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================= ===============================================================================
:bro:id:`PacketFilter::default_capture_filter`: :bro:type:`string` :bro:attr:`&redef`             The BPF filter that is used by default to define what traffic should
                                                                                                  be captured.
:bro:id:`PacketFilter::enable_auto_protocol_capture_filters`: :bro:type:`bool` :bro:attr:`&redef` Enables the old filtering approach of "only watch common ports for
                                                                                                  analyzed protocols".
:bro:id:`PacketFilter::max_filter_compile_time`: :bro:type:`interval` :bro:attr:`&redef`          The maximum amount of time that you'd like to allow for BPF filters to compile.
:bro:id:`PacketFilter::restricted_filter`: :bro:type:`string` :bro:attr:`&redef`                  Filter string which is unconditionally and'ed to the beginning of
                                                                                                  every dynamically built filter.
:bro:id:`PacketFilter::unrestricted_filter`: :bro:type:`string` :bro:attr:`&redef`                Filter string which is unconditionally or'ed to the beginning of
                                                                                                  every dynamically built filter.
================================================================================================= ===============================================================================

State Variables
###############
========================================================== ===================================================================
:bro:id:`PacketFilter::current_filter`: :bro:type:`string` This is where the default packet filter is stored and it should not
                                                           normally be modified by users.
========================================================== ===================================================================

Types
#####
========================================================== ==================================================================
:bro:type:`PacketFilter::FilterPlugin`: :bro:type:`record` A data structure to represent filter generating plugins.
:bro:type:`PacketFilter::Info`: :bro:type:`record`         The record type defining columns to be logged in the packet filter
                                                           logging stream.
========================================================== ==================================================================

Redefinitions
#############
========================================== =================================================
:bro:type:`Log::ID`: :bro:type:`enum`      Add the packet filter logging stream.
:bro:type:`Notice::Type`: :bro:type:`enum` Add notice types related to packet filter errors.
:bro:type:`PcapFilterID`: :bro:type:`enum` 
========================================== =================================================

Functions
#########
==================================================================== ======================================================================
:bro:id:`PacketFilter::exclude`: :bro:type:`function`                Install a BPF filter to exclude some traffic.
:bro:id:`PacketFilter::exclude_for`: :bro:type:`function`            Install a temporary filter to traffic which should not be passed
                                                                     through the BPF filter.
:bro:id:`PacketFilter::install`: :bro:type:`function`                Call this function to build and install a new dynamically built
                                                                     packet filter.
:bro:id:`PacketFilter::register_filter_plugin`: :bro:type:`function` API function to register a new plugin for dynamic restriction filters.
==================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: PacketFilter::default_capture_filter

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"ip or not ip"``

   The BPF filter that is used by default to define what traffic should
   be captured.  Filters defined in :bro:id:`restrict_filters` will
   still be applied to reduce the captured traffic.

.. bro:id:: PacketFilter::enable_auto_protocol_capture_filters

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Enables the old filtering approach of "only watch common ports for
   analyzed protocols".
   
   Unless you know what you are doing, leave this set to F.

.. bro:id:: PacketFilter::max_filter_compile_time

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``100.0 msecs``

   The maximum amount of time that you'd like to allow for BPF filters to compile.
   If this time is exceeded, compensation measures may be taken by the framework
   to reduce the filter size.  This threshold being crossed also results
   in the :bro:see:`PacketFilter::Too_Long_To_Compile_Filter` notice.

.. bro:id:: PacketFilter::restricted_filter

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Filter string which is unconditionally and'ed to the beginning of
   every dynamically built filter.  This is mostly used when a custom
   filter is being used but MPLS or VLAN tags are on the traffic.

.. bro:id:: PacketFilter::unrestricted_filter

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Filter string which is unconditionally or'ed to the beginning of
   every dynamically built filter.

State Variables
###############
.. bro:id:: PacketFilter::current_filter

   :Type: :bro:type:`string`
   :Default: ``"<not set yet>"``

   This is where the default packet filter is stored and it should not
   normally be modified by users.

Types
#####
.. bro:type:: PacketFilter::FilterPlugin

   :Type: :bro:type:`record`

      func: :bro:type:`function` () : :bro:type:`void`
         A function that is directly called when generating the complete filter.

   A data structure to represent filter generating plugins.

.. bro:type:: PacketFilter::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The time at which the packet filter installation attempt was made.

      node: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         This is a string representation of the node that applied this
         packet filter.  It's mostly useful in the context of
         dynamically changing filters on clusters.

      filter: :bro:type:`string` :bro:attr:`&log`
         The packet filter that is being set.

      init: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Indicate if this is the filter set during initialization.

      success: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Indicate if the filter was applied successfully.

   The record type defining columns to be logged in the packet filter
   logging stream.

Functions
#########
.. bro:id:: PacketFilter::exclude

   :Type: :bro:type:`function` (filter_id: :bro:type:`string`, filter: :bro:type:`string`) : :bro:type:`bool`

   Install a BPF filter to exclude some traffic.  The filter should
   positively match what is to be excluded, it will be wrapped in
   a "not".
   

   :filter_id: An arbitrary string that can be used to identify
              the filter.
   

   :filter: A BPF expression of traffic that should be excluded.
   

   :returns: A boolean value to indicate if the filter was successfully
            installed or not.

.. bro:id:: PacketFilter::exclude_for

   :Type: :bro:type:`function` (filter_id: :bro:type:`string`, filter: :bro:type:`string`, span: :bro:type:`interval`) : :bro:type:`bool`

   Install a temporary filter to traffic which should not be passed
   through the BPF filter.  The filter should match the traffic you
   don't want to see (it will be wrapped in a "not" condition).
   

   :filter_id: An arbitrary string that can be used to identify
              the filter.
   

   :filter: A BPF expression of traffic that should be excluded.
   

   :length: The duration for which this filter should be put in place.
   

   :returns: A boolean value to indicate if the filter was successfully
            installed or not.

.. bro:id:: PacketFilter::install

   :Type: :bro:type:`function` () : :bro:type:`bool`

   Call this function to build and install a new dynamically built
   packet filter.

.. bro:id:: PacketFilter::register_filter_plugin

   :Type: :bro:type:`function` (fp: :bro:type:`PacketFilter::FilterPlugin`) : :bro:type:`void`

   API function to register a new plugin for dynamic restriction filters.


