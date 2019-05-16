:tocdepth: 3

base/frameworks/packet-filter/main.zeek
=======================================
.. zeek:namespace:: PacketFilter

This script supports how Zeek sets its BPF capture filter.  By default
Zeek sets a capture filter that allows all traffic.  If a filter
is set on the command line, that filter takes precedence over the default
open filter and all filters defined in Zeek scripts with the
:zeek:id:`capture_filters` and :zeek:id:`restrict_filters` variables.

:Namespace: PacketFilter
:Imports: :doc:`base/frameworks/analyzer </scripts/base/frameworks/analyzer/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/packet-filter/utils.zeek </scripts/base/frameworks/packet-filter/utils.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
==================================================================================================== ===============================================================================
:zeek:id:`PacketFilter::default_capture_filter`: :zeek:type:`string` :zeek:attr:`&redef`             The BPF filter that is used by default to define what traffic should
                                                                                                     be captured.
:zeek:id:`PacketFilter::enable_auto_protocol_capture_filters`: :zeek:type:`bool` :zeek:attr:`&redef` Enables the old filtering approach of "only watch common ports for
                                                                                                     analyzed protocols".
:zeek:id:`PacketFilter::max_filter_compile_time`: :zeek:type:`interval` :zeek:attr:`&redef`          The maximum amount of time that you'd like to allow for BPF filters to compile.
:zeek:id:`PacketFilter::restricted_filter`: :zeek:type:`string` :zeek:attr:`&redef`                  Filter string which is unconditionally and'ed to the beginning of
                                                                                                     every dynamically built filter.
:zeek:id:`PacketFilter::unrestricted_filter`: :zeek:type:`string` :zeek:attr:`&redef`                Filter string which is unconditionally or'ed to the beginning of
                                                                                                     every dynamically built filter.
==================================================================================================== ===============================================================================

State Variables
###############
============================================================ ===================================================================
:zeek:id:`PacketFilter::current_filter`: :zeek:type:`string` This is where the default packet filter is stored and it should not
                                                             normally be modified by users.
============================================================ ===================================================================

Types
#####
============================================================ ==================================================================
:zeek:type:`PacketFilter::FilterPlugin`: :zeek:type:`record` A data structure to represent filter generating plugins.
:zeek:type:`PacketFilter::Info`: :zeek:type:`record`         The record type defining columns to be logged in the packet filter
                                                             logging stream.
============================================================ ==================================================================

Redefinitions
#############
============================================ =================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      Add the packet filter logging stream.
:zeek:type:`Notice::Type`: :zeek:type:`enum` Add notice types related to packet filter errors.
:zeek:type:`PcapFilterID`: :zeek:type:`enum` 
============================================ =================================================

Functions
#########
====================================================================== ======================================================================
:zeek:id:`PacketFilter::exclude`: :zeek:type:`function`                Install a BPF filter to exclude some traffic.
:zeek:id:`PacketFilter::exclude_for`: :zeek:type:`function`            Install a temporary filter to traffic which should not be passed
                                                                       through the BPF filter.
:zeek:id:`PacketFilter::install`: :zeek:type:`function`                Call this function to build and install a new dynamically built
                                                                       packet filter.
:zeek:id:`PacketFilter::register_filter_plugin`: :zeek:type:`function` API function to register a new plugin for dynamic restriction filters.
====================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketFilter::default_capture_filter

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"ip or not ip"``

   The BPF filter that is used by default to define what traffic should
   be captured.  Filters defined in :zeek:id:`restrict_filters` will
   still be applied to reduce the captured traffic.

.. zeek:id:: PacketFilter::enable_auto_protocol_capture_filters

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Enables the old filtering approach of "only watch common ports for
   analyzed protocols".
   
   Unless you know what you are doing, leave this set to F.

.. zeek:id:: PacketFilter::max_filter_compile_time

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100.0 msecs``

   The maximum amount of time that you'd like to allow for BPF filters to compile.
   If this time is exceeded, compensation measures may be taken by the framework
   to reduce the filter size.  This threshold being crossed also results
   in the :zeek:see:`PacketFilter::Too_Long_To_Compile_Filter` notice.

.. zeek:id:: PacketFilter::restricted_filter

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Filter string which is unconditionally and'ed to the beginning of
   every dynamically built filter.  This is mostly used when a custom
   filter is being used but MPLS or VLAN tags are on the traffic.

.. zeek:id:: PacketFilter::unrestricted_filter

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Filter string which is unconditionally or'ed to the beginning of
   every dynamically built filter.

State Variables
###############
.. zeek:id:: PacketFilter::current_filter

   :Type: :zeek:type:`string`
   :Default: ``"<not set yet>"``

   This is where the default packet filter is stored and it should not
   normally be modified by users.

Types
#####
.. zeek:type:: PacketFilter::FilterPlugin

   :Type: :zeek:type:`record`

      func: :zeek:type:`function` () : :zeek:type:`void`
         A function that is directly called when generating the complete filter.

   A data structure to represent filter generating plugins.

.. zeek:type:: PacketFilter::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The time at which the packet filter installation attempt was made.

      node: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         This is a string representation of the node that applied this
         packet filter.  It's mostly useful in the context of
         dynamically changing filters on clusters.

      filter: :zeek:type:`string` :zeek:attr:`&log`
         The packet filter that is being set.

      init: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Indicate if this is the filter set during initialization.

      success: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Indicate if the filter was applied successfully.

   The record type defining columns to be logged in the packet filter
   logging stream.

Functions
#########
.. zeek:id:: PacketFilter::exclude

   :Type: :zeek:type:`function` (filter_id: :zeek:type:`string`, filter: :zeek:type:`string`) : :zeek:type:`bool`

   Install a BPF filter to exclude some traffic.  The filter should
   positively match what is to be excluded, it will be wrapped in
   a "not".
   

   :filter_id: An arbitrary string that can be used to identify
              the filter.
   

   :filter: A BPF expression of traffic that should be excluded.
   

   :returns: A boolean value to indicate if the filter was successfully
            installed or not.

.. zeek:id:: PacketFilter::exclude_for

   :Type: :zeek:type:`function` (filter_id: :zeek:type:`string`, filter: :zeek:type:`string`, span: :zeek:type:`interval`) : :zeek:type:`bool`

   Install a temporary filter to traffic which should not be passed
   through the BPF filter.  The filter should match the traffic you
   don't want to see (it will be wrapped in a "not" condition).
   

   :filter_id: An arbitrary string that can be used to identify
              the filter.
   

   :filter: A BPF expression of traffic that should be excluded.
   

   :length: The duration for which this filter should be put in place.
   

   :returns: A boolean value to indicate if the filter was successfully
            installed or not.

.. zeek:id:: PacketFilter::install

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Call this function to build and install a new dynamically built
   packet filter.

.. zeek:id:: PacketFilter::register_filter_plugin

   :Type: :zeek:type:`function` (fp: :zeek:type:`PacketFilter::FilterPlugin`) : :zeek:type:`void`

   API function to register a new plugin for dynamic restriction filters.


