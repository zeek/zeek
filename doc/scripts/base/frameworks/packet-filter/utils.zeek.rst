:tocdepth: 3

base/frameworks/packet-filter/utils.zeek
========================================
.. zeek:namespace:: PacketFilter


:Namespace: PacketFilter

Summary
~~~~~~~
Functions
#########
=============================================================== ==================================================================
:zeek:id:`PacketFilter::combine_filters`: :zeek:type:`function` Combines two valid BPF filter strings with a string based operator
                                                                to form a new filter.
:zeek:id:`PacketFilter::port_to_bpf`: :zeek:type:`function`     Takes a :zeek:type:`port` and returns a BPF expression which will
                                                                match the port.
:zeek:id:`PacketFilter::sampling_filter`: :zeek:type:`function` Create a BPF filter to sample IPv4 and IPv6 traffic.
=============================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: PacketFilter::combine_filters
   :source-code: base/frameworks/packet-filter/utils.zeek 40 50

   :Type: :zeek:type:`function` (lfilter: :zeek:type:`string`, op: :zeek:type:`string`, rfilter: :zeek:type:`string`) : :zeek:type:`string`

   Combines two valid BPF filter strings with a string based operator
   to form a new filter.
   

   :param lfilter: Filter which will go on the left side.
   

   :param op: Operation being applied (typically "or" or "and").
   

   :param rfilter: Filter which will go on the right side.
   

   :returns: A new string representing the two filters combined with
            the operator.  Either filter being an empty string will
            still result in a valid filter.

.. zeek:id:: PacketFilter::port_to_bpf
   :source-code: base/frameworks/packet-filter/utils.zeek 34 38

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`string`

   Takes a :zeek:type:`port` and returns a BPF expression which will
   match the port.
   

   :param p: The port.
   

   :returns: A valid BPF filter string for matching the port.

.. zeek:id:: PacketFilter::sampling_filter
   :source-code: base/frameworks/packet-filter/utils.zeek 52 58

   :Type: :zeek:type:`function` (num_parts: :zeek:type:`count`, this_part: :zeek:type:`count`) : :zeek:type:`string`

   Create a BPF filter to sample IPv4 and IPv6 traffic.
   

   :param num_parts: The number of parts the traffic should be split into.
   

   :param this_part: The part of the traffic this filter will accept (0-based).


