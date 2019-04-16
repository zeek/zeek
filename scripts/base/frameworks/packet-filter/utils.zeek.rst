:tocdepth: 3

base/frameworks/packet-filter/utils.zeek
========================================
.. bro:namespace:: PacketFilter


:Namespace: PacketFilter

Summary
~~~~~~~
Functions
#########
============================================================= ==================================================================
:bro:id:`PacketFilter::combine_filters`: :bro:type:`function` Combines two valid BPF filter strings with a string based operator
                                                              to form a new filter.
:bro:id:`PacketFilter::port_to_bpf`: :bro:type:`function`     Takes a :bro:type:`port` and returns a BPF expression which will
                                                              match the port.
:bro:id:`PacketFilter::sampling_filter`: :bro:type:`function` Create a BPF filter to sample IPv4 and IPv6 traffic.
============================================================= ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: PacketFilter::combine_filters

   :Type: :bro:type:`function` (lfilter: :bro:type:`string`, op: :bro:type:`string`, rfilter: :bro:type:`string`) : :bro:type:`string`

   Combines two valid BPF filter strings with a string based operator
   to form a new filter.
   

   :lfilter: Filter which will go on the left side.
   

   :op: Operation being applied (typically "or" or "and").
   

   :rfilter: Filter which will go on the right side.
   

   :returns: A new string representing the two filters combined with
            the operator.  Either filter being an empty string will
            still result in a valid filter.

.. bro:id:: PacketFilter::port_to_bpf

   :Type: :bro:type:`function` (p: :bro:type:`port`) : :bro:type:`string`

   Takes a :bro:type:`port` and returns a BPF expression which will
   match the port.
   

   :p: The port.
   

   :returns: A valid BPF filter string for matching the port.

.. bro:id:: PacketFilter::sampling_filter

   :Type: :bro:type:`function` (num_parts: :bro:type:`count`, this_part: :bro:type:`count`) : :bro:type:`string`

   Create a BPF filter to sample IPv4 and IPv6 traffic.
   

   :num_parts: The number of parts the traffic should be split into.
   

   :this_part: The part of the traffic this filter will accept (0-based).


