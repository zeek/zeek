:tocdepth: 3

base/bif/pcap.bif.zeek
======================
.. bro:namespace:: GLOBAL
.. bro:namespace:: Pcap


:Namespaces: GLOBAL, Pcap

Summary
~~~~~~~
Functions
#########
============================================================ =============================================================
:bro:id:`Pcap::error`: :bro:type:`function`                  Returns a string representation of the last PCAP error.
:bro:id:`Pcap::install_pcap_filter`: :bro:type:`function`    Installs a PCAP filter that has been precompiled with
                                                             :bro:id:`Pcap::precompile_pcap_filter`.
:bro:id:`Pcap::precompile_pcap_filter`: :bro:type:`function` Precompiles a PCAP filter and binds it to a given identifier.
============================================================ =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Pcap::error

   :Type: :bro:type:`function` () : :bro:type:`string`

   Returns a string representation of the last PCAP error.
   

   :returns: A descriptive error message of the PCAP function that failed.
   
   .. bro:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_addr_filter
                install_src_net_filter
                uninstall_src_addr_filter
                uninstall_src_net_filter
                install_dst_addr_filter
                install_dst_net_filter
                uninstall_dst_addr_filter
                uninstall_dst_net_filter

.. bro:id:: Pcap::install_pcap_filter

   :Type: :bro:type:`function` (id: :bro:type:`PcapFilterID`) : :bro:type:`bool`

   Installs a PCAP filter that has been precompiled with
   :bro:id:`Pcap::precompile_pcap_filter`.
   

   :id: The PCAP filter id of a precompiled filter.
   

   :returns: True if the filter associated with *id* has been installed
            successfully.
   
   .. bro:see:: Pcap::precompile_pcap_filter
                install_src_addr_filter
                install_src_net_filter
                uninstall_src_addr_filter
                uninstall_src_net_filter
                install_dst_addr_filter
                install_dst_net_filter
                uninstall_dst_addr_filter
                uninstall_dst_net_filter
                Pcap::error

.. bro:id:: Pcap::precompile_pcap_filter

   :Type: :bro:type:`function` (id: :bro:type:`PcapFilterID`, s: :bro:type:`string`) : :bro:type:`bool`

   Precompiles a PCAP filter and binds it to a given identifier.
   

   :id: The PCAP identifier to reference the filter *s* later on.
   

   :s: The PCAP filter. See ``man tcpdump`` for valid expressions.
   

   :returns: True if *s* is valid and precompiles successfully.
   
   .. bro:see:: Pcap::install_pcap_filter
            install_src_addr_filter
            install_src_net_filter
            uninstall_src_addr_filter
            uninstall_src_net_filter
            install_dst_addr_filter
            install_dst_net_filter
            uninstall_dst_addr_filter
            uninstall_dst_net_filter
            Pcap::error


