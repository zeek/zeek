:tocdepth: 3

base/init-bare.zeek
===================
.. zeek:namespace:: BinPAC
.. zeek:namespace:: Cluster
.. zeek:namespace:: DCE_RPC
.. zeek:namespace:: DHCP
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: JSON
.. zeek:namespace:: KRB
.. zeek:namespace:: MOUNT3
.. zeek:namespace:: MQTT
.. zeek:namespace:: NCP
.. zeek:namespace:: NFS3
.. zeek:namespace:: NTLM
.. zeek:namespace:: NTP
.. zeek:namespace:: PE
.. zeek:namespace:: Pcap
.. zeek:namespace:: RADIUS
.. zeek:namespace:: RDP
.. zeek:namespace:: Reporter
.. zeek:namespace:: SMB
.. zeek:namespace:: SMB1
.. zeek:namespace:: SMB2
.. zeek:namespace:: SNMP
.. zeek:namespace:: SOCKS
.. zeek:namespace:: SSH
.. zeek:namespace:: SSL
.. zeek:namespace:: TCP
.. zeek:namespace:: Threading
.. zeek:namespace:: Tunnel
.. zeek:namespace:: Unified2
.. zeek:namespace:: Weird
.. zeek:namespace:: X509


:Namespaces: BinPAC, Cluster, DCE_RPC, DHCP, GLOBAL, JSON, KRB, MOUNT3, MQTT, NCP, NFS3, NTLM, NTP, PE, Pcap, RADIUS, RDP, Reporter, SMB, SMB1, SMB2, SNMP, SOCKS, SSH, SSL, TCP, Threading, Tunnel, Unified2, Weird, X509
:Imports: :doc:`base/bif/const.bif.zeek </scripts/base/bif/const.bif.zeek>`, :doc:`base/bif/event.bif.zeek </scripts/base/bif/event.bif.zeek>`, :doc:`base/bif/option.bif.zeek </scripts/base/bif/option.bif.zeek>`, :doc:`base/bif/plugins/Zeek_KRB.types.bif.zeek </scripts/base/bif/plugins/Zeek_KRB.types.bif.zeek>`, :doc:`base/bif/plugins/Zeek_SNMP.types.bif.zeek </scripts/base/bif/plugins/Zeek_SNMP.types.bif.zeek>`, :doc:`base/bif/reporter.bif.zeek </scripts/base/bif/reporter.bif.zeek>`, :doc:`base/bif/stats.bif.zeek </scripts/base/bif/stats.bif.zeek>`, :doc:`base/bif/strings.bif.zeek </scripts/base/bif/strings.bif.zeek>`, :doc:`base/bif/supervisor.bif.zeek </scripts/base/bif/supervisor.bif.zeek>`, :doc:`base/bif/types.bif.zeek </scripts/base/bif/types.bif.zeek>`, :doc:`base/bif/zeek.bif.zeek </scripts/base/bif/zeek.bif.zeek>`, :doc:`base/frameworks/supervisor/api.zeek </scripts/base/frameworks/supervisor/api.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================================== ======================================================================
:zeek:id:`MQTT::max_payload_size`: :zeek:type:`count` :zeek:attr:`&redef`           The maximum payload size to allocate for the purpose of
                                                                                    payload information in :zeek:see:`mqtt_publish` events (and the
                                                                                    default MQTT logs generated from that).
:zeek:id:`Weird::sampling_duration`: :zeek:type:`interval` :zeek:attr:`&redef`      How long a weird of a given type is allowed to keep state/counters in
                                                                                    memory.
:zeek:id:`Weird::sampling_rate`: :zeek:type:`count` :zeek:attr:`&redef`             The rate-limiting sampling rate.
:zeek:id:`Weird::sampling_threshold`: :zeek:type:`count` :zeek:attr:`&redef`        How many weirds of a given type to tolerate before sampling begins.
:zeek:id:`Weird::sampling_whitelist`: :zeek:type:`set` :zeek:attr:`&redef`          Prevents rate-limiting sampling of any weirds named in the table.
:zeek:id:`default_file_bof_buffer_size`: :zeek:type:`count` :zeek:attr:`&redef`     Default amount of bytes that file analysis will buffer in order to use
                                                                                    for mime type matching.
:zeek:id:`default_file_timeout_interval`: :zeek:type:`interval` :zeek:attr:`&redef` Default amount of time a file can be inactive before the file analysis
                                                                                    gives up and discards any internal state related to the file.
=================================================================================== ======================================================================

Redefinable Options
###################
========================================================================================== ================================================================================
:zeek:id:`BinPAC::flowbuffer_capacity_max`: :zeek:type:`count` :zeek:attr:`&redef`         Maximum capacity, in bytes, that the BinPAC flowbuffer is allowed to
                                                                                           grow to for use with incremental parsing of a given connection/analyzer.
:zeek:id:`BinPAC::flowbuffer_capacity_min`: :zeek:type:`count` :zeek:attr:`&redef`         The initial capacity, in bytes, that will be allocated to the BinPAC
                                                                                           flowbuffer of a given connection/analyzer.
:zeek:id:`BinPAC::flowbuffer_contract_threshold`: :zeek:type:`count` :zeek:attr:`&redef`   The threshold, in bytes, at which the BinPAC flowbuffer of a given
                                                                                           connection/analyzer will have its capacity contracted to
                                                                                           :zeek:see:`BinPAC::flowbuffer_capacity_min` after parsing a full unit.
:zeek:id:`DCE_RPC::max_cmd_reassembly`: :zeek:type:`count` :zeek:attr:`&redef`             The maximum number of simultaneous fragmented commands that
                                                                                           the DCE_RPC analyzer will tolerate before the it will generate
                                                                                           a weird and skip further input.
:zeek:id:`DCE_RPC::max_frag_data`: :zeek:type:`count` :zeek:attr:`&redef`                  The maximum number of fragmented bytes that the DCE_RPC analyzer
                                                                                           will tolerate on a command before the analyzer will generate a weird
                                                                                           and skip further input.
:zeek:id:`KRB::keytab`: :zeek:type:`string` :zeek:attr:`&redef`                            Kerberos keytab file name.
:zeek:id:`NCP::max_frame_size`: :zeek:type:`count` :zeek:attr:`&redef`                     The maximum number of bytes to allocate when parsing NCP frames.
:zeek:id:`NFS3::return_data`: :zeek:type:`bool` :zeek:attr:`&redef`                        If true, :zeek:see:`nfs_proc_read` and :zeek:see:`nfs_proc_write`
                                                                                           events return the file data that has been read/written.
:zeek:id:`NFS3::return_data_first_only`: :zeek:type:`bool` :zeek:attr:`&redef`             If :zeek:id:`NFS3::return_data` is true, whether to *only* return data
                                                                                           if the read or write offset is 0, i.e., only return data for the
                                                                                           beginning of the file.
:zeek:id:`NFS3::return_data_max`: :zeek:type:`count` :zeek:attr:`&redef`                   If :zeek:id:`NFS3::return_data` is true, how much data should be
                                                                                           returned at most.
:zeek:id:`Pcap::bufsize`: :zeek:type:`count` :zeek:attr:`&redef`                           Number of Mbytes to provide as buffer space when capturing from live
                                                                                           interfaces.
:zeek:id:`Pcap::snaplen`: :zeek:type:`count` :zeek:attr:`&redef`                           Number of bytes per packet to capture from live interfaces.
:zeek:id:`Reporter::errors_to_stderr`: :zeek:type:`bool` :zeek:attr:`&redef`               Tunable for sending reporter error messages to STDERR.
:zeek:id:`Reporter::info_to_stderr`: :zeek:type:`bool` :zeek:attr:`&redef`                 Tunable for sending reporter info messages to STDERR.
:zeek:id:`Reporter::warnings_to_stderr`: :zeek:type:`bool` :zeek:attr:`&redef`             Tunable for sending reporter warning messages to STDERR.
:zeek:id:`SMB::pipe_filenames`: :zeek:type:`set` :zeek:attr:`&redef`                       A set of file names used as named pipes over SMB.
:zeek:id:`SSL::dtls_max_reported_version_errors`: :zeek:type:`count` :zeek:attr:`&redef`   Maximum number of invalid version errors to report in one DTLS connection.
:zeek:id:`SSL::dtls_max_version_errors`: :zeek:type:`count` :zeek:attr:`&redef`            Number of non-DTLS frames that can occur in a DTLS connection before
                                                                                           parsing of the connection is suspended.
:zeek:id:`Threading::heartbeat_interval`: :zeek:type:`interval` :zeek:attr:`&redef`        The heartbeat interval used by the threading framework.
:zeek:id:`Tunnel::delay_gtp_confirmation`: :zeek:type:`bool` :zeek:attr:`&redef`           With this set, the GTP analyzer waits until the most-recent upflow
                                                                                           and downflow packets are a valid GTPv1 encapsulation before
                                                                                           issuing :zeek:see:`protocol_confirmation`.
:zeek:id:`Tunnel::delay_teredo_confirmation`: :zeek:type:`bool` :zeek:attr:`&redef`        With this set, the Teredo analyzer waits until it sees both sides
                                                                                           of a connection using a valid Teredo encapsulation before issuing
                                                                                           a :zeek:see:`protocol_confirmation`.
:zeek:id:`Tunnel::enable_ayiya`: :zeek:type:`bool` :zeek:attr:`&redef`                     Toggle whether to do IPv{4,6}-in-AYIYA decapsulation.
:zeek:id:`Tunnel::enable_gre`: :zeek:type:`bool` :zeek:attr:`&redef`                       Toggle whether to do GRE decapsulation.
:zeek:id:`Tunnel::enable_gtpv1`: :zeek:type:`bool` :zeek:attr:`&redef`                     Toggle whether to do GTPv1 decapsulation.
:zeek:id:`Tunnel::enable_ip`: :zeek:type:`bool` :zeek:attr:`&redef`                        Toggle whether to do IPv{4,6}-in-IPv{4,6} decapsulation.
:zeek:id:`Tunnel::enable_teredo`: :zeek:type:`bool` :zeek:attr:`&redef`                    Toggle whether to do IPv6-in-Teredo decapsulation.
:zeek:id:`Tunnel::ip_tunnel_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`            How often to cleanup internal state for inactive IP tunnels
                                                                                           (includes GRE tunnels).
:zeek:id:`Tunnel::max_depth`: :zeek:type:`count` :zeek:attr:`&redef`                       The maximum depth of a tunnel to decapsulate until giving up.
:zeek:id:`Tunnel::validate_vxlan_checksums`: :zeek:type:`bool` :zeek:attr:`&redef`         Whether to validate the checksum supplied in the outer UDP header
                                                                                           of a VXLAN encapsulation.
:zeek:id:`Tunnel::vxlan_ports`: :zeek:type:`set` :zeek:attr:`&redef`                       The set of UDP ports used for VXLAN traffic.
:zeek:id:`bits_per_uid`: :zeek:type:`count` :zeek:attr:`&redef`                            Number of bits in UIDs that are generated to identify connections and
                                                                                           files.
:zeek:id:`check_for_unused_event_handlers`: :zeek:type:`bool` :zeek:attr:`&redef`          If true, warns about unused event handlers at startup.
:zeek:id:`cmd_line_bpf_filter`: :zeek:type:`string` :zeek:attr:`&redef`                    BPF filter the user has set via the -f command line options.
:zeek:id:`detect_filtered_trace`: :zeek:type:`bool` :zeek:attr:`&redef`                    Whether to attempt to automatically detect SYN/FIN/RST-filtered trace
                                                                                           and not report missing segments for such connections.
:zeek:id:`dns_session_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`                  Time to wait before timing out a DNS request.
:zeek:id:`dpd_buffer_size`: :zeek:type:`count` :zeek:attr:`&redef`                         Size of per-connection buffer used for dynamic protocol detection.
:zeek:id:`dpd_ignore_ports`: :zeek:type:`bool` :zeek:attr:`&redef`                         If true, don't consider any ports for deciding which protocol analyzer to
                                                                                           use.
:zeek:id:`dpd_late_match_stop`: :zeek:type:`bool` :zeek:attr:`&redef`                      If true, stops signature matching after a late match.
:zeek:id:`dpd_match_only_beginning`: :zeek:type:`bool` :zeek:attr:`&redef`                 If true, stops signature matching if :zeek:see:`dpd_buffer_size` has been
                                                                                           reached.
:zeek:id:`dpd_reassemble_first_packets`: :zeek:type:`bool` :zeek:attr:`&redef`             Reassemble the beginning of all TCP connections before doing
                                                                                           signature matching.
:zeek:id:`encap_hdr_size`: :zeek:type:`count` :zeek:attr:`&redef`                          If positive, indicates the encapsulation header size that should
                                                                                           be skipped.
:zeek:id:`exit_only_after_terminate`: :zeek:type:`bool` :zeek:attr:`&redef`                Flag to prevent Zeek from exiting automatically when input is exhausted.
:zeek:id:`expensive_profiling_multiple`: :zeek:type:`count` :zeek:attr:`&redef`            Multiples of :zeek:see:`profiling_interval` at which (more expensive) memory
                                                                                           profiling is done (0 disables).
:zeek:id:`frag_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`                         How long to hold onto fragments for possible reassembly.
:zeek:id:`global_hash_seed`: :zeek:type:`string` :zeek:attr:`&redef`                       Seed for hashes computed internally for probabilistic data structures.
:zeek:id:`icmp_inactivity_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`              If an ICMP flow is inactive, time it out after this interval.
:zeek:id:`ignore_checksums`: :zeek:type:`bool` :zeek:attr:`&redef`                         If true, don't verify checksums.
:zeek:id:`ignore_keep_alive_rexmit`: :zeek:type:`bool` :zeek:attr:`&redef`                 Ignore certain TCP retransmissions for :zeek:see:`conn_stats`.
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef`                       Ports which the core considers being likely used by servers.
:zeek:id:`log_rotate_base_time`: :zeek:type:`string` :zeek:attr:`&redef`                   Base time of log rotations in 24-hour time format (``%H:%M``), e.g.
:zeek:id:`max_timer_expires`: :zeek:type:`count` :zeek:attr:`&redef`                       The maximum number of timers to expire after processing each new
                                                                                           packet.
:zeek:id:`mmdb_dir`: :zeek:type:`string` :zeek:attr:`&redef`                               The directory containing MaxMind DB (.mmdb) files to use for GeoIP support.
:zeek:id:`non_analyzed_lifetime`: :zeek:type:`interval` :zeek:attr:`&redef`                If a connection belongs to an application that we don't analyze,
                                                                                           time it out after this interval.
:zeek:id:`packet_filter_default`: :zeek:type:`bool` :zeek:attr:`&redef`                    Default mode for Zeek's user-space dynamic packet filter.
:zeek:id:`partial_connection_ok`: :zeek:type:`bool` :zeek:attr:`&redef`                    If true, instantiate connection state when a partial connection
                                                                                           (one missing its initial establishment negotiation) is seen.
:zeek:id:`peer_description`: :zeek:type:`string` :zeek:attr:`&redef`                       Description transmitted to remote communication peers for identification.
:zeek:id:`pkt_profile_freq`: :zeek:type:`double` :zeek:attr:`&redef`                       Frequency associated with packet profiling.
:zeek:id:`pkt_profile_mode`: :zeek:type:`pkt_profile_modes` :zeek:attr:`&redef`            Output mode for packet profiling information.
:zeek:id:`profiling_interval`: :zeek:type:`interval` :zeek:attr:`&redef`                   Update interval for profiling (0 disables).
:zeek:id:`record_all_packets`: :zeek:type:`bool` :zeek:attr:`&redef`                       If a trace file is given with ``-w``, dump *all* packets seen by Zeek into it.
:zeek:id:`report_gaps_for_partial`: :zeek:type:`bool` :zeek:attr:`&redef`                  Whether we want :zeek:see:`content_gap` for partial
                                                                                           connections.
:zeek:id:`rpc_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`                          Time to wait before timing out an RPC request.
:zeek:id:`segment_profiling`: :zeek:type:`bool` :zeek:attr:`&redef`                        If true, then write segment profiling information (very high volume!)
                                                                                           in addition to profiling statistics.
:zeek:id:`sig_max_group_size`: :zeek:type:`count` :zeek:attr:`&redef`                      Maximum size of regular expression groups for signature matching.
:zeek:id:`skip_http_data`: :zeek:type:`bool` :zeek:attr:`&redef`                           Skip HTTP data for performance considerations.
:zeek:id:`stp_delta`: :zeek:type:`interval` :zeek:attr:`&redef`                            Internal to the stepping stone detector.
:zeek:id:`stp_idle_min`: :zeek:type:`interval` :zeek:attr:`&redef`                         Internal to the stepping stone detector.
:zeek:id:`table_expire_delay`: :zeek:type:`interval` :zeek:attr:`&redef`                   When expiring table entries, wait this amount of time before checking the
                                                                                           next chunk of entries.
:zeek:id:`table_expire_interval`: :zeek:type:`interval` :zeek:attr:`&redef`                Check for expired table entries after this amount of time.
:zeek:id:`table_incremental_step`: :zeek:type:`count` :zeek:attr:`&redef`                  When expiring/serializing table entries, don't work on more than this many
                                                                                           table entries at a time.
:zeek:id:`tcp_SYN_ack_ok`: :zeek:type:`bool` :zeek:attr:`&redef`                           If true, instantiate connection state when a SYN/ACK is seen but not the
                                                                                           initial SYN (even if :zeek:see:`partial_connection_ok` is false).
:zeek:id:`tcp_SYN_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`                      Check up on the result of an initial SYN after this much time.
:zeek:id:`tcp_attempt_delay`: :zeek:type:`interval` :zeek:attr:`&redef`                    Wait this long upon seeing an initial SYN before timing out the
                                                                                           connection attempt.
:zeek:id:`tcp_close_delay`: :zeek:type:`interval` :zeek:attr:`&redef`                      Upon seeing a normal connection close, flush state after this much time.
:zeek:id:`tcp_connection_linger`: :zeek:type:`interval` :zeek:attr:`&redef`                When checking a closed connection for further activity, consider it
                                                                                           inactive if there hasn't been any for this long.
:zeek:id:`tcp_content_deliver_all_orig`: :zeek:type:`bool` :zeek:attr:`&redef`             If true, all TCP originator-side traffic is reported via
                                                                                           :zeek:see:`tcp_contents`.
:zeek:id:`tcp_content_deliver_all_resp`: :zeek:type:`bool` :zeek:attr:`&redef`             If true, all TCP responder-side traffic is reported via
                                                                                           :zeek:see:`tcp_contents`.
:zeek:id:`tcp_content_delivery_ports_orig`: :zeek:type:`table` :zeek:attr:`&redef`         Defines destination TCP ports for which the contents of the originator stream
                                                                                           should be delivered via :zeek:see:`tcp_contents`.
:zeek:id:`tcp_content_delivery_ports_resp`: :zeek:type:`table` :zeek:attr:`&redef`         Defines destination TCP ports for which the contents of the responder stream
                                                                                           should be delivered via :zeek:see:`tcp_contents`.
:zeek:id:`tcp_excessive_data_without_further_acks`: :zeek:type:`count` :zeek:attr:`&redef` If we've seen this much data without any of it being acked, we give up
                                                                                           on that connection to avoid memory exhaustion due to buffering all that
                                                                                           stuff.
:zeek:id:`tcp_inactivity_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`               If a TCP connection is inactive, time it out after this interval.
:zeek:id:`tcp_match_undelivered`: :zeek:type:`bool` :zeek:attr:`&redef`                    If true, pass any undelivered to the signature engine before flushing the state.
:zeek:id:`tcp_max_above_hole_without_any_acks`: :zeek:type:`count` :zeek:attr:`&redef`     If we're not seeing our peer's ACKs, the maximum volume of data above a
                                                                                           sequence hole that we'll tolerate before assuming that there's been a packet
                                                                                           drop and we should give up on tracking a connection.
:zeek:id:`tcp_max_initial_window`: :zeek:type:`count` :zeek:attr:`&redef`                  Maximum amount of data that might plausibly be sent in an initial flight
                                                                                           (prior to receiving any acks).
:zeek:id:`tcp_max_old_segments`: :zeek:type:`count` :zeek:attr:`&redef`                    Number of TCP segments to buffer beyond what's been acknowledged already
                                                                                           to detect retransmission inconsistencies.
:zeek:id:`tcp_partial_close_delay`: :zeek:type:`interval` :zeek:attr:`&redef`              Generate a :zeek:id:`connection_partial_close` event this much time after one
                                                                                           half of a partial connection closes, assuming there has been no subsequent
                                                                                           activity.
:zeek:id:`tcp_reassembler_ports_orig`: :zeek:type:`set` :zeek:attr:`&redef`                For services without a handler, these sets define originator-side ports
                                                                                           that still trigger reassembly.
:zeek:id:`tcp_reassembler_ports_resp`: :zeek:type:`set` :zeek:attr:`&redef`                For services without a handler, these sets define responder-side ports
                                                                                           that still trigger reassembly.
:zeek:id:`tcp_reset_delay`: :zeek:type:`interval` :zeek:attr:`&redef`                      Upon seeing a RST, flush state after this much time.
:zeek:id:`tcp_session_timer`: :zeek:type:`interval` :zeek:attr:`&redef`                    After a connection has closed, wait this long for further activity
                                                                                           before checking whether to time out its state.
:zeek:id:`tcp_storm_interarrival_thresh`: :zeek:type:`interval` :zeek:attr:`&redef`        FINs/RSTs must come with this much time or less between them to be
                                                                                           considered a "storm".
:zeek:id:`tcp_storm_thresh`: :zeek:type:`count` :zeek:attr:`&redef`                        Number of FINs/RSTs in a row that constitute a "storm".
:zeek:id:`time_machine_profiling`: :zeek:type:`bool` :zeek:attr:`&redef`                   If true, output profiling for Time-Machine queries.
:zeek:id:`timer_mgr_inactivity_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`         Per-incident timer managers are drained after this amount of inactivity.
:zeek:id:`truncate_http_URI`: :zeek:type:`int` :zeek:attr:`&redef`                         Maximum length of HTTP URIs passed to events.
:zeek:id:`udp_content_deliver_all_orig`: :zeek:type:`bool` :zeek:attr:`&redef`             If true, all UDP originator-side traffic is reported via
                                                                                           :zeek:see:`udp_contents`.
:zeek:id:`udp_content_deliver_all_resp`: :zeek:type:`bool` :zeek:attr:`&redef`             If true, all UDP responder-side traffic is reported via
                                                                                           :zeek:see:`udp_contents`.
:zeek:id:`udp_content_delivery_ports_orig`: :zeek:type:`table` :zeek:attr:`&redef`         Defines UDP destination ports for which the contents of the originator stream
                                                                                           should be delivered via :zeek:see:`udp_contents`.
:zeek:id:`udp_content_delivery_ports_resp`: :zeek:type:`table` :zeek:attr:`&redef`         Defines UDP destination ports for which the contents of the responder stream
                                                                                           should be delivered via :zeek:see:`udp_contents`.
:zeek:id:`udp_inactivity_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`               If a UDP flow is inactive, time it out after this interval.
:zeek:id:`use_conn_size_analyzer`: :zeek:type:`bool` :zeek:attr:`&redef`                   Whether to use the ``ConnSize`` analyzer to count the number of packets and
                                                                                           IP-level bytes transferred by each endpoint.
:zeek:id:`watchdog_interval`: :zeek:type:`interval` :zeek:attr:`&redef`                    Zeek's watchdog interval.
========================================================================================== ================================================================================

Constants
#########
=========================================================== =======================================================================
:zeek:id:`CONTENTS_BOTH`: :zeek:type:`count`                Record both originator and responder contents.
:zeek:id:`CONTENTS_NONE`: :zeek:type:`count`                Turn off recording of contents.
:zeek:id:`CONTENTS_ORIG`: :zeek:type:`count`                Record originator contents.
:zeek:id:`CONTENTS_RESP`: :zeek:type:`count`                Record responder contents.
:zeek:id:`DNS_ADDL`: :zeek:type:`count`                     An additional record.
:zeek:id:`DNS_ANS`: :zeek:type:`count`                      An answer record.
:zeek:id:`DNS_AUTH`: :zeek:type:`count`                     An authoritative record.
:zeek:id:`DNS_QUERY`: :zeek:type:`count`                    A query.
:zeek:id:`ENDIAN_BIG`: :zeek:type:`count`                   Big endian.
:zeek:id:`ENDIAN_CONFUSED`: :zeek:type:`count`              Tried to determine endian, but failed.
:zeek:id:`ENDIAN_LITTLE`: :zeek:type:`count`                Little endian.
:zeek:id:`ENDIAN_UNKNOWN`: :zeek:type:`count`               Endian not yet determined.
:zeek:id:`ICMP_UNREACH_ADMIN_PROHIB`: :zeek:type:`count`    Administratively prohibited.
:zeek:id:`ICMP_UNREACH_HOST`: :zeek:type:`count`            Host unreachable.
:zeek:id:`ICMP_UNREACH_NEEDFRAG`: :zeek:type:`count`        Fragment needed.
:zeek:id:`ICMP_UNREACH_NET`: :zeek:type:`count`             Network unreachable.
:zeek:id:`ICMP_UNREACH_PORT`: :zeek:type:`count`            Port unreachable.
:zeek:id:`ICMP_UNREACH_PROTOCOL`: :zeek:type:`count`        Protocol unreachable.
:zeek:id:`IPPROTO_AH`: :zeek:type:`count`                   IPv6 authentication header.
:zeek:id:`IPPROTO_DSTOPTS`: :zeek:type:`count`              IPv6 destination options header.
:zeek:id:`IPPROTO_ESP`: :zeek:type:`count`                  IPv6 encapsulating security payload header.
:zeek:id:`IPPROTO_FRAGMENT`: :zeek:type:`count`             IPv6 fragment header.
:zeek:id:`IPPROTO_HOPOPTS`: :zeek:type:`count`              IPv6 hop-by-hop-options header.
:zeek:id:`IPPROTO_ICMP`: :zeek:type:`count`                 Control message protocol.
:zeek:id:`IPPROTO_ICMPV6`: :zeek:type:`count`               ICMP for IPv6.
:zeek:id:`IPPROTO_IGMP`: :zeek:type:`count`                 Group management protocol.
:zeek:id:`IPPROTO_IP`: :zeek:type:`count`                   Dummy for IP.
:zeek:id:`IPPROTO_IPIP`: :zeek:type:`count`                 IP encapsulation in IP.
:zeek:id:`IPPROTO_IPV6`: :zeek:type:`count`                 IPv6 header.
:zeek:id:`IPPROTO_MOBILITY`: :zeek:type:`count`             IPv6 mobility header.
:zeek:id:`IPPROTO_NONE`: :zeek:type:`count`                 IPv6 no next header.
:zeek:id:`IPPROTO_RAW`: :zeek:type:`count`                  Raw IP packet.
:zeek:id:`IPPROTO_ROUTING`: :zeek:type:`count`              IPv6 routing header.
:zeek:id:`IPPROTO_TCP`: :zeek:type:`count`                  TCP.
:zeek:id:`IPPROTO_UDP`: :zeek:type:`count`                  User datagram protocol.
:zeek:id:`LOGIN_STATE_AUTHENTICATE`: :zeek:type:`count`     
:zeek:id:`LOGIN_STATE_CONFUSED`: :zeek:type:`count`         
:zeek:id:`LOGIN_STATE_LOGGED_IN`: :zeek:type:`count`        
:zeek:id:`LOGIN_STATE_SKIP`: :zeek:type:`count`             
:zeek:id:`RPC_status`: :zeek:type:`table`                   Mapping of numerical RPC status codes to readable messages.
:zeek:id:`SNMP::OBJ_COUNTER32_TAG`: :zeek:type:`count`      Unsigned 32-bit integer.
:zeek:id:`SNMP::OBJ_COUNTER64_TAG`: :zeek:type:`count`      Unsigned 64-bit integer.
:zeek:id:`SNMP::OBJ_ENDOFMIBVIEW_TAG`: :zeek:type:`count`   A NULL value.
:zeek:id:`SNMP::OBJ_INTEGER_TAG`: :zeek:type:`count`        Signed 64-bit integer.
:zeek:id:`SNMP::OBJ_IPADDRESS_TAG`: :zeek:type:`count`      An IP address.
:zeek:id:`SNMP::OBJ_NOSUCHINSTANCE_TAG`: :zeek:type:`count` A NULL value.
:zeek:id:`SNMP::OBJ_NOSUCHOBJECT_TAG`: :zeek:type:`count`   A NULL value.
:zeek:id:`SNMP::OBJ_OCTETSTRING_TAG`: :zeek:type:`count`    An octet string.
:zeek:id:`SNMP::OBJ_OID_TAG`: :zeek:type:`count`            An Object Identifier.
:zeek:id:`SNMP::OBJ_OPAQUE_TAG`: :zeek:type:`count`         An octet string.
:zeek:id:`SNMP::OBJ_TIMETICKS_TAG`: :zeek:type:`count`      Unsigned 32-bit integer.
:zeek:id:`SNMP::OBJ_UNSIGNED32_TAG`: :zeek:type:`count`     Unsigned 32-bit integer.
:zeek:id:`SNMP::OBJ_UNSPECIFIED_TAG`: :zeek:type:`count`    A NULL value.
:zeek:id:`TCP_CLOSED`: :zeek:type:`count`                   Endpoint has closed connection.
:zeek:id:`TCP_ESTABLISHED`: :zeek:type:`count`              Endpoint has finished initial handshake regularly.
:zeek:id:`TCP_INACTIVE`: :zeek:type:`count`                 Endpoint is still inactive.
:zeek:id:`TCP_PARTIAL`: :zeek:type:`count`                  Endpoint has sent data but no initial SYN.
:zeek:id:`TCP_RESET`: :zeek:type:`count`                    Endpoint has sent RST.
:zeek:id:`TCP_SYN_ACK_SENT`: :zeek:type:`count`             Endpoint has sent SYN/ACK.
:zeek:id:`TCP_SYN_SENT`: :zeek:type:`count`                 Endpoint has sent SYN.
:zeek:id:`TH_ACK`: :zeek:type:`count`                       ACK.
:zeek:id:`TH_FIN`: :zeek:type:`count`                       FIN.
:zeek:id:`TH_FLAGS`: :zeek:type:`count`                     Mask combining all flags.
:zeek:id:`TH_PUSH`: :zeek:type:`count`                      PUSH.
:zeek:id:`TH_RST`: :zeek:type:`count`                       RST.
:zeek:id:`TH_SYN`: :zeek:type:`count`                       SYN.
:zeek:id:`TH_URG`: :zeek:type:`count`                       URG.
:zeek:id:`UDP_ACTIVE`: :zeek:type:`count`                   Endpoint has sent something.
:zeek:id:`UDP_INACTIVE`: :zeek:type:`count`                 Endpoint is still inactive.
:zeek:id:`trace_output_file`: :zeek:type:`string`           Holds the filename of the trace file given with ``-w`` (empty if none).
=========================================================== =======================================================================

State Variables
###############
=========================================================================================================================== ============================================================================
:zeek:id:`capture_filters`: :zeek:type:`table` :zeek:attr:`&redef`                                                          Set of BPF capture filters to use for capturing, indexed by a user-definable
                                                                                                                            ID (which must be unique).
:zeek:id:`direct_login_prompts`: :zeek:type:`set` :zeek:attr:`&redef`                                                       TODO.
:zeek:id:`discarder_maxlen`: :zeek:type:`count` :zeek:attr:`&redef`                                                         Maximum length of payload passed to discarder functions.
:zeek:id:`dns_max_queries`: :zeek:type:`count` :zeek:attr:`&redef`                                                          If a DNS request includes more than this many queries, assume it's non-DNS
                                                                                                                            traffic and do not process it.
:zeek:id:`dns_skip_addl`: :zeek:type:`set` :zeek:attr:`&redef`                                                              For DNS servers in these sets, omit processing the ADDL records they include
                                                                                                                            in their replies.
:zeek:id:`dns_skip_all_addl`: :zeek:type:`bool` :zeek:attr:`&redef`                                                         If true, all DNS ADDL records are skipped.
:zeek:id:`dns_skip_all_auth`: :zeek:type:`bool` :zeek:attr:`&redef`                                                         If true, all DNS AUTH records are skipped.
:zeek:id:`dns_skip_auth`: :zeek:type:`set` :zeek:attr:`&redef`                                                              For DNS servers in these sets, omit processing the AUTH records they include
                                                                                                                            in their replies.
:zeek:id:`done_with_network`: :zeek:type:`bool`                                                                             
:zeek:id:`http_entity_data_delivery_size`: :zeek:type:`count` :zeek:attr:`&redef`                                           Maximum number of HTTP entity data delivered to events.
:zeek:id:`interfaces`: :zeek:type:`string` :zeek:attr:`&add_func` = :zeek:see:`add_interface` :zeek:attr:`&redef`           Network interfaces to listen on.
:zeek:id:`load_sample_freq`: :zeek:type:`count` :zeek:attr:`&redef`                                                         Rate at which to generate :zeek:see:`load_sample` events.
:zeek:id:`login_failure_msgs`: :zeek:type:`set` :zeek:attr:`&redef`                                                         TODO.
:zeek:id:`login_non_failure_msgs`: :zeek:type:`set` :zeek:attr:`&redef`                                                     TODO.
:zeek:id:`login_prompts`: :zeek:type:`set` :zeek:attr:`&redef`                                                              TODO.
:zeek:id:`login_success_msgs`: :zeek:type:`set` :zeek:attr:`&redef`                                                         TODO.
:zeek:id:`login_timeouts`: :zeek:type:`set` :zeek:attr:`&redef`                                                             TODO.
:zeek:id:`mime_segment_length`: :zeek:type:`count` :zeek:attr:`&redef`                                                      The length of MIME data segments delivered to handlers of
                                                                                                                            :zeek:see:`mime_segment_data`.
:zeek:id:`mime_segment_overlap_length`: :zeek:type:`count` :zeek:attr:`&redef`                                              The number of bytes of overlap between successive segments passed to
                                                                                                                            :zeek:see:`mime_segment_data`.
:zeek:id:`pkt_profile_file`: :zeek:type:`file` :zeek:attr:`&redef`                                                          File where packet profiles are logged.
:zeek:id:`profiling_file`: :zeek:type:`file` :zeek:attr:`&redef`                                                            Write profiling info into this file in regular intervals.
:zeek:id:`restrict_filters`: :zeek:type:`table` :zeek:attr:`&redef`                                                         Set of BPF filters to restrict capturing, indexed by a user-definable ID
                                                                                                                            (which must be unique).
:zeek:id:`secondary_filters`: :zeek:type:`table` :zeek:attr:`&redef`                                                        Definition of "secondary filters".
:zeek:id:`signature_files`: :zeek:type:`string` :zeek:attr:`&add_func` = :zeek:see:`add_signature_file` :zeek:attr:`&redef` Signature files to read.
:zeek:id:`skip_authentication`: :zeek:type:`set` :zeek:attr:`&redef`                                                        TODO.
:zeek:id:`stp_skip_src`: :zeek:type:`set` :zeek:attr:`&redef`                                                               Internal to the stepping stone detector.
=========================================================================================================================== ============================================================================

Types
#####
============================================================================= =======================================================================================================================
:zeek:type:`BrokerStats`: :zeek:type:`record`                                 Statistics about Broker communication.
:zeek:type:`Cluster::Pool`: :zeek:type:`record`                               A pool used for distributing data/work among a set of cluster nodes.
:zeek:type:`ConnStats`: :zeek:type:`record`                                   
:zeek:type:`DHCP::Addrs`: :zeek:type:`vector`                                 A list of addresses offered by a DHCP server.
:zeek:type:`DHCP::ClientFQDN`: :zeek:type:`record`                            DHCP Client FQDN Option information (Option 81)
:zeek:type:`DHCP::ClientID`: :zeek:type:`record`                              DHCP Client Identifier (Option 61)
                                                                              ..
:zeek:type:`DHCP::Msg`: :zeek:type:`record`                                   A DHCP message.
:zeek:type:`DHCP::Options`: :zeek:type:`record`                               
:zeek:type:`DHCP::SubOpt`: :zeek:type:`record`                                DHCP Relay Agent Information Option (Option 82)
                                                                              ..
:zeek:type:`DHCP::SubOpts`: :zeek:type:`vector`                               
:zeek:type:`DNSStats`: :zeek:type:`record`                                    Statistics related to Zeek's active use of DNS.
:zeek:type:`EncapsulatingConnVector`: :zeek:type:`vector`                     A type alias for a vector of encapsulating "connections", i.e.
:zeek:type:`EventStats`: :zeek:type:`record`                                  
:zeek:type:`FileAnalysisStats`: :zeek:type:`record`                           Statistics of file analysis.
:zeek:type:`GapStats`: :zeek:type:`record`                                    Statistics about number of gaps in TCP connections.
:zeek:type:`IPAddrAnonymization`: :zeek:type:`enum`                           ..
:zeek:type:`IPAddrAnonymizationClass`: :zeek:type:`enum`                      ..
:zeek:type:`JSON::TimestampFormat`: :zeek:type:`enum`                         
:zeek:type:`KRB::AP_Options`: :zeek:type:`record`                             AP Options.
:zeek:type:`KRB::Error_Msg`: :zeek:type:`record`                              The data from the ERROR_MSG message.
:zeek:type:`KRB::Host_Address`: :zeek:type:`record`                           A Kerberos host address See :rfc:`4120`.
:zeek:type:`KRB::Host_Address_Vector`: :zeek:type:`vector`                    
:zeek:type:`KRB::KDC_Options`: :zeek:type:`record`                            KDC Options.
:zeek:type:`KRB::KDC_Request`: :zeek:type:`record`                            The data from the AS_REQ and TGS_REQ messages.
:zeek:type:`KRB::KDC_Response`: :zeek:type:`record`                           The data from the AS_REQ and TGS_REQ messages.
:zeek:type:`KRB::SAFE_Msg`: :zeek:type:`record`                               The data from the SAFE message.
:zeek:type:`KRB::Ticket`: :zeek:type:`record`                                 A Kerberos ticket.
:zeek:type:`KRB::Ticket_Vector`: :zeek:type:`vector`                          
:zeek:type:`KRB::Type_Value`: :zeek:type:`record`                             Used in a few places in the Kerberos analyzer for elements
                                                                              that have a type and a string value.
:zeek:type:`KRB::Type_Value_Vector`: :zeek:type:`vector`                      
:zeek:type:`MOUNT3::dirmntargs_t`: :zeek:type:`record`                        MOUNT *mnt* arguments.
:zeek:type:`MOUNT3::info_t`: :zeek:type:`record`                              Record summarizing the general results and status of MOUNT3
                                                                              request/reply pairs.
:zeek:type:`MOUNT3::mnt_reply_t`: :zeek:type:`record`                         MOUNT lookup reply.
:zeek:type:`MQTT::ConnectAckMsg`: :zeek:type:`record`                         
:zeek:type:`MQTT::ConnectMsg`: :zeek:type:`record`                            
:zeek:type:`MQTT::PublishMsg`: :zeek:type:`record`                            
:zeek:type:`MatcherStats`: :zeek:type:`record`                                Statistics of all regular expression matchers.
:zeek:type:`ModbusCoils`: :zeek:type:`vector`                                 A vector of boolean values that indicate the setting
                                                                              for a range of modbus coils.
:zeek:type:`ModbusHeaders`: :zeek:type:`record`                               
:zeek:type:`ModbusRegisters`: :zeek:type:`vector`                             A vector of count values that represent 16bit modbus
                                                                              register values.
:zeek:type:`NFS3::delobj_reply_t`: :zeek:type:`record`                        NFS reply for *remove*, *rmdir*.
:zeek:type:`NFS3::direntry_t`: :zeek:type:`record`                            NFS *direntry*.
:zeek:type:`NFS3::direntry_vec_t`: :zeek:type:`vector`                        Vector of NFS *direntry*.
:zeek:type:`NFS3::diropargs_t`: :zeek:type:`record`                           NFS *readdir* arguments.
:zeek:type:`NFS3::fattr_t`: :zeek:type:`record`                               NFS file attributes.
:zeek:type:`NFS3::fsstat_t`: :zeek:type:`record`                              NFS *fsstat*.
:zeek:type:`NFS3::info_t`: :zeek:type:`record`                                Record summarizing the general results and status of NFSv3
                                                                              request/reply pairs.
:zeek:type:`NFS3::link_reply_t`: :zeek:type:`record`                          NFS *link* reply.
:zeek:type:`NFS3::linkargs_t`: :zeek:type:`record`                            NFS *link* arguments.
:zeek:type:`NFS3::lookup_reply_t`: :zeek:type:`record`                        NFS lookup reply.
:zeek:type:`NFS3::newobj_reply_t`: :zeek:type:`record`                        NFS reply for *create*, *mkdir*, and *symlink*.
:zeek:type:`NFS3::read_reply_t`: :zeek:type:`record`                          NFS *read* reply.
:zeek:type:`NFS3::readargs_t`: :zeek:type:`record`                            NFS *read* arguments.
:zeek:type:`NFS3::readdir_reply_t`: :zeek:type:`record`                       NFS *readdir* reply.
:zeek:type:`NFS3::readdirargs_t`: :zeek:type:`record`                         NFS *readdir* arguments.
:zeek:type:`NFS3::readlink_reply_t`: :zeek:type:`record`                      NFS *readline* reply.
:zeek:type:`NFS3::renameobj_reply_t`: :zeek:type:`record`                     NFS reply for *rename*.
:zeek:type:`NFS3::renameopargs_t`: :zeek:type:`record`                        NFS *rename* arguments.
:zeek:type:`NFS3::sattr_reply_t`: :zeek:type:`record`                         NFS *sattr* reply.
:zeek:type:`NFS3::sattr_t`: :zeek:type:`record`                               NFS file attributes.
:zeek:type:`NFS3::sattrargs_t`: :zeek:type:`record`                           NFS *sattr* arguments.
:zeek:type:`NFS3::symlinkargs_t`: :zeek:type:`record`                         NFS *symlink* arguments.
:zeek:type:`NFS3::symlinkdata_t`: :zeek:type:`record`                         NFS symlinkdata attributes.
:zeek:type:`NFS3::wcc_attr_t`: :zeek:type:`record`                            NFS *wcc* attributes.
:zeek:type:`NFS3::write_reply_t`: :zeek:type:`record`                         NFS *write* reply.
:zeek:type:`NFS3::writeargs_t`: :zeek:type:`record`                           NFS *write* arguments.
:zeek:type:`NTLM::AVs`: :zeek:type:`record`                                   
:zeek:type:`NTLM::Authenticate`: :zeek:type:`record`                          
:zeek:type:`NTLM::Challenge`: :zeek:type:`record`                             
:zeek:type:`NTLM::Negotiate`: :zeek:type:`record`                             
:zeek:type:`NTLM::NegotiateFlags`: :zeek:type:`record`                        
:zeek:type:`NTLM::Version`: :zeek:type:`record`                               
:zeek:type:`NTP::ControlMessage`: :zeek:type:`record`                         NTP control message as defined in :rfc:`1119` for mode=6
                                                                              This record contains the fields used by the NTP protocol
                                                                              for control operations.
:zeek:type:`NTP::Message`: :zeek:type:`record`                                NTP message as defined in :rfc:`5905`.
:zeek:type:`NTP::Mode7Message`: :zeek:type:`record`                           NTP mode 7 message.
:zeek:type:`NTP::StandardMessage`: :zeek:type:`record`                        NTP standard message as defined in :rfc:`5905` for modes 1-5
                                                                              This record contains the standard fields used by the NTP protocol
                                                                              for standard syncronization operations.
:zeek:type:`NetStats`: :zeek:type:`record`                                    Packet capture statistics.
:zeek:type:`PE::DOSHeader`: :zeek:type:`record`                               
:zeek:type:`PE::FileHeader`: :zeek:type:`record`                              
:zeek:type:`PE::OptionalHeader`: :zeek:type:`record`                          
:zeek:type:`PE::SectionHeader`: :zeek:type:`record`                           Record for Portable Executable (PE) section headers.
:zeek:type:`PacketSource`: :zeek:type:`record`                                Properties of an I/O packet source being read by Zeek.
:zeek:type:`PcapFilterID`: :zeek:type:`enum`                                  Enum type identifying dynamic BPF filters.
:zeek:type:`ProcStats`: :zeek:type:`record`                                   Statistics about Zeek's process.
:zeek:type:`RADIUS::AttributeList`: :zeek:type:`vector`                       
:zeek:type:`RADIUS::Attributes`: :zeek:type:`table`                           
:zeek:type:`RADIUS::Message`: :zeek:type:`record`                             
:zeek:type:`RDP::ClientChannelDef`: :zeek:type:`record`                       Name and flags for a single channel requested by the client.
:zeek:type:`RDP::ClientChannelList`: :zeek:type:`vector`                      The list of channels requested by the client.
:zeek:type:`RDP::ClientClusterData`: :zeek:type:`record`                      The TS_UD_CS_CLUSTER data block is sent by the client to the server
                                                                              either to advertise that it can support the Server Redirection PDUs
                                                                              or to request a connection to a given session identifier.
:zeek:type:`RDP::ClientCoreData`: :zeek:type:`record`                         
:zeek:type:`RDP::ClientSecurityData`: :zeek:type:`record`                     The TS_UD_CS_SEC data block contains security-related information used
                                                                              to advertise client cryptographic support.
:zeek:type:`RDP::EarlyCapabilityFlags`: :zeek:type:`record`                   
:zeek:type:`ReassemblerStats`: :zeek:type:`record`                            Holds statistics for all types of reassembly.
:zeek:type:`ReporterStats`: :zeek:type:`record`                               Statistics about reporter messages and weirds.
:zeek:type:`SMB1::Find_First2_Request_Args`: :zeek:type:`record`              
:zeek:type:`SMB1::Find_First2_Response_Args`: :zeek:type:`record`             
:zeek:type:`SMB1::Header`: :zeek:type:`record`                                An SMB1 header.
:zeek:type:`SMB1::NegotiateCapabilities`: :zeek:type:`record`                 
:zeek:type:`SMB1::NegotiateRawMode`: :zeek:type:`record`                      
:zeek:type:`SMB1::NegotiateResponse`: :zeek:type:`record`                     
:zeek:type:`SMB1::NegotiateResponseCore`: :zeek:type:`record`                 
:zeek:type:`SMB1::NegotiateResponseLANMAN`: :zeek:type:`record`               
:zeek:type:`SMB1::NegotiateResponseNTLM`: :zeek:type:`record`                 
:zeek:type:`SMB1::NegotiateResponseSecurity`: :zeek:type:`record`             
:zeek:type:`SMB1::SessionSetupAndXCapabilities`: :zeek:type:`record`          
:zeek:type:`SMB1::SessionSetupAndXRequest`: :zeek:type:`record`               
:zeek:type:`SMB1::SessionSetupAndXResponse`: :zeek:type:`record`              
:zeek:type:`SMB1::Trans2_Args`: :zeek:type:`record`                           
:zeek:type:`SMB1::Trans2_Sec_Args`: :zeek:type:`record`                       
:zeek:type:`SMB1::Trans_Sec_Args`: :zeek:type:`record`                        
:zeek:type:`SMB2::CloseResponse`: :zeek:type:`record`                         The response to an SMB2 *close* request, which is used by the client to close an instance
                                                                              of a file that was opened previously.
:zeek:type:`SMB2::CompressionCapabilities`: :zeek:type:`record`               Compression information as defined in SMB v.
:zeek:type:`SMB2::CreateRequest`: :zeek:type:`record`                         The request sent by the client to request either creation of or access to a file.
:zeek:type:`SMB2::CreateResponse`: :zeek:type:`record`                        The response to an SMB2 *create_request* request, which is sent by the client to request
                                                                              either creation of or access to a file.
:zeek:type:`SMB2::EncryptionCapabilities`: :zeek:type:`record`                Encryption information as defined in SMB v.
:zeek:type:`SMB2::FileAttrs`: :zeek:type:`record`                             A series of boolean flags describing basic and extended file attributes for SMB2.
:zeek:type:`SMB2::FileEA`: :zeek:type:`record`                                This information class is used to query or set extended attribute (EA) information for a file.
:zeek:type:`SMB2::FileEAs`: :zeek:type:`vector`                               A vector of extended attribute (EA) information for a file.
:zeek:type:`SMB2::Fscontrol`: :zeek:type:`record`                             A series of integers flags used to set quota and content indexing control information for a file system volume in SMB2.
:zeek:type:`SMB2::GUID`: :zeek:type:`record`                                  An SMB2 globally unique identifier which identifies a file.
:zeek:type:`SMB2::Header`: :zeek:type:`record`                                An SMB2 header.
:zeek:type:`SMB2::NegotiateContextValue`: :zeek:type:`record`                 The context type information as defined in SMB v.
:zeek:type:`SMB2::NegotiateContextValues`: :zeek:type:`vector`                
:zeek:type:`SMB2::NegotiateResponse`: :zeek:type:`record`                     The response to an SMB2 *negotiate* request, which is used by tghe client to notify the server
                                                                              what dialects of the SMB2 protocol the client understands.
:zeek:type:`SMB2::PreAuthIntegrityCapabilities`: :zeek:type:`record`          Preauthentication information as defined in SMB v.
:zeek:type:`SMB2::SessionSetupFlags`: :zeek:type:`record`                     A flags field that indicates additional information about the session that's sent in the
                                                                              *session_setup* response.
:zeek:type:`SMB2::SessionSetupRequest`: :zeek:type:`record`                   The request sent by the client to request a new authenticated session
                                                                              within a new or existing SMB 2 Protocol transport connection to the server.
:zeek:type:`SMB2::SessionSetupResponse`: :zeek:type:`record`                  The response to an SMB2 *session_setup* request, which is sent by the client to request a
                                                                              new authenticated session within a new or existing SMB 2 Protocol transport connection
                                                                              to the server.
:zeek:type:`SMB2::Transform_header`: :zeek:type:`record`                      An SMB2 transform header (for SMB 3.x dialects with encryption enabled).
:zeek:type:`SMB2::TreeConnectResponse`: :zeek:type:`record`                   The response to an SMB2 *tree_connect* request, which is sent by the client to request
                                                                              access to a particular share on the server.
:zeek:type:`SMB::MACTimes`: :zeek:type:`record` :zeek:attr:`&log`             MAC times for a file.
:zeek:type:`SNMP::Binding`: :zeek:type:`record`                               The ``VarBind`` data structure from either :rfc:`1157` or
                                                                              :rfc:`3416`, which maps an Object Identifier to a value.
:zeek:type:`SNMP::Bindings`: :zeek:type:`vector`                              A ``VarBindList`` data structure from either :rfc:`1157` or :rfc:`3416`.
:zeek:type:`SNMP::BulkPDU`: :zeek:type:`record`                               A ``BulkPDU`` data structure from :rfc:`3416`.
:zeek:type:`SNMP::Header`: :zeek:type:`record`                                A generic SNMP header data structure that may include data from
                                                                              any version of SNMP.
:zeek:type:`SNMP::HeaderV1`: :zeek:type:`record`                              The top-level message data structure of an SNMPv1 datagram, not
                                                                              including the PDU data.
:zeek:type:`SNMP::HeaderV2`: :zeek:type:`record`                              The top-level message data structure of an SNMPv2 datagram, not
                                                                              including the PDU data.
:zeek:type:`SNMP::HeaderV3`: :zeek:type:`record`                              The top-level message data structure of an SNMPv3 datagram, not
                                                                              including the PDU data.
:zeek:type:`SNMP::ObjectValue`: :zeek:type:`record`                           A generic SNMP object value, that may include any of the
                                                                              valid ``ObjectSyntax`` values from :rfc:`1155` or :rfc:`3416`.
:zeek:type:`SNMP::PDU`: :zeek:type:`record`                                   A ``PDU`` data structure from either :rfc:`1157` or :rfc:`3416`.
:zeek:type:`SNMP::ScopedPDU_Context`: :zeek:type:`record`                     The ``ScopedPduData`` data structure of an SNMPv3 datagram, not
                                                                              including the PDU data (i.e.
:zeek:type:`SNMP::TrapPDU`: :zeek:type:`record`                               A ``Trap-PDU`` data structure from :rfc:`1157`.
:zeek:type:`SOCKS::Address`: :zeek:type:`record` :zeek:attr:`&log`            This record is for a SOCKS client or server to provide either a
                                                                              name or an address to represent a desired or established connection.
:zeek:type:`SSH::Algorithm_Prefs`: :zeek:type:`record`                        The client and server each have some preferences for the algorithms used
                                                                              in each direction.
:zeek:type:`SSH::Capabilities`: :zeek:type:`record`                           This record lists the preferences of an SSH endpoint for
                                                                              algorithm selection.
:zeek:type:`SSL::PSKIdentity`: :zeek:type:`record`                            
:zeek:type:`SSL::SignatureAndHashAlgorithm`: :zeek:type:`record`              
:zeek:type:`SYN_packet`: :zeek:type:`record`                                  Fields of a SYN packet.
:zeek:type:`TCP::Option`: :zeek:type:`record`                                 A TCP Option field parsed from a TCP header.
:zeek:type:`TCP::OptionList`: :zeek:type:`vector`                             The full list of TCP Option fields parsed from a TCP header.
:zeek:type:`ThreadStats`: :zeek:type:`record`                                 Statistics about threads.
:zeek:type:`TimerStats`: :zeek:type:`record`                                  Statistics of timers.
:zeek:type:`Tunnel::EncapsulatingConn`: :zeek:type:`record` :zeek:attr:`&log` Records the identity of an encapsulating parent of a tunneled connection.
:zeek:type:`Unified2::IDSEvent`: :zeek:type:`record`                          
:zeek:type:`Unified2::Packet`: :zeek:type:`record`                            
:zeek:type:`X509::BasicConstraints`: :zeek:type:`record` :zeek:attr:`&log`    
:zeek:type:`X509::Certificate`: :zeek:type:`record`                           
:zeek:type:`X509::Extension`: :zeek:type:`record`                             
:zeek:type:`X509::Result`: :zeek:type:`record`                                Result of an X509 certificate chain verification
:zeek:type:`X509::SubjectAlternativeName`: :zeek:type:`record`                
:zeek:type:`addr_set`: :zeek:type:`set`                                       A set of addresses.
:zeek:type:`addr_vec`: :zeek:type:`vector`                                    A vector of addresses.
:zeek:type:`any_vec`: :zeek:type:`vector`                                     A vector of any, used by some builtin functions to store a list of varying
                                                                              types.
:zeek:type:`bittorrent_benc_dir`: :zeek:type:`table`                          A table of BitTorrent "benc" values.
:zeek:type:`bittorrent_benc_value`: :zeek:type:`record`                       BitTorrent "benc" value.
:zeek:type:`bittorrent_peer`: :zeek:type:`record`                             A BitTorrent peer.
:zeek:type:`bittorrent_peer_set`: :zeek:type:`set`                            A set of BitTorrent peers.
:zeek:type:`bt_tracker_headers`: :zeek:type:`table`                           Header table type used by BitTorrent analyzer.
:zeek:type:`call_argument`: :zeek:type:`record`                               Meta-information about a parameter to a function/event.
:zeek:type:`call_argument_vector`: :zeek:type:`vector`                        Vector type used to capture parameters of a function/event call.
:zeek:type:`conn_id`: :zeek:type:`record` :zeek:attr:`&log`                   A connection's identifying 4-tuple of endpoints and ports.
:zeek:type:`connection`: :zeek:type:`record`                                  A connection.
:zeek:type:`count_set`: :zeek:type:`set`                                      A set of counts.
:zeek:type:`dns_answer`: :zeek:type:`record`                                  The general part of a DNS reply.
:zeek:type:`dns_dnskey_rr`: :zeek:type:`record`                               A DNSSEC DNSKEY record.
:zeek:type:`dns_ds_rr`: :zeek:type:`record`                                   A DNSSEC DS record.
:zeek:type:`dns_edns_additional`: :zeek:type:`record`                         An additional DNS EDNS record.
:zeek:type:`dns_mapping`: :zeek:type:`record`                                 
:zeek:type:`dns_msg`: :zeek:type:`record`                                     A DNS message.
:zeek:type:`dns_nsec3_rr`: :zeek:type:`record`                                A DNSSEC NSEC3 record.
:zeek:type:`dns_rrsig_rr`: :zeek:type:`record`                                A DNSSEC RRSIG record.
:zeek:type:`dns_soa`: :zeek:type:`record`                                     A DNS SOA record.
:zeek:type:`dns_tsig_additional`: :zeek:type:`record`                         An additional DNS TSIG record.
:zeek:type:`endpoint`: :zeek:type:`record`                                    Statistics about a :zeek:type:`connection` endpoint.
:zeek:type:`endpoint_stats`: :zeek:type:`record`                              Statistics about what a TCP endpoint sent.
:zeek:type:`entropy_test_result`: :zeek:type:`record`                         Computed entropy values.
:zeek:type:`fa_file`: :zeek:type:`record` :zeek:attr:`&redef`                 A file that Zeek is analyzing.
:zeek:type:`fa_metadata`: :zeek:type:`record`                                 Metadata that's been inferred about a particular file.
:zeek:type:`files_tag_set`: :zeek:type:`set`                                  A set of file analyzer tags.
:zeek:type:`flow_id`: :zeek:type:`record` :zeek:attr:`&log`                   The identifying 4-tuple of a uni-directional flow.
:zeek:type:`ftp_port`: :zeek:type:`record`                                    A parsed host/port combination describing server endpoint for an upcoming
                                                                              data transfer.
:zeek:type:`geo_location`: :zeek:type:`record` :zeek:attr:`&log`              GeoIP location information.
:zeek:type:`gtp_access_point_name`: :zeek:type:`string`                       
:zeek:type:`gtp_cause`: :zeek:type:`count`                                    
:zeek:type:`gtp_charging_characteristics`: :zeek:type:`count`                 
:zeek:type:`gtp_charging_gateway_addr`: :zeek:type:`addr`                     
:zeek:type:`gtp_charging_id`: :zeek:type:`count`                              
:zeek:type:`gtp_create_pdp_ctx_request_elements`: :zeek:type:`record`         
:zeek:type:`gtp_create_pdp_ctx_response_elements`: :zeek:type:`record`        
:zeek:type:`gtp_delete_pdp_ctx_request_elements`: :zeek:type:`record`         
:zeek:type:`gtp_delete_pdp_ctx_response_elements`: :zeek:type:`record`        
:zeek:type:`gtp_end_user_addr`: :zeek:type:`record`                           
:zeek:type:`gtp_gsn_addr`: :zeek:type:`record`                                
:zeek:type:`gtp_imsi`: :zeek:type:`count`                                     
:zeek:type:`gtp_msisdn`: :zeek:type:`string`                                  
:zeek:type:`gtp_nsapi`: :zeek:type:`count`                                    
:zeek:type:`gtp_omc_id`: :zeek:type:`string`                                  
:zeek:type:`gtp_private_extension`: :zeek:type:`record`                       
:zeek:type:`gtp_proto_config_options`: :zeek:type:`string`                    
:zeek:type:`gtp_qos_profile`: :zeek:type:`record`                             
:zeek:type:`gtp_rai`: :zeek:type:`record`                                     
:zeek:type:`gtp_recovery`: :zeek:type:`count`                                 
:zeek:type:`gtp_reordering_required`: :zeek:type:`bool`                       
:zeek:type:`gtp_selection_mode`: :zeek:type:`count`                           
:zeek:type:`gtp_teardown_ind`: :zeek:type:`bool`                              
:zeek:type:`gtp_teid1`: :zeek:type:`count`                                    
:zeek:type:`gtp_teid_control_plane`: :zeek:type:`count`                       
:zeek:type:`gtp_tft`: :zeek:type:`string`                                     
:zeek:type:`gtp_trace_reference`: :zeek:type:`count`                          
:zeek:type:`gtp_trace_type`: :zeek:type:`count`                               
:zeek:type:`gtp_trigger_id`: :zeek:type:`string`                              
:zeek:type:`gtp_update_pdp_ctx_request_elements`: :zeek:type:`record`         
:zeek:type:`gtp_update_pdp_ctx_response_elements`: :zeek:type:`record`        
:zeek:type:`gtpv1_hdr`: :zeek:type:`record`                                   A GTPv1 (GPRS Tunneling Protocol) header.
:zeek:type:`http_message_stat`: :zeek:type:`record`                           HTTP message statistics.
:zeek:type:`http_stats_rec`: :zeek:type:`record`                              HTTP session statistics.
:zeek:type:`icmp6_nd_option`: :zeek:type:`record`                             Options extracted from ICMPv6 neighbor discovery messages as specified
                                                                              by :rfc:`4861`.
:zeek:type:`icmp6_nd_options`: :zeek:type:`vector`                            A type alias for a vector of ICMPv6 neighbor discovery message options.
:zeek:type:`icmp6_nd_prefix_info`: :zeek:type:`record`                        Values extracted from a Prefix Information option in an ICMPv6 neighbor
                                                                              discovery message as specified by :rfc:`4861`.
:zeek:type:`icmp_conn`: :zeek:type:`record`                                   Specifics about an ICMP conversation.
:zeek:type:`icmp_context`: :zeek:type:`record`                                Packet context part of an ICMP message.
:zeek:type:`icmp_hdr`: :zeek:type:`record`                                    Values extracted from an ICMP header.
:zeek:type:`id_table`: :zeek:type:`table`                                     Table type used to map script-level identifiers to meta-information
                                                                              describing them.
:zeek:type:`index_vec`: :zeek:type:`vector`                                   A vector of counts, used by some builtin functions to store a list of indices.
:zeek:type:`interval_set`: :zeek:type:`set`                                   A set of intervals.
:zeek:type:`ip4_hdr`: :zeek:type:`record`                                     Values extracted from an IPv4 header.
:zeek:type:`ip6_ah`: :zeek:type:`record`                                      Values extracted from an IPv6 Authentication extension header.
:zeek:type:`ip6_dstopts`: :zeek:type:`record`                                 Values extracted from an IPv6 Destination options extension header.
:zeek:type:`ip6_esp`: :zeek:type:`record`                                     Values extracted from an IPv6 ESP extension header.
:zeek:type:`ip6_ext_hdr`: :zeek:type:`record`                                 A general container for a more specific IPv6 extension header.
:zeek:type:`ip6_ext_hdr_chain`: :zeek:type:`vector`                           A type alias for a vector of IPv6 extension headers.
:zeek:type:`ip6_fragment`: :zeek:type:`record`                                Values extracted from an IPv6 Fragment extension header.
:zeek:type:`ip6_hdr`: :zeek:type:`record`                                     Values extracted from an IPv6 header.
:zeek:type:`ip6_hopopts`: :zeek:type:`record`                                 Values extracted from an IPv6 Hop-by-Hop options extension header.
:zeek:type:`ip6_mobility_back`: :zeek:type:`record`                           Values extracted from an IPv6 Mobility Binding Acknowledgement message.
:zeek:type:`ip6_mobility_be`: :zeek:type:`record`                             Values extracted from an IPv6 Mobility Binding Error message.
:zeek:type:`ip6_mobility_brr`: :zeek:type:`record`                            Values extracted from an IPv6 Mobility Binding Refresh Request message.
:zeek:type:`ip6_mobility_bu`: :zeek:type:`record`                             Values extracted from an IPv6 Mobility Binding Update message.
:zeek:type:`ip6_mobility_cot`: :zeek:type:`record`                            Values extracted from an IPv6 Mobility Care-of Test message.
:zeek:type:`ip6_mobility_coti`: :zeek:type:`record`                           Values extracted from an IPv6 Mobility Care-of Test Init message.
:zeek:type:`ip6_mobility_hdr`: :zeek:type:`record`                            Values extracted from an IPv6 Mobility header.
:zeek:type:`ip6_mobility_hot`: :zeek:type:`record`                            Values extracted from an IPv6 Mobility Home Test message.
:zeek:type:`ip6_mobility_hoti`: :zeek:type:`record`                           Values extracted from an IPv6 Mobility Home Test Init message.
:zeek:type:`ip6_mobility_msg`: :zeek:type:`record`                            Values extracted from an IPv6 Mobility header's message data.
:zeek:type:`ip6_option`: :zeek:type:`record`                                  Values extracted from an IPv6 extension header's (e.g.
:zeek:type:`ip6_options`: :zeek:type:`vector`                                 A type alias for a vector of IPv6 options.
:zeek:type:`ip6_routing`: :zeek:type:`record`                                 Values extracted from an IPv6 Routing extension header.
:zeek:type:`irc_join_info`: :zeek:type:`record`                               IRC join information.
:zeek:type:`irc_join_list`: :zeek:type:`set`                                  Set of IRC join information.
:zeek:type:`l2_hdr`: :zeek:type:`record`                                      Values extracted from the layer 2 header.
:zeek:type:`load_sample_info`: :zeek:type:`set`                               
:zeek:type:`mime_header_list`: :zeek:type:`table`                             A list of MIME headers.
:zeek:type:`mime_header_rec`: :zeek:type:`record`                             A MIME header key/value pair.
:zeek:type:`mime_match`: :zeek:type:`record`                                  A structure indicating a MIME type and strength of a match against
                                                                              file magic signatures.
:zeek:type:`mime_matches`: :zeek:type:`vector`                                A vector of file magic signature matches, ordered by strength of
                                                                              the signature, strongest first.
:zeek:type:`pcap_packet`: :zeek:type:`record`                                 Policy-level representation of a packet passed on by libpcap.
:zeek:type:`pkt_hdr`: :zeek:type:`record`                                     A packet header, consisting of an IP header and transport-layer header.
:zeek:type:`pkt_profile_modes`: :zeek:type:`enum`                             Output modes for packet profiling information.
:zeek:type:`pm_callit_request`: :zeek:type:`record`                           An RPC portmapper *callit* request.
:zeek:type:`pm_mapping`: :zeek:type:`record`                                  An RPC portmapper mapping.
:zeek:type:`pm_mappings`: :zeek:type:`table`                                  Table of RPC portmapper mappings.
:zeek:type:`pm_port_request`: :zeek:type:`record`                             An RPC portmapper request.
:zeek:type:`psk_identity_vec`: :zeek:type:`vector`                            
:zeek:type:`raw_pkt_hdr`: :zeek:type:`record`                                 A raw packet header, consisting of L2 header and everything in
                                                                              :zeek:see:`pkt_hdr`.
:zeek:type:`record_field`: :zeek:type:`record`                                Meta-information about a record field.
:zeek:type:`record_field_table`: :zeek:type:`table`                           Table type used to map record field declarations to meta-information
                                                                              describing them.
:zeek:type:`rotate_info`: :zeek:type:`record`                                 ..
:zeek:type:`script_id`: :zeek:type:`record`                                   Meta-information about a script-level identifier.
:zeek:type:`signature_and_hashalgorithm_vec`: :zeek:type:`vector`             A vector of Signature and Hash Algorithms.
:zeek:type:`signature_state`: :zeek:type:`record`                             Description of a signature match.
:zeek:type:`string_array`: :zeek:type:`table`                                 An ordered array of strings.
:zeek:type:`string_set`: :zeek:type:`set`                                     A set of strings.
:zeek:type:`string_vec`: :zeek:type:`vector`                                  A vector of strings.
:zeek:type:`subnet_vec`: :zeek:type:`vector`                                  A vector of subnets.
:zeek:type:`sw_align`: :zeek:type:`record`                                    Helper type for return value of Smith-Waterman algorithm.
:zeek:type:`sw_align_vec`: :zeek:type:`vector`                                Helper type for return value of Smith-Waterman algorithm.
:zeek:type:`sw_params`: :zeek:type:`record`                                   Parameters for the Smith-Waterman algorithm.
:zeek:type:`sw_substring`: :zeek:type:`record`                                Helper type for return value of Smith-Waterman algorithm.
:zeek:type:`sw_substring_vec`: :zeek:type:`vector`                            Return type for Smith-Waterman algorithm.
:zeek:type:`table_string_of_count`: :zeek:type:`table`                        A table of counts indexed by strings.
:zeek:type:`table_string_of_string`: :zeek:type:`table`                       A table of strings indexed by strings.
:zeek:type:`tcp_hdr`: :zeek:type:`record`                                     Values extracted from a TCP header.
:zeek:type:`teredo_auth`: :zeek:type:`record`                                 A Teredo origin indication header.
:zeek:type:`teredo_hdr`: :zeek:type:`record`                                  A Teredo packet header.
:zeek:type:`teredo_origin`: :zeek:type:`record`                               A Teredo authentication header.
:zeek:type:`transport_proto`: :zeek:type:`enum`                               A connection's transport-layer protocol.
:zeek:type:`udp_hdr`: :zeek:type:`record`                                     Values extracted from a UDP header.
:zeek:type:`var_sizes`: :zeek:type:`table`                                    Table type used to map variable names to their memory allocation.
:zeek:type:`x509_opaque_vector`: :zeek:type:`vector`                          A vector of x509 opaques.
============================================================================= =======================================================================================================================

Functions
#########
====================================================== =========================================================
:zeek:id:`add_interface`: :zeek:type:`function`        Internal function.
:zeek:id:`add_signature_file`: :zeek:type:`function`   Internal function.
:zeek:id:`discarder_check_icmp`: :zeek:type:`function` Function for skipping packets based on their ICMP header.
:zeek:id:`discarder_check_ip`: :zeek:type:`function`   Function for skipping packets based on their IP header.
:zeek:id:`discarder_check_tcp`: :zeek:type:`function`  Function for skipping packets based on their TCP header.
:zeek:id:`discarder_check_udp`: :zeek:type:`function`  Function for skipping packets based on their UDP header.
:zeek:id:`max_count`: :zeek:type:`function`            Returns maximum of two ``count`` values.
:zeek:id:`max_double`: :zeek:type:`function`           Returns maximum of two ``double`` values.
:zeek:id:`max_interval`: :zeek:type:`function`         Returns maximum of two ``interval`` values.
:zeek:id:`min_count`: :zeek:type:`function`            Returns minimum of two ``count`` values.
:zeek:id:`min_double`: :zeek:type:`function`           Returns minimum of two ``double`` values.
:zeek:id:`min_interval`: :zeek:type:`function`         Returns minimum of two ``interval`` values.
====================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: MQTT::max_payload_size

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   The maximum payload size to allocate for the purpose of
   payload information in :zeek:see:`mqtt_publish` events (and the
   default MQTT logs generated from that).

.. zeek:id:: Weird::sampling_duration

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 mins``

   How long a weird of a given type is allowed to keep state/counters in
   memory. For "net" weirds an expiration timer starts per weird name when
   first initializing its counter. For "flow" weirds an expiration timer
   starts once per src/dst IP pair for the first weird of any name. For
   "conn" weirds, counters and expiration timers are kept for the duration
   of the connection for each named weird and reset when necessary. E.g.
   if a "conn" weird by the name of "foo" is seen more than
   :zeek:see:`Weird::sampling_threshold` times, then an expiration timer
   begins for "foo" and upon triggering will reset the counter for "foo"
   and unthrottle its rate-limiting until it once again exceeds the
   threshold.

.. zeek:id:: Weird::sampling_rate

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1000``

   The rate-limiting sampling rate. One out of every of this number of
   rate-limited weirds of a given type will be allowed to raise events
   for further script-layer handling. Setting the sampling rate to 0
   will disable all output of rate-limited weirds.

.. zeek:id:: Weird::sampling_threshold

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``25``

   How many weirds of a given type to tolerate before sampling begins.
   I.e. this many consecutive weirds of a given type will be allowed to
   raise events for script-layer handling before being rate-limited.

.. zeek:id:: Weird::sampling_whitelist

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Prevents rate-limiting sampling of any weirds named in the table.

.. zeek:id:: default_file_bof_buffer_size

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``4096``

   Default amount of bytes that file analysis will buffer in order to use
   for mime type matching.  File analyzers attached at the time of mime type
   matching or later, will receive a copy of this buffer.

.. zeek:id:: default_file_timeout_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2.0 mins``

   Default amount of time a file can be inactive before the file analysis
   gives up and discards any internal state related to the file.

Redefinable Options
###################
.. zeek:id:: BinPAC::flowbuffer_capacity_max

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10485760``

   Maximum capacity, in bytes, that the BinPAC flowbuffer is allowed to
   grow to for use with incremental parsing of a given connection/analyzer.

.. zeek:id:: BinPAC::flowbuffer_capacity_min

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``512``

   The initial capacity, in bytes, that will be allocated to the BinPAC
   flowbuffer of a given connection/analyzer.  If the buffer buffer is
   later contracted, its capacity is also reduced to this size.

.. zeek:id:: BinPAC::flowbuffer_contract_threshold

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2097152``

   The threshold, in bytes, at which the BinPAC flowbuffer of a given
   connection/analyzer will have its capacity contracted to
   :zeek:see:`BinPAC::flowbuffer_capacity_min` after parsing a full unit.
   I.e. this is the maximum capacity to reserve in between the parsing of
   units.  If, after parsing a unit, the flowbuffer capacity is greater
   than this value, it will be contracted.

.. zeek:id:: DCE_RPC::max_cmd_reassembly

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``20``

   The maximum number of simultaneous fragmented commands that
   the DCE_RPC analyzer will tolerate before the it will generate
   a weird and skip further input.

.. zeek:id:: DCE_RPC::max_frag_data

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30000``

   The maximum number of fragmented bytes that the DCE_RPC analyzer
   will tolerate on a command before the analyzer will generate a weird
   and skip further input.

.. zeek:id:: KRB::keytab

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Kerberos keytab file name. Used to decrypt tickets encountered on the wire.

.. zeek:id:: NCP::max_frame_size

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``65536``

   The maximum number of bytes to allocate when parsing NCP frames.

.. zeek:id:: NFS3::return_data

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, :zeek:see:`nfs_proc_read` and :zeek:see:`nfs_proc_write`
   events return the file data that has been read/written.
   
   .. zeek:see:: NFS3::return_data_max NFS3::return_data_first_only

.. zeek:id:: NFS3::return_data_first_only

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If :zeek:id:`NFS3::return_data` is true, whether to *only* return data
   if the read or write offset is 0, i.e., only return data for the
   beginning of the file.

.. zeek:id:: NFS3::return_data_max

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``512``

   If :zeek:id:`NFS3::return_data` is true, how much data should be
   returned at most.

.. zeek:id:: Pcap::bufsize

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``128``

   Number of Mbytes to provide as buffer space when capturing from live
   interfaces.

.. zeek:id:: Pcap::snaplen

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``9216``

   Number of bytes per packet to capture from live interfaces.

.. zeek:id:: Reporter::errors_to_stderr

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Tunable for sending reporter error messages to STDERR.  The option to
   turn it off is presented here in case Zeek is being run by some
   external harness and shouldn't output anything to the console.

.. zeek:id:: Reporter::info_to_stderr

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Tunable for sending reporter info messages to STDERR.  The option to
   turn it off is presented here in case Zeek is being run by some
   external harness and shouldn't output anything to the console.

.. zeek:id:: Reporter::warnings_to_stderr

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Tunable for sending reporter warning messages to STDERR.  The option
   to turn it off is presented here in case Zeek is being run by some
   external harness and shouldn't output anything to the console.

.. zeek:id:: SMB::pipe_filenames

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/protocols/smb/consts.zeek`

      ``=``::

         spoolss, winreg, samr, srvsvc, netdfs, lsarpc, wkssvc, MsFteWds


   A set of file names used as named pipes over SMB. This
   only comes into play as a heuristic to identify named
   pipes when the drive mapping wasn't seen by Zeek.
   
   .. zeek:see:: smb_pipe_connect_heuristic

.. zeek:id:: SSL::dtls_max_reported_version_errors

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1``

   Maximum number of invalid version errors to report in one DTLS connection.

.. zeek:id:: SSL::dtls_max_version_errors

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   Number of non-DTLS frames that can occur in a DTLS connection before
   parsing of the connection is suspended.
   DTLS does not immediately stop parsing a connection because other protocols
   might be interleaved in the same UDP "connection".

.. zeek:id:: Threading::heartbeat_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   The heartbeat interval used by the threading framework.
   Changing this should usually not be necessary and will break
   several tests.

.. zeek:id:: Tunnel::delay_gtp_confirmation

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   With this set, the GTP analyzer waits until the most-recent upflow
   and downflow packets are a valid GTPv1 encapsulation before
   issuing :zeek:see:`protocol_confirmation`.  If it's false, the
   first occurrence of a packet with valid GTPv1 encapsulation causes
   confirmation.  Since the same inner connection can be carried
   differing outer upflow/downflow connections, setting to false
   may work better.

.. zeek:id:: Tunnel::delay_teredo_confirmation

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   With this set, the Teredo analyzer waits until it sees both sides
   of a connection using a valid Teredo encapsulation before issuing
   a :zeek:see:`protocol_confirmation`.  If it's false, the first
   occurrence of a packet with valid Teredo encapsulation causes a
   confirmation.

.. zeek:id:: Tunnel::enable_ayiya

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Toggle whether to do IPv{4,6}-in-AYIYA decapsulation.

.. zeek:id:: Tunnel::enable_gre

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Toggle whether to do GRE decapsulation.

.. zeek:id:: Tunnel::enable_gtpv1

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Toggle whether to do GTPv1 decapsulation.

.. zeek:id:: Tunnel::enable_ip

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Toggle whether to do IPv{4,6}-in-IPv{4,6} decapsulation.

.. zeek:id:: Tunnel::enable_teredo

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Toggle whether to do IPv6-in-Teredo decapsulation.

.. zeek:id:: Tunnel::ip_tunnel_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   How often to cleanup internal state for inactive IP tunnels
   (includes GRE tunnels).

.. zeek:id:: Tunnel::max_depth

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2``

   The maximum depth of a tunnel to decapsulate until giving up.
   Setting this to zero will disable all types of tunnel decapsulation.

.. zeek:id:: Tunnel::validate_vxlan_checksums

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether to validate the checksum supplied in the outer UDP header
   of a VXLAN encapsulation.  The spec says the checksum should be
   transmitted as zero, but if not, then the decapsulating destination
   may choose whether to perform the validation.

.. zeek:id:: Tunnel::vxlan_ports

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            4789/udp
         }


   The set of UDP ports used for VXLAN traffic.  Traffic using this
   UDP destination port will attempt to be decapsulated.  Note that if
   if you customize this, you may still want to manually ensure that
   :zeek:see:`likely_server_ports` also gets populated accordingly.

.. zeek:id:: bits_per_uid

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``96``

   Number of bits in UIDs that are generated to identify connections and
   files.  The larger the value, the more confidence in UID uniqueness.
   The maximum is currently 128 bits.

.. zeek:id:: check_for_unused_event_handlers

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, warns about unused event handlers at startup.

.. zeek:id:: cmd_line_bpf_filter

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   BPF filter the user has set via the -f command line options. Empty if none.

.. zeek:id:: detect_filtered_trace

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether to attempt to automatically detect SYN/FIN/RST-filtered trace
   and not report missing segments for such connections.
   If this is enabled, then missing data at the end of connections may not
   be reported via :zeek:see:`content_gap`.

.. zeek:id:: dns_session_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   Time to wait before timing out a DNS request.

.. zeek:id:: dpd_buffer_size

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1024``

   Size of per-connection buffer used for dynamic protocol detection. For each
   connection, Zeek buffers this initial amount of payload in memory so that
   complete protocol analysis can start even after the initial packets have
   already passed through (i.e., when a DPD signature matches only later).
   However, once the buffer is full, data is deleted and lost to analyzers that
   are activated afterwards. Then only analyzers that can deal with partial
   connections will be able to analyze the session.
   
   .. zeek:see:: dpd_reassemble_first_packets dpd_match_only_beginning
      dpd_ignore_ports

.. zeek:id:: dpd_ignore_ports

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, don't consider any ports for deciding which protocol analyzer to
   use.
   
   .. zeek:see:: dpd_reassemble_first_packets dpd_buffer_size
      dpd_match_only_beginning

.. zeek:id:: dpd_late_match_stop

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``
   :Redefinition: from :doc:`/scripts/policy/protocols/conn/speculative-service.zeek`

      ``=``::

         T


   If true, stops signature matching after a late match. A late match may occur
   in case the DPD buffer is exhausted but a protocol signature matched. To
   allow late matching, :zeek:see:`dpd_match_only_beginning` must be disabled.
   
   .. zeek:see:: dpd_reassemble_first_packets dpd_buffer_size
      dpd_match_only_beginning
   
   .. note:: Despite the name, this option stops *all* signature matching, not
      only signatures used for dynamic protocol detection but is triggered by
      DPD signatures only.

.. zeek:id:: dpd_match_only_beginning

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``
   :Redefinition: from :doc:`/scripts/policy/protocols/conn/speculative-service.zeek`

      ``=``::

         F


   If true, stops signature matching if :zeek:see:`dpd_buffer_size` has been
   reached.
   
   .. zeek:see:: dpd_reassemble_first_packets dpd_buffer_size
      dpd_ignore_ports
   
   .. note:: Despite the name, this option affects *all* signature matching, not
      only signatures used for dynamic protocol detection.

.. zeek:id:: dpd_reassemble_first_packets

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Reassemble the beginning of all TCP connections before doing
   signature matching. Enabling this provides more accurate matching at the
   expense of CPU cycles.
   
   .. zeek:see:: dpd_buffer_size
      dpd_match_only_beginning dpd_ignore_ports
   
   .. note:: Despite the name, this option affects *all* signature matching, not
      only signatures used for dynamic protocol detection.

.. zeek:id:: encap_hdr_size

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   If positive, indicates the encapsulation header size that should
   be skipped. This applies to all packets.

.. zeek:id:: exit_only_after_terminate

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Flag to prevent Zeek from exiting automatically when input is exhausted.
   Normally Zeek terminates when all packet sources have gone dry
   and communication isn't enabled. If this flag is set, Zeek's main loop will
   instead keep idling until :zeek:see:`terminate` is explicitly called.
   
   This is mainly for testing purposes when termination behaviour needs to be
   controlled for reproducing results.

.. zeek:id:: expensive_profiling_multiple

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``
   :Redefinition: from :doc:`/scripts/policy/misc/profiling.zeek`

      ``=``::

         20


   Multiples of :zeek:see:`profiling_interval` at which (more expensive) memory
   profiling is done (0 disables).
   
   .. zeek:see:: profiling_interval profiling_file segment_profiling

.. zeek:id:: frag_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0 secs``
   :Redefinition: from :doc:`/scripts/policy/tuning/defaults/packet-fragments.zeek`

      ``=``::

         5.0 mins


   How long to hold onto fragments for possible reassembly.  A value of 0.0
   means "forever", which resists evasion, but can lead to state accrual.

.. zeek:id:: global_hash_seed

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Seed for hashes computed internally for probabilistic data structures. Using
   the same value here will make the hashes compatible between independent Zeek
   instances. If left unset, Zeek will use a temporary local seed.

.. zeek:id:: icmp_inactivity_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   If an ICMP flow is inactive, time it out after this interval. If 0 secs, then
   don't time it out.
   
   .. zeek:see:: tcp_inactivity_timeout udp_inactivity_timeout set_inactivity_timeout

.. zeek:id:: ignore_checksums

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, don't verify checksums.  Useful for running on altered trace
   files, and for saving a few cycles, but at the risk of analyzing invalid
   data. Note that the ``-C`` command-line option overrides the setting of this
   variable.

.. zeek:id:: ignore_keep_alive_rexmit

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Ignore certain TCP retransmissions for :zeek:see:`conn_stats`.  Some
   connections (e.g., SSH) retransmit the acknowledged last byte to keep the
   connection alive. If *ignore_keep_alive_rexmit* is set to true, such
   retransmissions will be excluded in the rexmit counter in
   :zeek:see:`conn_stats`.
   
   .. zeek:see:: conn_stats

.. zeek:id:: likely_server_ports

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/frameworks/tunnels/main.zeek`

      ``+=``::

         Tunnel::ayiya_ports, Tunnel::teredo_ports, Tunnel::gtpv1_ports, Tunnel::vxlan_ports

   :Redefinition: from :doc:`/scripts/base/protocols/dce-rpc/main.zeek`

      ``+=``::

         DCE_RPC::ports

   :Redefinition: from :doc:`/scripts/base/protocols/dhcp/main.zeek`

      ``+=``::

         67/udp

   :Redefinition: from :doc:`/scripts/base/protocols/dnp3/main.zeek`

      ``+=``::

         DNP3::ports

   :Redefinition: from :doc:`/scripts/base/protocols/dns/main.zeek`

      ``+=``::

         DNS::ports

   :Redefinition: from :doc:`/scripts/base/protocols/ftp/main.zeek`

      ``+=``::

         FTP::ports

   :Redefinition: from :doc:`/scripts/base/protocols/ssl/main.zeek`

      ``+=``::

         SSL::ssl_ports, SSL::dtls_ports

   :Redefinition: from :doc:`/scripts/base/protocols/http/main.zeek`

      ``+=``::

         HTTP::ports

   :Redefinition: from :doc:`/scripts/base/protocols/imap/main.zeek`

      ``+=``::

         IMAP::ports

   :Redefinition: from :doc:`/scripts/base/protocols/irc/main.zeek`

      ``+=``::

         IRC::ports

   :Redefinition: from :doc:`/scripts/base/protocols/krb/main.zeek`

      ``+=``::

         KRB::tcp_ports, KRB::udp_ports

   :Redefinition: from :doc:`/scripts/base/protocols/modbus/main.zeek`

      ``+=``::

         Modbus::ports

   :Redefinition: from :doc:`/scripts/base/protocols/ntp/main.zeek`

      ``+=``::

         NTP::ports

   :Redefinition: from :doc:`/scripts/base/protocols/radius/main.zeek`

      ``+=``::

         RADIUS::ports

   :Redefinition: from :doc:`/scripts/base/protocols/rdp/main.zeek`

      ``+=``::

         RDP::ports

   :Redefinition: from :doc:`/scripts/base/protocols/sip/main.zeek`

      ``+=``::

         SIP::ports

   :Redefinition: from :doc:`/scripts/base/protocols/snmp/main.zeek`

      ``+=``::

         SNMP::ports

   :Redefinition: from :doc:`/scripts/base/protocols/smb/main.zeek`

      ``+=``::

         SMB::ports

   :Redefinition: from :doc:`/scripts/base/protocols/smtp/main.zeek`

      ``+=``::

         SMTP::ports

   :Redefinition: from :doc:`/scripts/base/protocols/socks/main.zeek`

      ``+=``::

         SOCKS::ports

   :Redefinition: from :doc:`/scripts/base/protocols/ssh/main.zeek`

      ``+=``::

         SSH::ports

   :Redefinition: from :doc:`/scripts/base/protocols/syslog/main.zeek`

      ``+=``::

         Syslog::ports

   :Redefinition: from :doc:`/scripts/base/protocols/xmpp/main.zeek`

      ``+=``::

         XMPP::ports

   :Redefinition: from :doc:`/scripts/policy/protocols/mqtt/main.zeek`

      ``+=``::

         MQTT::ports


   Ports which the core considers being likely used by servers. For ports in
   this set, it may heuristically decide to flip the direction of the
   connection if it misses the initial handshake.

.. zeek:id:: log_rotate_base_time

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"0:00"``

   Base time of log rotations in 24-hour time format (``%H:%M``), e.g. "12:00".

.. zeek:id:: max_timer_expires

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``300``

   The maximum number of timers to expire after processing each new
   packet.  The value trades off spreading out the timer expiration load
   with possibly having to hold state longer.  A value of 0 means
   "process all expired timers with each new packet".

.. zeek:id:: mmdb_dir

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The directory containing MaxMind DB (.mmdb) files to use for GeoIP support.

.. zeek:id:: non_analyzed_lifetime

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0 secs``

   If a connection belongs to an application that we don't analyze,
   time it out after this interval.  If 0 secs, then don't time it out (but
   :zeek:see:`tcp_inactivity_timeout`, :zeek:see:`udp_inactivity_timeout`, and
   :zeek:see:`icmp_inactivity_timeout` still apply).

.. zeek:id:: packet_filter_default

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Default mode for Zeek's user-space dynamic packet filter. If true, packets
   that aren't explicitly allowed through, are dropped from any further
   processing.
   
   .. note:: This is not the BPF packet filter but an additional dynamic filter
      that Zeek optionally applies just before normal processing starts.
   
   .. zeek:see:: install_dst_addr_filter install_dst_net_filter
      install_src_addr_filter install_src_net_filter  uninstall_dst_addr_filter
      uninstall_dst_net_filter uninstall_src_addr_filter uninstall_src_net_filter

.. zeek:id:: partial_connection_ok

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, instantiate connection state when a partial connection
   (one missing its initial establishment negotiation) is seen.

.. zeek:id:: peer_description

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek"``

   Description transmitted to remote communication peers for identification.

.. zeek:id:: pkt_profile_freq

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0.0``

   Frequency associated with packet profiling.
   
   .. zeek:see:: pkt_profile_modes pkt_profile_mode pkt_profile_file

.. zeek:id:: pkt_profile_mode

   :Type: :zeek:type:`pkt_profile_modes`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PKT_PROFILE_MODE_NONE``

   Output mode for packet profiling information.
   
   .. zeek:see:: pkt_profile_modes pkt_profile_freq pkt_profile_file

.. zeek:id:: profiling_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0 secs``
   :Redefinition: from :doc:`/scripts/policy/misc/profiling.zeek`

      ``=``::

         15.0 secs


   Update interval for profiling (0 disables).  The easiest way to activate
   profiling is loading  :doc:`/scripts/policy/misc/profiling.zeek`.
   
   .. zeek:see:: profiling_file expensive_profiling_multiple segment_profiling

.. zeek:id:: record_all_packets

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If a trace file is given with ``-w``, dump *all* packets seen by Zeek into it.
   By default, Zeek applies (very few) heuristics to reduce the volume. A side
   effect of setting this to true is that we can write the packets out before we
   actually process them, which can be helpful for debugging in case the
   analysis triggers a crash.
   
   .. zeek:see:: trace_output_file

.. zeek:id:: report_gaps_for_partial

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether we want :zeek:see:`content_gap` for partial
   connections. A connection is partial if it is missing a full handshake. Note
   that gap reports for partial connections might not be reliable.
   
   .. zeek:see:: content_gap partial_connection

.. zeek:id:: rpc_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``24.0 secs``

   Time to wait before timing out an RPC request.

.. zeek:id:: segment_profiling

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, then write segment profiling information (very high volume!)
   in addition to profiling statistics.
   
   .. zeek:see:: profiling_interval expensive_profiling_multiple profiling_file

.. zeek:id:: sig_max_group_size

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``50``

   Maximum size of regular expression groups for signature matching.

.. zeek:id:: skip_http_data

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Skip HTTP data for performance considerations. The skipped
   portion will not go through TCP reassembly.
   
   .. zeek:see:: http_entity_data skip_http_entity_data http_entity_data_delivery_size

.. zeek:id:: stp_delta

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`

   Internal to the stepping stone detector.

.. zeek:id:: stp_idle_min

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`

   Internal to the stepping stone detector.

.. zeek:id:: table_expire_delay

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 msecs``

   When expiring table entries, wait this amount of time before checking the
   next chunk of entries.
   
   .. zeek:see:: table_expire_interval table_incremental_step

.. zeek:id:: table_expire_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   Check for expired table entries after this amount of time.
   
   .. zeek:see:: table_incremental_step table_expire_delay

.. zeek:id:: table_incremental_step

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5000``

   When expiring/serializing table entries, don't work on more than this many
   table entries at a time.
   
   .. zeek:see:: table_expire_interval table_expire_delay

.. zeek:id:: tcp_SYN_ack_ok

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, instantiate connection state when a SYN/ACK is seen but not the
   initial SYN (even if :zeek:see:`partial_connection_ok` is false).

.. zeek:id:: tcp_SYN_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   Check up on the result of an initial SYN after this much time.

.. zeek:id:: tcp_attempt_delay

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   Wait this long upon seeing an initial SYN before timing out the
   connection attempt.

.. zeek:id:: tcp_close_delay

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   Upon seeing a normal connection close, flush state after this much time.

.. zeek:id:: tcp_connection_linger

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   When checking a closed connection for further activity, consider it
   inactive if there hasn't been any for this long.  Complain if the
   connection is reused before this much time has elapsed.

.. zeek:id:: tcp_content_deliver_all_orig

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, all TCP originator-side traffic is reported via
   :zeek:see:`tcp_contents`.
   
   .. zeek:see:: tcp_content_delivery_ports_orig tcp_content_delivery_ports_resp
      tcp_content_deliver_all_resp udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp tcp_contents

.. zeek:id:: tcp_content_deliver_all_resp

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, all TCP responder-side traffic is reported via
   :zeek:see:`tcp_contents`.
   
   .. zeek:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp
      tcp_content_deliver_all_orig udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp tcp_contents

.. zeek:id:: tcp_content_delivery_ports_orig

   :Type: :zeek:type:`table` [:zeek:type:`port`] of :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Defines destination TCP ports for which the contents of the originator stream
   should be delivered via :zeek:see:`tcp_contents`.
   
   .. zeek:see:: tcp_content_delivery_ports_resp tcp_content_deliver_all_orig
      tcp_content_deliver_all_resp udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp  tcp_contents

.. zeek:id:: tcp_content_delivery_ports_resp

   :Type: :zeek:type:`table` [:zeek:type:`port`] of :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Defines destination TCP ports for which the contents of the responder stream
   should be delivered via :zeek:see:`tcp_contents`.
   
   .. zeek:see:: tcp_content_delivery_ports_orig tcp_content_deliver_all_orig
      tcp_content_deliver_all_resp udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp tcp_contents

.. zeek:id:: tcp_excessive_data_without_further_acks

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10485760``

   If we've seen this much data without any of it being acked, we give up
   on that connection to avoid memory exhaustion due to buffering all that
   stuff.  If set to zero, then we don't ever give up.  Ideally, Zeek would
   track the current window on a connection and use it to infer that data
   has in fact gone too far, but for now we just make this quite beefy.
   
   .. zeek:see:: tcp_max_initial_window tcp_max_above_hole_without_any_acks

.. zeek:id:: tcp_inactivity_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   If a TCP connection is inactive, time it out after this interval. If 0 secs,
   then don't time it out.
   
   .. zeek:see:: udp_inactivity_timeout icmp_inactivity_timeout set_inactivity_timeout

.. zeek:id:: tcp_match_undelivered

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, pass any undelivered to the signature engine before flushing the state.
   If a connection state is removed, there may still be some data waiting in the
   reassembler.

.. zeek:id:: tcp_max_above_hole_without_any_acks

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``16384``

   If we're not seeing our peer's ACKs, the maximum volume of data above a
   sequence hole that we'll tolerate before assuming that there's been a packet
   drop and we should give up on tracking a connection. If set to zero, then we
   don't ever give up.
   
   .. zeek:see:: tcp_max_initial_window tcp_excessive_data_without_further_acks

.. zeek:id:: tcp_max_initial_window

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``16384``

   Maximum amount of data that might plausibly be sent in an initial flight
   (prior to receiving any acks).  Used to determine whether we must not be
   seeing our peer's ACKs.  Set to zero to turn off this determination.
   
   .. zeek:see:: tcp_max_above_hole_without_any_acks tcp_excessive_data_without_further_acks

.. zeek:id:: tcp_max_old_segments

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   Number of TCP segments to buffer beyond what's been acknowledged already
   to detect retransmission inconsistencies. Zero disables any additonal
   buffering.

.. zeek:id:: tcp_partial_close_delay

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``3.0 secs``

   Generate a :zeek:id:`connection_partial_close` event this much time after one
   half of a partial connection closes, assuming there has been no subsequent
   activity.

.. zeek:id:: tcp_reassembler_ports_orig

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   For services without a handler, these sets define originator-side ports
   that still trigger reassembly.
   
   .. zeek:see:: tcp_reassembler_ports_resp

.. zeek:id:: tcp_reassembler_ports_resp

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   For services without a handler, these sets define responder-side ports
   that still trigger reassembly.
   
   .. zeek:see:: tcp_reassembler_ports_orig

.. zeek:id:: tcp_reset_delay

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   Upon seeing a RST, flush state after this much time.

.. zeek:id:: tcp_session_timer

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``6.0 secs``

   After a connection has closed, wait this long for further activity
   before checking whether to time out its state.

.. zeek:id:: tcp_storm_interarrival_thresh

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   FINs/RSTs must come with this much time or less between them to be
   considered a "storm".
   
   .. zeek:see:: tcp_storm_thresh

.. zeek:id:: tcp_storm_thresh

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1000``

   Number of FINs/RSTs in a row that constitute a "storm". Storms are reported
   as ``weird`` via the notice framework, and they must also come within
   intervals of at most :zeek:see:`tcp_storm_interarrival_thresh`.
   
   .. zeek:see:: tcp_storm_interarrival_thresh

.. zeek:id:: time_machine_profiling

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, output profiling for Time-Machine queries.

.. zeek:id:: timer_mgr_inactivity_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   Per-incident timer managers are drained after this amount of inactivity.

.. zeek:id:: truncate_http_URI

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``-1``

   Maximum length of HTTP URIs passed to events. Longer ones will be truncated
   to prevent over-long URIs (usually sent by worms) from slowing down event
   processing.  A value of -1 means "do not truncate".
   
   .. zeek:see:: http_request

.. zeek:id:: udp_content_deliver_all_orig

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, all UDP originator-side traffic is reported via
   :zeek:see:`udp_contents`.
   
   .. zeek:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp tcp_content_deliver_all_resp
      tcp_content_delivery_ports_orig udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_resp
      udp_contents

.. zeek:id:: udp_content_deliver_all_resp

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, all UDP responder-side traffic is reported via
   :zeek:see:`udp_contents`.
   
   .. zeek:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp tcp_content_deliver_all_resp
      tcp_content_delivery_ports_orig udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_contents

.. zeek:id:: udp_content_delivery_ports_orig

   :Type: :zeek:type:`table` [:zeek:type:`port`] of :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Defines UDP destination ports for which the contents of the originator stream
   should be delivered via :zeek:see:`udp_contents`.
   
   .. zeek:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp
      tcp_content_deliver_all_orig tcp_content_deliver_all_resp
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp  udp_contents

.. zeek:id:: udp_content_delivery_ports_resp

   :Type: :zeek:type:`table` [:zeek:type:`port`] of :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Defines UDP destination ports for which the contents of the responder stream
   should be delivered via :zeek:see:`udp_contents`.
   
   .. zeek:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp tcp_content_deliver_all_orig
      tcp_content_deliver_all_resp udp_content_delivery_ports_orig
      udp_content_deliver_all_orig udp_content_deliver_all_resp udp_contents

.. zeek:id:: udp_inactivity_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   If a UDP flow is inactive, time it out after this interval. If 0 secs, then
   don't time it out.
   
   .. zeek:see:: tcp_inactivity_timeout icmp_inactivity_timeout set_inactivity_timeout

.. zeek:id:: use_conn_size_analyzer

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether to use the ``ConnSize`` analyzer to count the number of packets and
   IP-level bytes transferred by each endpoint. If true, these values are
   returned in the connection's :zeek:see:`endpoint` record value.

.. zeek:id:: watchdog_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   Zeek's watchdog interval.

Constants
#########
.. zeek:id:: CONTENTS_BOTH

   :Type: :zeek:type:`count`
   :Default: ``3``

   Record both originator and responder contents.

.. zeek:id:: CONTENTS_NONE

   :Type: :zeek:type:`count`
   :Default: ``0``

   Turn off recording of contents.

.. zeek:id:: CONTENTS_ORIG

   :Type: :zeek:type:`count`
   :Default: ``1``

   Record originator contents.

.. zeek:id:: CONTENTS_RESP

   :Type: :zeek:type:`count`
   :Default: ``2``

   Record responder contents.

.. zeek:id:: DNS_ADDL

   :Type: :zeek:type:`count`
   :Default: ``3``

   An additional record.

.. zeek:id:: DNS_ANS

   :Type: :zeek:type:`count`
   :Default: ``1``

   An answer record.

.. zeek:id:: DNS_AUTH

   :Type: :zeek:type:`count`
   :Default: ``2``

   An authoritative record.

.. zeek:id:: DNS_QUERY

   :Type: :zeek:type:`count`
   :Default: ``0``

   A query. This shouldn't occur, just for completeness.

.. zeek:id:: ENDIAN_BIG

   :Type: :zeek:type:`count`
   :Default: ``2``

   Big endian.

.. zeek:id:: ENDIAN_CONFUSED

   :Type: :zeek:type:`count`
   :Default: ``3``

   Tried to determine endian, but failed.

.. zeek:id:: ENDIAN_LITTLE

   :Type: :zeek:type:`count`
   :Default: ``1``

   Little endian.

.. zeek:id:: ENDIAN_UNKNOWN

   :Type: :zeek:type:`count`
   :Default: ``0``

   Endian not yet determined.

.. zeek:id:: ICMP_UNREACH_ADMIN_PROHIB

   :Type: :zeek:type:`count`
   :Default: ``13``

   Administratively prohibited.

.. zeek:id:: ICMP_UNREACH_HOST

   :Type: :zeek:type:`count`
   :Default: ``1``

   Host unreachable.

.. zeek:id:: ICMP_UNREACH_NEEDFRAG

   :Type: :zeek:type:`count`
   :Default: ``4``

   Fragment needed.

.. zeek:id:: ICMP_UNREACH_NET

   :Type: :zeek:type:`count`
   :Default: ``0``

   Network unreachable.

.. zeek:id:: ICMP_UNREACH_PORT

   :Type: :zeek:type:`count`
   :Default: ``3``

   Port unreachable.

.. zeek:id:: ICMP_UNREACH_PROTOCOL

   :Type: :zeek:type:`count`
   :Default: ``2``

   Protocol unreachable.

.. zeek:id:: IPPROTO_AH

   :Type: :zeek:type:`count`
   :Default: ``51``

   IPv6 authentication header.

.. zeek:id:: IPPROTO_DSTOPTS

   :Type: :zeek:type:`count`
   :Default: ``60``

   IPv6 destination options header.

.. zeek:id:: IPPROTO_ESP

   :Type: :zeek:type:`count`
   :Default: ``50``

   IPv6 encapsulating security payload header.

.. zeek:id:: IPPROTO_FRAGMENT

   :Type: :zeek:type:`count`
   :Default: ``44``

   IPv6 fragment header.

.. zeek:id:: IPPROTO_HOPOPTS

   :Type: :zeek:type:`count`
   :Default: ``0``

   IPv6 hop-by-hop-options header.

.. zeek:id:: IPPROTO_ICMP

   :Type: :zeek:type:`count`
   :Default: ``1``

   Control message protocol.

.. zeek:id:: IPPROTO_ICMPV6

   :Type: :zeek:type:`count`
   :Default: ``58``

   ICMP for IPv6.

.. zeek:id:: IPPROTO_IGMP

   :Type: :zeek:type:`count`
   :Default: ``2``

   Group management protocol.

.. zeek:id:: IPPROTO_IP

   :Type: :zeek:type:`count`
   :Default: ``0``

   Dummy for IP.

.. zeek:id:: IPPROTO_IPIP

   :Type: :zeek:type:`count`
   :Default: ``4``

   IP encapsulation in IP.

.. zeek:id:: IPPROTO_IPV6

   :Type: :zeek:type:`count`
   :Default: ``41``

   IPv6 header.

.. zeek:id:: IPPROTO_MOBILITY

   :Type: :zeek:type:`count`
   :Default: ``135``

   IPv6 mobility header.

.. zeek:id:: IPPROTO_NONE

   :Type: :zeek:type:`count`
   :Default: ``59``

   IPv6 no next header.

.. zeek:id:: IPPROTO_RAW

   :Type: :zeek:type:`count`
   :Default: ``255``

   Raw IP packet.

.. zeek:id:: IPPROTO_ROUTING

   :Type: :zeek:type:`count`
   :Default: ``43``

   IPv6 routing header.

.. zeek:id:: IPPROTO_TCP

   :Type: :zeek:type:`count`
   :Default: ``6``

   TCP.

.. zeek:id:: IPPROTO_UDP

   :Type: :zeek:type:`count`
   :Default: ``17``

   User datagram protocol.

.. zeek:id:: LOGIN_STATE_AUTHENTICATE

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: LOGIN_STATE_CONFUSED

   :Type: :zeek:type:`count`
   :Default: ``3``


.. zeek:id:: LOGIN_STATE_LOGGED_IN

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: LOGIN_STATE_SKIP

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: RPC_status

   :Type: :zeek:type:`table` [:zeek:type:`rpc_status`] of :zeek:type:`string`
   :Default:

      ::

         {
            [RPC_PROG_MISMATCH] = "mismatch",
            [RPC_UNKNOWN_ERROR] = "unknown",
            [RPC_TIMEOUT] = "timeout",
            [RPC_GARBAGE_ARGS] = "garbage args",
            [RPC_PROG_UNAVAIL] = "prog unavail",
            [RPC_AUTH_ERROR] = "auth error",
            [RPC_SYSTEM_ERR] = "system err",
            [RPC_SUCCESS] = "ok",
            [RPC_PROC_UNAVAIL] = "proc unavail"
         }


   Mapping of numerical RPC status codes to readable messages.
   
   .. zeek:see:: pm_attempt_callit pm_attempt_dump pm_attempt_getport
      pm_attempt_null pm_attempt_set pm_attempt_unset rpc_dialogue rpc_reply

.. zeek:id:: SNMP::OBJ_COUNTER32_TAG

   :Type: :zeek:type:`count`
   :Default: ``65``

   Unsigned 32-bit integer.

.. zeek:id:: SNMP::OBJ_COUNTER64_TAG

   :Type: :zeek:type:`count`
   :Default: ``70``

   Unsigned 64-bit integer.

.. zeek:id:: SNMP::OBJ_ENDOFMIBVIEW_TAG

   :Type: :zeek:type:`count`
   :Default: ``130``

   A NULL value.

.. zeek:id:: SNMP::OBJ_INTEGER_TAG

   :Type: :zeek:type:`count`
   :Default: ``2``

   Signed 64-bit integer.

.. zeek:id:: SNMP::OBJ_IPADDRESS_TAG

   :Type: :zeek:type:`count`
   :Default: ``64``

   An IP address.

.. zeek:id:: SNMP::OBJ_NOSUCHINSTANCE_TAG

   :Type: :zeek:type:`count`
   :Default: ``129``

   A NULL value.

.. zeek:id:: SNMP::OBJ_NOSUCHOBJECT_TAG

   :Type: :zeek:type:`count`
   :Default: ``128``

   A NULL value.

.. zeek:id:: SNMP::OBJ_OCTETSTRING_TAG

   :Type: :zeek:type:`count`
   :Default: ``4``

   An octet string.

.. zeek:id:: SNMP::OBJ_OID_TAG

   :Type: :zeek:type:`count`
   :Default: ``6``

   An Object Identifier.

.. zeek:id:: SNMP::OBJ_OPAQUE_TAG

   :Type: :zeek:type:`count`
   :Default: ``68``

   An octet string.

.. zeek:id:: SNMP::OBJ_TIMETICKS_TAG

   :Type: :zeek:type:`count`
   :Default: ``67``

   Unsigned 32-bit integer.

.. zeek:id:: SNMP::OBJ_UNSIGNED32_TAG

   :Type: :zeek:type:`count`
   :Default: ``66``

   Unsigned 32-bit integer.

.. zeek:id:: SNMP::OBJ_UNSPECIFIED_TAG

   :Type: :zeek:type:`count`
   :Default: ``5``

   A NULL value.

.. zeek:id:: TCP_CLOSED

   :Type: :zeek:type:`count`
   :Default: ``5``

   Endpoint has closed connection.

.. zeek:id:: TCP_ESTABLISHED

   :Type: :zeek:type:`count`
   :Default: ``4``

   Endpoint has finished initial handshake regularly.

.. zeek:id:: TCP_INACTIVE

   :Type: :zeek:type:`count`
   :Default: ``0``

   Endpoint is still inactive.

.. zeek:id:: TCP_PARTIAL

   :Type: :zeek:type:`count`
   :Default: ``3``

   Endpoint has sent data but no initial SYN.

.. zeek:id:: TCP_RESET

   :Type: :zeek:type:`count`
   :Default: ``6``

   Endpoint has sent RST.

.. zeek:id:: TCP_SYN_ACK_SENT

   :Type: :zeek:type:`count`
   :Default: ``2``

   Endpoint has sent SYN/ACK.

.. zeek:id:: TCP_SYN_SENT

   :Type: :zeek:type:`count`
   :Default: ``1``

   Endpoint has sent SYN.

.. zeek:id:: TH_ACK

   :Type: :zeek:type:`count`
   :Default: ``16``

   ACK.

.. zeek:id:: TH_FIN

   :Type: :zeek:type:`count`
   :Default: ``1``

   FIN.

.. zeek:id:: TH_FLAGS

   :Type: :zeek:type:`count`
   :Default: ``63``

   Mask combining all flags.

.. zeek:id:: TH_PUSH

   :Type: :zeek:type:`count`
   :Default: ``8``

   PUSH.

.. zeek:id:: TH_RST

   :Type: :zeek:type:`count`
   :Default: ``4``

   RST.

.. zeek:id:: TH_SYN

   :Type: :zeek:type:`count`
   :Default: ``2``

   SYN.

.. zeek:id:: TH_URG

   :Type: :zeek:type:`count`
   :Default: ``32``

   URG.

.. zeek:id:: UDP_ACTIVE

   :Type: :zeek:type:`count`
   :Default: ``1``

   Endpoint has sent something.

.. zeek:id:: UDP_INACTIVE

   :Type: :zeek:type:`count`
   :Default: ``0``

   Endpoint is still inactive.

.. zeek:id:: trace_output_file

   :Type: :zeek:type:`string`
   :Default: ``""``

   Holds the filename of the trace file given with ``-w`` (empty if none).
   
   .. zeek:see:: record_all_packets

State Variables
###############
.. zeek:id:: capture_filters

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Set of BPF capture filters to use for capturing, indexed by a user-definable
   ID (which must be unique). If Zeek is *not* configured with
   :zeek:id:`PacketFilter::enable_auto_protocol_capture_filters`,
   all packets matching at least one of the filters in this table (and all in
   :zeek:id:`restrict_filters`) will be analyzed.
   
   .. zeek:see:: PacketFilter PacketFilter::enable_auto_protocol_capture_filters
      PacketFilter::unrestricted_filter restrict_filters

.. zeek:id:: direct_login_prompts

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   TODO.

.. zeek:id:: discarder_maxlen

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``128``

   Maximum length of payload passed to discarder functions.
   
   .. zeek:see:: discarder_check_tcp discarder_check_udp discarder_check_icmp
      discarder_check_ip

.. zeek:id:: dns_max_queries

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``25``

   If a DNS request includes more than this many queries, assume it's non-DNS
   traffic and do not process it.  Set to 0 to turn off this functionality.

.. zeek:id:: dns_skip_addl

   :Type: :zeek:type:`set` [:zeek:type:`addr`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   For DNS servers in these sets, omit processing the ADDL records they include
   in their replies.
   
   .. zeek:see:: dns_skip_all_addl dns_skip_auth

.. zeek:id:: dns_skip_all_addl

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``
   :Redefinition: from :doc:`/scripts/policy/protocols/dns/auth-addl.zeek`

      ``=``::

         F


   If true, all DNS ADDL records are skipped.
   
   .. zeek:see:: dns_skip_all_auth dns_skip_addl

.. zeek:id:: dns_skip_all_auth

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``
   :Redefinition: from :doc:`/scripts/policy/protocols/dns/auth-addl.zeek`

      ``=``::

         F


   If true, all DNS AUTH records are skipped.
   
   .. zeek:see:: dns_skip_all_addl dns_skip_auth

.. zeek:id:: dns_skip_auth

   :Type: :zeek:type:`set` [:zeek:type:`addr`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   For DNS servers in these sets, omit processing the AUTH records they include
   in their replies.
   
   .. zeek:see:: dns_skip_all_auth dns_skip_addl

.. zeek:id:: done_with_network

   :Type: :zeek:type:`bool`
   :Default: ``F``


.. zeek:id:: http_entity_data_delivery_size

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1500``

   Maximum number of HTTP entity data delivered to events.
   
   .. zeek:see:: http_entity_data skip_http_entity_data skip_http_data

.. zeek:id:: interfaces

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&add_func` = :zeek:see:`add_interface` :zeek:attr:`&redef`
   :Default: ``""``

   Network interfaces to listen on. Use ``redef interfaces += "eth0"`` to
   extend.

.. zeek:id:: load_sample_freq

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``20``

   Rate at which to generate :zeek:see:`load_sample` events. As all
   events, the event is only generated if you've also defined a
   :zeek:see:`load_sample` handler.  Units are inverse number of packets; e.g.,
   a value of 20 means "roughly one in every 20 packets".
   
   .. zeek:see:: load_sample

.. zeek:id:: login_failure_msgs

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   TODO.

.. zeek:id:: login_non_failure_msgs

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   TODO.

.. zeek:id:: login_prompts

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   TODO.

.. zeek:id:: login_success_msgs

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   TODO.

.. zeek:id:: login_timeouts

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   TODO.

.. zeek:id:: mime_segment_length

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1024``

   The length of MIME data segments delivered to handlers of
   :zeek:see:`mime_segment_data`.
   
   .. zeek:see:: mime_segment_data mime_segment_overlap_length

.. zeek:id:: mime_segment_overlap_length

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   The number of bytes of overlap between successive segments passed to
   :zeek:see:`mime_segment_data`.

.. zeek:id:: pkt_profile_file

   :Type: :zeek:type:`file`
   :Attributes: :zeek:attr:`&redef`

   File where packet profiles are logged.
   
   .. zeek:see:: pkt_profile_modes pkt_profile_freq pkt_profile_mode

.. zeek:id:: profiling_file

   :Type: :zeek:type:`file`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         file "prof.log" of string

   :Redefinition: from :doc:`/scripts/policy/misc/profiling.zeek`

      ``=``::

         open(fmt(prof.%s, Profiling::log_suffix()))


   Write profiling info into this file in regular intervals. The easiest way to
   activate profiling is loading :doc:`/scripts/policy/misc/profiling.zeek`.
   
   .. zeek:see:: profiling_interval expensive_profiling_multiple segment_profiling

.. zeek:id:: restrict_filters

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Set of BPF filters to restrict capturing, indexed by a user-definable ID
   (which must be unique).
   
   .. zeek:see:: PacketFilter PacketFilter::enable_auto_protocol_capture_filters
      PacketFilter::unrestricted_filter capture_filters

.. zeek:id:: secondary_filters

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`event` (filter: :zeek:type:`string`, pkt: :zeek:type:`pkt_hdr`)
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Definition of "secondary filters". A secondary filter is a BPF filter given
   as index in this table. For each such filter, the corresponding event is
   raised for all matching packets.

.. zeek:id:: signature_files

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&add_func` = :zeek:see:`add_signature_file` :zeek:attr:`&redef`
   :Default: ``""``

   Signature files to read. Use ``redef signature_files  += "foo.sig"`` to
   extend. Signature files added this way will be searched relative to
   ``ZEEKPATH``.  Using the ``@load-sigs`` directive instead is preferred
   since that can search paths relative to the current script.

.. zeek:id:: skip_authentication

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   TODO.

.. zeek:id:: stp_skip_src

   :Type: :zeek:type:`set` [:zeek:type:`addr`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Internal to the stepping stone detector.

Types
#####
.. zeek:type:: BrokerStats

   :Type: :zeek:type:`record`

      num_peers: :zeek:type:`count`

      num_stores: :zeek:type:`count`
         Number of active data stores.

      num_pending_queries: :zeek:type:`count`
         Number of pending data store queries.

      num_events_incoming: :zeek:type:`count`
         Number of total log messages received.

      num_events_outgoing: :zeek:type:`count`
         Number of total log messages sent.

      num_logs_incoming: :zeek:type:`count`
         Number of total log records received.

      num_logs_outgoing: :zeek:type:`count`
         Number of total log records sent.

      num_ids_incoming: :zeek:type:`count`
         Number of total identifiers received.

      num_ids_outgoing: :zeek:type:`count`
         Number of total identifiers sent.

   Statistics about Broker communication.
   
   .. zeek:see:: get_broker_stats

.. zeek:type:: Cluster::Pool

   :Type: :zeek:type:`record`

      spec: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&default` = *[topic=, node_type=Cluster::PROXY, max_nodes=<uninitialized>, exclusive=F]* :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.zeek` is loaded)

         The specification of the pool that was used when registering it.

      nodes: :zeek:type:`Cluster::PoolNodeTable` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.zeek` is loaded)

         Nodes in the pool, indexed by their name (e.g. "manager").

      node_list: :zeek:type:`vector` of :zeek:type:`Cluster::PoolNode` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.zeek` is loaded)

         A list of nodes in the pool in a deterministic order.

      hrw_pool: :zeek:type:`HashHRW::Pool` :zeek:attr:`&default` = ``[sites={  }]`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.zeek` is loaded)

         The Rendezvous hashing structure.

      rr_key_seq: :zeek:type:`Cluster::RoundRobinTable` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.zeek` is loaded)

         Round-Robin table indexed by arbitrary key and storing the next
         index of *node_list* that will be eligible to receive work (if it's
         alive at the time of next request).

      alive_count: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.zeek` is loaded)

         Number of pool nodes that are currently alive.

   A pool used for distributing data/work among a set of cluster nodes.

.. zeek:type:: ConnStats

   :Type: :zeek:type:`record`

      total_conns: :zeek:type:`count`
         

      current_conns: :zeek:type:`count`
         

      sess_current_conns: :zeek:type:`count`
         

      num_packets: :zeek:type:`count`

      num_fragments: :zeek:type:`count`

      max_fragments: :zeek:type:`count`

      num_tcp_conns: :zeek:type:`count`
         Current number of TCP connections in memory.

      max_tcp_conns: :zeek:type:`count`
         Maximum number of concurrent TCP connections so far.

      cumulative_tcp_conns: :zeek:type:`count`
         Total number of TCP connections so far.

      num_udp_conns: :zeek:type:`count`
         Current number of UDP flows in memory.

      max_udp_conns: :zeek:type:`count`
         Maximum number of concurrent UDP flows so far.

      cumulative_udp_conns: :zeek:type:`count`
         Total number of UDP flows so far.

      num_icmp_conns: :zeek:type:`count`
         Current number of ICMP flows in memory.

      max_icmp_conns: :zeek:type:`count`
         Maximum number of concurrent ICMP flows so far.

      cumulative_icmp_conns: :zeek:type:`count`
         Total number of ICMP flows so far.

      killed_by_inactivity: :zeek:type:`count`


.. zeek:type:: DHCP::Addrs

   :Type: :zeek:type:`vector` of :zeek:type:`addr`

   A list of addresses offered by a DHCP server.  Could be routers,
   DNS servers, or other.
   
   .. zeek:see:: dhcp_message

.. zeek:type:: DHCP::ClientFQDN

   :Type: :zeek:type:`record`

      flags: :zeek:type:`count`
         An unparsed bitfield of flags (refer to RFC 4702).

      rcode1: :zeek:type:`count`
         This field is deprecated in the standard.

      rcode2: :zeek:type:`count`
         This field is deprecated in the standard.

      domain_name: :zeek:type:`string`
         The Domain Name part of the option carries all or part of the FQDN
         of a DHCP client.

   DHCP Client FQDN Option information (Option 81)

.. zeek:type:: DHCP::ClientID

   :Type: :zeek:type:`record`

      hwtype: :zeek:type:`count`

      hwaddr: :zeek:type:`string`

   DHCP Client Identifier (Option 61)
   .. zeek:see:: dhcp_message

.. zeek:type:: DHCP::Msg

   :Type: :zeek:type:`record`

      op: :zeek:type:`count`
         Message OP code. 1 = BOOTREQUEST, 2 = BOOTREPLY

      m_type: :zeek:type:`count`
         The type of DHCP message.

      xid: :zeek:type:`count`
         Transaction ID of a DHCP session.

      secs: :zeek:type:`interval`
         Number of seconds since client began address acquisition
         or renewal process

      flags: :zeek:type:`count`

      ciaddr: :zeek:type:`addr`
         Original IP address of the client.

      yiaddr: :zeek:type:`addr`
         IP address assigned to the client.

      siaddr: :zeek:type:`addr`
         IP address of the server.

      giaddr: :zeek:type:`addr`
         IP address of the relaying gateway.

      chaddr: :zeek:type:`string`
         Client hardware address.

      sname: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Server host name.

      file_n: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Boot file name.

   A DHCP message.
   .. zeek:see:: dhcp_message

.. zeek:type:: DHCP::Options

   :Type: :zeek:type:`record`

      options: :zeek:type:`index_vec` :zeek:attr:`&optional`
         The ordered list of all DHCP option numbers.

      subnet_mask: :zeek:type:`addr` :zeek:attr:`&optional`
         Subnet Mask Value (option 1)

      routers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         Router addresses (option 3)

      dns_servers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         DNS Server addresses (option 6)

      host_name: :zeek:type:`string` :zeek:attr:`&optional`
         The Hostname of the client (option 12)

      domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The DNS domain name of the client (option 15)

      forwarding: :zeek:type:`bool` :zeek:attr:`&optional`
         Enable/Disable IP Forwarding (option 19)

      broadcast: :zeek:type:`addr` :zeek:attr:`&optional`
         Broadcast Address (option 28)

      vendor: :zeek:type:`string` :zeek:attr:`&optional`
         Vendor specific data. This can frequently
         be unparsed binary data. (option 43)

      nbns: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         NETBIOS name server list (option 44)

      addr_request: :zeek:type:`addr` :zeek:attr:`&optional`
         Address requested by the client (option 50)

      lease: :zeek:type:`interval` :zeek:attr:`&optional`
         Lease time offered by the server. (option 51)

      serv_addr: :zeek:type:`addr` :zeek:attr:`&optional`
         Server address to allow clients to distinguish
         between lease offers. (option 54)

      param_list: :zeek:type:`index_vec` :zeek:attr:`&optional`
         DHCP Parameter Request list (option 55)

      message: :zeek:type:`string` :zeek:attr:`&optional`
         Textual error message (option 56)

      max_msg_size: :zeek:type:`count` :zeek:attr:`&optional`
         Maximum Message Size (option 57)

      renewal_time: :zeek:type:`interval` :zeek:attr:`&optional`
         This option specifies the time interval from address
         assignment until the client transitions to the
         RENEWING state. (option 58)

      rebinding_time: :zeek:type:`interval` :zeek:attr:`&optional`
         This option specifies the time interval from address
         assignment until the client transitions to the
         REBINDING state. (option 59)

      vendor_class: :zeek:type:`string` :zeek:attr:`&optional`
         This option is used by DHCP clients to optionally
         identify the vendor type and configuration of a DHCP
         client. (option 60)

      client_id: :zeek:type:`DHCP::ClientID` :zeek:attr:`&optional`
         DHCP Client Identifier (Option 61)

      user_class: :zeek:type:`string` :zeek:attr:`&optional`
         User Class opaque value (Option 77)

      client_fqdn: :zeek:type:`DHCP::ClientFQDN` :zeek:attr:`&optional`
         DHCP Client FQDN (Option 81)

      sub_opt: :zeek:type:`DHCP::SubOpts` :zeek:attr:`&optional`
         DHCP Relay Agent Information Option (Option 82)

      auto_config: :zeek:type:`bool` :zeek:attr:`&optional`
         Auto Config option to let host know if it's allowed to
         auto assign an IP address. (Option 116)

      auto_proxy_config: :zeek:type:`string` :zeek:attr:`&optional`
         URL to find a proxy.pac for auto proxy config (Option 252)

      time_offset: :zeek:type:`int` :zeek:attr:`&optional`
         The offset of the client's subnet in seconds from UTC. (Option 2)

      time_servers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         A list of :rfc:`868` time servers available to the client.
         (Option 4)

      name_servers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         A list of IEN 116 name servers available to the client. (Option 5)

      ntp_servers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         A list of IP addresses indicating NTP servers available to the
         client. (Option 42)


.. zeek:type:: DHCP::SubOpt

   :Type: :zeek:type:`record`

      code: :zeek:type:`count`

      value: :zeek:type:`string`

   DHCP Relay Agent Information Option (Option 82)
   .. zeek:see:: dhcp_message

.. zeek:type:: DHCP::SubOpts

   :Type: :zeek:type:`vector` of :zeek:type:`DHCP::SubOpt`


.. zeek:type:: DNSStats

   :Type: :zeek:type:`record`

      requests: :zeek:type:`count`
         Number of DNS requests made

      successful: :zeek:type:`count`
         Number of successful DNS replies.

      failed: :zeek:type:`count`
         Number of DNS reply failures.

      pending: :zeek:type:`count`
         Current pending queries.

      cached_hosts: :zeek:type:`count`
         Number of cached hosts.

      cached_addresses: :zeek:type:`count`
         Number of cached addresses.

   Statistics related to Zeek's active use of DNS.  These numbers are
   about Zeek performing DNS queries on it's own, not traffic
   being seen.
   
   .. zeek:see:: get_dns_stats

.. zeek:type:: EncapsulatingConnVector

   :Type: :zeek:type:`vector` of :zeek:type:`Tunnel::EncapsulatingConn`

   A type alias for a vector of encapsulating "connections", i.e. for when
   there are tunnels within tunnels.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: EventStats

   :Type: :zeek:type:`record`

      queued: :zeek:type:`count`
         Total number of events queued so far.

      dispatched: :zeek:type:`count`
         Total number of events dispatched so far.


.. zeek:type:: FileAnalysisStats

   :Type: :zeek:type:`record`

      current: :zeek:type:`count`
         Current number of files being analyzed.

      max: :zeek:type:`count`
         Maximum number of concurrent files so far.

      cumulative: :zeek:type:`count`
         Cumulative number of files analyzed.

   Statistics of file analysis.
   
   .. zeek:see:: get_file_analysis_stats

.. zeek:type:: GapStats

   :Type: :zeek:type:`record`

      ack_events: :zeek:type:`count`
         How many ack events *could* have had gaps.

      ack_bytes: :zeek:type:`count`
         How many bytes those covered.

      gap_events: :zeek:type:`count`
         How many *did* have gaps.

      gap_bytes: :zeek:type:`count`
         How many bytes were missing in the gaps.

   Statistics about number of gaps in TCP connections.
   
   .. zeek:see:: get_gap_stats

.. zeek:type:: IPAddrAnonymization

   :Type: :zeek:type:`enum`

      .. zeek:enum:: KEEP_ORIG_ADDR IPAddrAnonymization

      .. zeek:enum:: SEQUENTIALLY_NUMBERED IPAddrAnonymization

      .. zeek:enum:: RANDOM_MD5 IPAddrAnonymization

      .. zeek:enum:: PREFIX_PRESERVING_A50 IPAddrAnonymization

      .. zeek:enum:: PREFIX_PRESERVING_MD5 IPAddrAnonymization

   .. zeek:see:: anonymize_addr

.. zeek:type:: IPAddrAnonymizationClass

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ORIG_ADDR IPAddrAnonymizationClass

      .. zeek:enum:: RESP_ADDR IPAddrAnonymizationClass

      .. zeek:enum:: OTHER_ADDR IPAddrAnonymizationClass

   .. zeek:see:: anonymize_addr

.. zeek:type:: JSON::TimestampFormat

   :Type: :zeek:type:`enum`

      .. zeek:enum:: JSON::TS_EPOCH JSON::TimestampFormat

         Timestamps will be formatted as UNIX epoch doubles.  This is
         the format that Zeek typically writes out timestamps.

      .. zeek:enum:: JSON::TS_MILLIS JSON::TimestampFormat

         Timestamps will be formatted as unsigned integers that
         represent the number of milliseconds since the UNIX
         epoch.

      .. zeek:enum:: JSON::TS_ISO8601 JSON::TimestampFormat

         Timestamps will be formatted in the ISO8601 DateTime format.
         Subseconds are also included which isn't actually part of the
         standard but most consumers that parse ISO8601 seem to be able
         to cope with that.


.. zeek:type:: KRB::AP_Options

   :Type: :zeek:type:`record`

      use_session_key: :zeek:type:`bool`
         Indicates that user-to-user-authentication is in use

      mutual_required: :zeek:type:`bool`
         Mutual authentication is required

   AP Options. See :rfc:`4120`

.. zeek:type:: KRB::Error_Msg

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count` :zeek:attr:`&optional`
         Protocol version number (5 for KRB5)

      msg_type: :zeek:type:`count` :zeek:attr:`&optional`
         The message type (30 for ERROR_MSG)

      client_time: :zeek:type:`time` :zeek:attr:`&optional`
         Current time on the client

      server_time: :zeek:type:`time` :zeek:attr:`&optional`
         Current time on the server

      error_code: :zeek:type:`count`
         The specific error code

      client_realm: :zeek:type:`string` :zeek:attr:`&optional`
         Realm of the ticket

      client_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name on the ticket

      service_realm: :zeek:type:`string` :zeek:attr:`&optional`
         Realm of the service

      service_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name of the service

      error_text: :zeek:type:`string` :zeek:attr:`&optional`
         Additional text to explain the error

      pa_data: :zeek:type:`vector` of :zeek:type:`KRB::Type_Value` :zeek:attr:`&optional`
         Optional pre-authentication data

   The data from the ERROR_MSG message. See :rfc:`4120`.

.. zeek:type:: KRB::Host_Address

   :Type: :zeek:type:`record`

      ip: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         IPv4 or IPv6 address

      netbios: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         NetBIOS address

      unknown: :zeek:type:`KRB::Type_Value` :zeek:attr:`&optional`
         Some other type that we don't support yet

   A Kerberos host address See :rfc:`4120`.

.. zeek:type:: KRB::Host_Address_Vector

   :Type: :zeek:type:`vector` of :zeek:type:`KRB::Host_Address`


.. zeek:type:: KRB::KDC_Options

   :Type: :zeek:type:`record`

      forwardable: :zeek:type:`bool`
         The ticket to be issued should have its forwardable flag set.

      forwarded: :zeek:type:`bool`
         A (TGT) request for forwarding.

      proxiable: :zeek:type:`bool`
         The ticket to be issued should have its proxiable flag set.

      proxy: :zeek:type:`bool`
         A request for a proxy.

      allow_postdate: :zeek:type:`bool`
         The ticket to be issued should have its may-postdate flag set.

      postdated: :zeek:type:`bool`
         A request for a postdated ticket.

      renewable: :zeek:type:`bool`
         The ticket to be issued should have its renewable  flag set.

      opt_hardware_auth: :zeek:type:`bool`
         Reserved for opt_hardware_auth

      disable_transited_check: :zeek:type:`bool`
         Request that the KDC not check the transited field of a TGT against
         the policy of the local realm before it will issue derivative tickets
         based on the TGT.

      renewable_ok: :zeek:type:`bool`
         If a ticket with the requested lifetime cannot be issued, a renewable
         ticket is acceptable

      enc_tkt_in_skey: :zeek:type:`bool`
         The ticket for the end server is to be encrypted in the session key
         from the additional TGT provided

      renew: :zeek:type:`bool`
         The request is for a renewal

      validate: :zeek:type:`bool`
         The request is to validate a postdated ticket.

   KDC Options. See :rfc:`4120`

.. zeek:type:: KRB::KDC_Request

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :zeek:type:`count`
         The message type (10 for AS_REQ, 12 for TGS_REQ)

      pa_data: :zeek:type:`vector` of :zeek:type:`KRB::Type_Value` :zeek:attr:`&optional`
         Optional pre-authentication data

      kdc_options: :zeek:type:`KRB::KDC_Options` :zeek:attr:`&optional`
         Options specified in the request

      client_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name on the ticket

      service_realm: :zeek:type:`string` :zeek:attr:`&optional`
         Realm of the service

      service_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name of the service

      from: :zeek:type:`time` :zeek:attr:`&optional`
         Time the ticket is good from

      till: :zeek:type:`time` :zeek:attr:`&optional`
         Time the ticket is good till

      rtime: :zeek:type:`time` :zeek:attr:`&optional`
         The requested renew-till time

      nonce: :zeek:type:`count` :zeek:attr:`&optional`
         A random nonce generated by the client

      encryption_types: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&optional`
         The desired encryption algorithms, in order of preference

      host_addrs: :zeek:type:`vector` of :zeek:type:`KRB::Host_Address` :zeek:attr:`&optional`
         Any additional addresses the ticket should be valid for

      additional_tickets: :zeek:type:`vector` of :zeek:type:`KRB::Ticket` :zeek:attr:`&optional`
         Additional tickets may be included for certain transactions

   The data from the AS_REQ and TGS_REQ messages. See :rfc:`4120`.

.. zeek:type:: KRB::KDC_Response

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :zeek:type:`count`
         The message type (11 for AS_REP, 13 for TGS_REP)

      pa_data: :zeek:type:`vector` of :zeek:type:`KRB::Type_Value` :zeek:attr:`&optional`
         Optional pre-authentication data

      client_realm: :zeek:type:`string` :zeek:attr:`&optional`
         Realm on the ticket

      client_name: :zeek:type:`string`
         Name on the service

      ticket: :zeek:type:`KRB::Ticket`
         The ticket that was issued

   The data from the AS_REQ and TGS_REQ messages. See :rfc:`4120`.

.. zeek:type:: KRB::SAFE_Msg

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :zeek:type:`count`
         The message type (20 for SAFE_MSG)

      data: :zeek:type:`string`
         The application-specific data that is being passed
         from the sender to the reciever

      timestamp: :zeek:type:`time` :zeek:attr:`&optional`
         Current time from the sender of the message

      seq: :zeek:type:`count` :zeek:attr:`&optional`
         Sequence number used to detect replays

      sender: :zeek:type:`KRB::Host_Address` :zeek:attr:`&optional`
         Sender address

      recipient: :zeek:type:`KRB::Host_Address` :zeek:attr:`&optional`
         Recipient address

   The data from the SAFE message. See :rfc:`4120`.

.. zeek:type:: KRB::Ticket

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count`
         Protocol version number (5 for KRB5)

      realm: :zeek:type:`string`
         Realm

      service_name: :zeek:type:`string`
         Name of the service

      cipher: :zeek:type:`count`
         Cipher the ticket was encrypted with

      ciphertext: :zeek:type:`string` :zeek:attr:`&optional`
         Cipher text of the ticket

      authenticationinfo: :zeek:type:`string` :zeek:attr:`&optional`
         Authentication info

   A Kerberos ticket. See :rfc:`4120`.

.. zeek:type:: KRB::Ticket_Vector

   :Type: :zeek:type:`vector` of :zeek:type:`KRB::Ticket`


.. zeek:type:: KRB::Type_Value

   :Type: :zeek:type:`record`

      data_type: :zeek:type:`count`
         The data type

      val: :zeek:type:`string`
         The data value

   Used in a few places in the Kerberos analyzer for elements
   that have a type and a string value.

.. zeek:type:: KRB::Type_Value_Vector

   :Type: :zeek:type:`vector` of :zeek:type:`KRB::Type_Value`


.. zeek:type:: MOUNT3::dirmntargs_t

   :Type: :zeek:type:`record`

      dirname: :zeek:type:`string`
         Name of directory to mount

   MOUNT *mnt* arguments.
   
   .. zeek:see:: mount_proc_mnt

.. zeek:type:: MOUNT3::info_t

   :Type: :zeek:type:`record`

      rpc_stat: :zeek:type:`rpc_status`
         The RPC status.

      mnt_stat: :zeek:type:`MOUNT3::status_t`
         The MOUNT status.

      req_start: :zeek:type:`time`
         The start time of the request.

      req_dur: :zeek:type:`interval`
         The duration of the request.

      req_len: :zeek:type:`count`
         The length in bytes of the request.

      rep_start: :zeek:type:`time`
         The start time of the reply.

      rep_dur: :zeek:type:`interval`
         The duration of the reply.

      rep_len: :zeek:type:`count`
         The length in bytes of the reply.

      rpc_uid: :zeek:type:`count`
         The user id of the reply.

      rpc_gid: :zeek:type:`count`
         The group id of the reply.

      rpc_stamp: :zeek:type:`count`
         The stamp of the reply.

      rpc_machine_name: :zeek:type:`string`
         The machine name of the reply.

      rpc_auxgids: :zeek:type:`index_vec`
         The auxiliary ids of the reply.

   Record summarizing the general results and status of MOUNT3
   request/reply pairs.
   
   Note that when *rpc_stat* or *mount_stat* indicates not successful,
   the reply record passed to the corresponding event will be empty and
   contain uninitialized fields, so don't use it. Also note that time

.. zeek:type:: MOUNT3::mnt_reply_t

   :Type: :zeek:type:`record`

      dirfh: :zeek:type:`string` :zeek:attr:`&optional`
         Dir handle

      auth_flavors: :zeek:type:`vector` of :zeek:type:`MOUNT3::auth_flavor_t` :zeek:attr:`&optional`
         Returned authentication flavors

   MOUNT lookup reply. If the mount failed, *dir_attr* may be set. If the
   mount succeeded, *fh* is always set.
   
   .. zeek:see:: mount_proc_mnt

.. zeek:type:: MQTT::ConnectAckMsg

   :Type: :zeek:type:`record`

      return_code: :zeek:type:`count`
         Return code from the connack message

      session_present: :zeek:type:`bool`
         The Session present flag helps the client
         establish whether the Client and Server
         have a consistent view about whether there
         is already stored Session state.


.. zeek:type:: MQTT::ConnectMsg

   :Type: :zeek:type:`record`

      protocol_name: :zeek:type:`string`
         Protocol name

      protocol_version: :zeek:type:`count`
         Protocol version

      client_id: :zeek:type:`string`
         Identifies the Client to the Server.

      keep_alive: :zeek:type:`interval`
         The maximum time interval that is permitted to elapse between the
         point at which the Client finishes transmitting one Control Packet
         and the point it starts sending the next.

      clean_session: :zeek:type:`bool`
         The clean_session flag indicates if the server should or shouldn't
         use a clean session or use existing previous session state.

      will_retain: :zeek:type:`bool`
         Specifies if the Will Message is to be retained when it is published.

      will_qos: :zeek:type:`count`
         Specifies the QoS level to be used when publishing the Will Message.

      will_topic: :zeek:type:`string` :zeek:attr:`&optional`
         Topic to publish the Will message to.

      will_msg: :zeek:type:`string` :zeek:attr:`&optional`
         The actual Will message to publish.

      username: :zeek:type:`string` :zeek:attr:`&optional`
         Username to use for authentication to the server.

      password: :zeek:type:`string` :zeek:attr:`&optional`
         Pass to use for authentication to the server.


.. zeek:type:: MQTT::PublishMsg

   :Type: :zeek:type:`record`

      dup: :zeek:type:`bool`
         Indicates if this is the first attempt at publishing the message.

      qos: :zeek:type:`count`
         Indicates what level of QoS is enabled for this message.

      retain: :zeek:type:`bool`
         Indicates if the server should retain this message so that clients
         subscribing to the topic in the future will receive this message
         automatically.

      topic: :zeek:type:`string`
         Name of the topic the published message is directed into.

      payload: :zeek:type:`string`
         Payload of the published message.

      payload_len: :zeek:type:`count`
         The actual length of the payload in the case the *payload*
         field's contents were truncated according to
         :zeek:see:`MQTT::max_payload_size`.


.. zeek:type:: MatcherStats

   :Type: :zeek:type:`record`

      matchers: :zeek:type:`count`
         Number of distinct RE matchers.

      nfa_states: :zeek:type:`count`
         Number of NFA states across all matchers.

      dfa_states: :zeek:type:`count`
         Number of DFA states across all matchers.

      computed: :zeek:type:`count`
         Number of computed DFA state transitions.

      mem: :zeek:type:`count`
         Number of bytes used by DFA states.

      hits: :zeek:type:`count`
         Number of cache hits.

      misses: :zeek:type:`count`
         Number of cache misses.

   Statistics of all regular expression matchers.
   
   .. zeek:see:: get_matcher_stats

.. zeek:type:: ModbusCoils

   :Type: :zeek:type:`vector` of :zeek:type:`bool`

   A vector of boolean values that indicate the setting
   for a range of modbus coils.

.. zeek:type:: ModbusHeaders

   :Type: :zeek:type:`record`

      tid: :zeek:type:`count`
         Transaction identifier

      pid: :zeek:type:`count`
         Protocol identifier

      uid: :zeek:type:`count`
         Unit identifier (previously 'slave address')

      function_code: :zeek:type:`count`
         MODBUS function code


.. zeek:type:: ModbusRegisters

   :Type: :zeek:type:`vector` of :zeek:type:`count`

   A vector of count values that represent 16bit modbus
   register values.

.. zeek:type:: NFS3::delobj_reply_t

   :Type: :zeek:type:`record`

      dir_pre_attr: :zeek:type:`NFS3::wcc_attr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ dir.

      dir_post_attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ dir.

   NFS reply for *remove*, *rmdir*. Corresponds to *wcc_data* in the spec.
   
   .. zeek:see:: nfs_proc_remove nfs_proc_rmdir

.. zeek:type:: NFS3::direntry_t

   :Type: :zeek:type:`record`

      fileid: :zeek:type:`count`
         E.g., inode number.

      fname: :zeek:type:`string`
         Filename.

      cookie: :zeek:type:`count`
         Cookie value.

      attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         *readdirplus*: the *fh* attributes for the entry.

      fh: :zeek:type:`string` :zeek:attr:`&optional`
         *readdirplus*: the *fh* for the entry

   NFS *direntry*.  *fh* and *attr* are used for *readdirplus*. However,
   even for *readdirplus* they may not be filled out.
   
   .. zeek:see:: NFS3::direntry_vec_t NFS3::readdir_reply_t

.. zeek:type:: NFS3::direntry_vec_t

   :Type: :zeek:type:`vector` of :zeek:type:`NFS3::direntry_t`

   Vector of NFS *direntry*.
   
   .. zeek:see:: NFS3::readdir_reply_t

.. zeek:type:: NFS3::diropargs_t

   :Type: :zeek:type:`record`

      dirfh: :zeek:type:`string`
         The file handle of the directory.

      fname: :zeek:type:`string`
         The name of the file we are interested in.

   NFS *readdir* arguments.
   
   .. zeek:see:: nfs_proc_readdir

.. zeek:type:: NFS3::fattr_t

   :Type: :zeek:type:`record`

      ftype: :zeek:type:`NFS3::file_type_t`
         File type.

      mode: :zeek:type:`count`
         Mode

      nlink: :zeek:type:`count`
         Number of links.

      uid: :zeek:type:`count`
         User ID.

      gid: :zeek:type:`count`
         Group ID.

      size: :zeek:type:`count`
         Size.

      used: :zeek:type:`count`
         TODO.

      rdev1: :zeek:type:`count`
         TODO.

      rdev2: :zeek:type:`count`
         TODO.

      fsid: :zeek:type:`count`
         TODO.

      fileid: :zeek:type:`count`
         TODO.

      atime: :zeek:type:`time`
         Time of last access.

      mtime: :zeek:type:`time`
         Time of last modification.

      ctime: :zeek:type:`time`
         Time of creation.

   NFS file attributes. Field names are based on RFC 1813.
   
   .. zeek:see:: nfs_proc_getattr

.. zeek:type:: NFS3::fsstat_t

   :Type: :zeek:type:`record`

      attrs: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Attributes.

      tbytes: :zeek:type:`double`
         TODO.

      fbytes: :zeek:type:`double`
         TODO.

      abytes: :zeek:type:`double`
         TODO.

      tfiles: :zeek:type:`double`
         TODO.

      ffiles: :zeek:type:`double`
         TODO.

      afiles: :zeek:type:`double`
         TODO.

      invarsec: :zeek:type:`interval`
         TODO.

   NFS *fsstat*.

.. zeek:type:: NFS3::info_t

   :Type: :zeek:type:`record`

      rpc_stat: :zeek:type:`rpc_status`
         The RPC status.

      nfs_stat: :zeek:type:`NFS3::status_t`
         The NFS status.

      req_start: :zeek:type:`time`
         The start time of the request.

      req_dur: :zeek:type:`interval`
         The duration of the request.

      req_len: :zeek:type:`count`
         The length in bytes of the request.

      rep_start: :zeek:type:`time`
         The start time of the reply.

      rep_dur: :zeek:type:`interval`
         The duration of the reply.

      rep_len: :zeek:type:`count`
         The length in bytes of the reply.

      rpc_uid: :zeek:type:`count`
         The user id of the reply.

      rpc_gid: :zeek:type:`count`
         The group id of the reply.

      rpc_stamp: :zeek:type:`count`
         The stamp of the reply.

      rpc_machine_name: :zeek:type:`string`
         The machine name of the reply.

      rpc_auxgids: :zeek:type:`index_vec`
         The auxiliary ids of the reply.

   Record summarizing the general results and status of NFSv3
   request/reply pairs.
   
   Note that when *rpc_stat* or *nfs_stat* indicates not successful,
   the reply record passed to the corresponding event will be empty and
   contain uninitialized fields, so don't use it. Also note that time
   and duration values might not be fully accurate. For TCP, we record
   times when the corresponding chunk of data is delivered to the
   analyzer. Depending on the reassembler, this might be well after the
   first packet of the request was received.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup
      nfs_proc_mkdir nfs_proc_not_implemented nfs_proc_null
      nfs_proc_read nfs_proc_readdir nfs_proc_readlink nfs_proc_remove
      nfs_proc_rmdir nfs_proc_write nfs_reply_status

.. zeek:type:: NFS3::link_reply_t

   :Type: :zeek:type:`record`

      post_attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Optional post-operation attributes of the file system object identified by file

      preattr: :zeek:type:`NFS3::wcc_attr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ file.

      postattr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ file.

   NFS *link* reply.
   
   .. zeek:see:: nfs_proc_link

.. zeek:type:: NFS3::linkargs_t

   :Type: :zeek:type:`record`

      fh: :zeek:type:`string`
         The file handle for the existing file system object.

      link: :zeek:type:`NFS3::diropargs_t`
         The location of the link to be created.

   NFS *link* arguments.
   
   .. zeek:see:: nfs_proc_link

.. zeek:type:: NFS3::lookup_reply_t

   :Type: :zeek:type:`record`

      fh: :zeek:type:`string` :zeek:attr:`&optional`
         File handle of object looked up.

      obj_attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ file

      dir_attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ dir.

   NFS lookup reply. If the lookup failed, *dir_attr* may be set. If the
   lookup succeeded, *fh* is always set and *obj_attr* and *dir_attr*
   may be set.
   
   .. zeek:see:: nfs_proc_lookup

.. zeek:type:: NFS3::newobj_reply_t

   :Type: :zeek:type:`record`

      fh: :zeek:type:`string` :zeek:attr:`&optional`
         File handle of object created.

      obj_attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ new object.

      dir_pre_attr: :zeek:type:`NFS3::wcc_attr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ dir.

      dir_post_attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ dir.

   NFS reply for *create*, *mkdir*, and *symlink*. If the proc
   failed, *dir_\*_attr* may be set. If the proc succeeded, *fh* and the
   *attr*'s may be set. Note: no guarantee that *fh* is set after
   success.
   
   .. zeek:see:: nfs_proc_create nfs_proc_mkdir

.. zeek:type:: NFS3::read_reply_t

   :Type: :zeek:type:`record`

      attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Attributes.

      size: :zeek:type:`count` :zeek:attr:`&optional`
         Number of bytes read.

      eof: :zeek:type:`bool` :zeek:attr:`&optional`
         Sid the read end at EOF.

      data: :zeek:type:`string` :zeek:attr:`&optional`
         The actual data; not yet implemented.

   NFS *read* reply. If the lookup fails, *attr* may be set. If the
   lookup succeeds, *attr* may be set and all other fields are set.

.. zeek:type:: NFS3::readargs_t

   :Type: :zeek:type:`record`

      fh: :zeek:type:`string`
         File handle to read from.

      offset: :zeek:type:`count`
         Offset in file.

      size: :zeek:type:`count`
         Number of bytes to read.

   NFS *read* arguments.
   
   .. zeek:see:: nfs_proc_read

.. zeek:type:: NFS3::readdir_reply_t

   :Type: :zeek:type:`record`

      isplus: :zeek:type:`bool`
         True if the reply for a *readdirplus* request.

      dir_attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Directory attributes.

      cookieverf: :zeek:type:`count` :zeek:attr:`&optional`
         TODO.

      entries: :zeek:type:`NFS3::direntry_vec_t` :zeek:attr:`&optional`
         Returned directory entries.

      eof: :zeek:type:`bool`
         If true, no more entries in directory.

   NFS *readdir* reply. Used for *readdir* and *readdirplus*. If an is
   returned, *dir_attr* might be set. On success, *dir_attr* may be set,
   all others must be set.

.. zeek:type:: NFS3::readdirargs_t

   :Type: :zeek:type:`record`

      isplus: :zeek:type:`bool`
         Is this a readdirplus request?

      dirfh: :zeek:type:`string`
         The directory filehandle.

      cookie: :zeek:type:`count`
         Cookie / pos in dir; 0 for first call.

      cookieverf: :zeek:type:`count`
         The cookie verifier.

      dircount: :zeek:type:`count`
         "count" field for readdir; maxcount otherwise (in bytes).

      maxcount: :zeek:type:`count` :zeek:attr:`&optional`
         Only used for readdirplus. in bytes.

   NFS *readdir* arguments. Used for both *readdir* and *readdirplus*.
   
   .. zeek:see:: nfs_proc_readdir

.. zeek:type:: NFS3::readlink_reply_t

   :Type: :zeek:type:`record`

      attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Attributes.

      nfspath: :zeek:type:`string` :zeek:attr:`&optional`
         Contents of the symlink; in general a pathname as text.

   NFS *readline* reply. If the request fails, *attr* may be set. If the
   request succeeds, *attr* may be set and all other fields are set.
   
   .. zeek:see:: nfs_proc_readlink

.. zeek:type:: NFS3::renameobj_reply_t

   :Type: :zeek:type:`record`

      src_dir_pre_attr: :zeek:type:`NFS3::wcc_attr_t`

      src_dir_post_attr: :zeek:type:`NFS3::fattr_t`

      dst_dir_pre_attr: :zeek:type:`NFS3::wcc_attr_t`

      dst_dir_post_attr: :zeek:type:`NFS3::fattr_t`

   NFS reply for *rename*. Corresponds to *wcc_data* in the spec.
   
   .. zeek:see:: nfs_proc_rename

.. zeek:type:: NFS3::renameopargs_t

   :Type: :zeek:type:`record`

      src_dirfh: :zeek:type:`string`

      src_fname: :zeek:type:`string`

      dst_dirfh: :zeek:type:`string`

      dst_fname: :zeek:type:`string`

   NFS *rename* arguments.
   
   .. zeek:see:: nfs_proc_rename

.. zeek:type:: NFS3::sattr_reply_t

   :Type: :zeek:type:`record`

      dir_pre_attr: :zeek:type:`NFS3::wcc_attr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ dir.

      dir_post_attr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Optional attributes associated w/ dir.

   NFS *sattr* reply. If the request fails, *pre|post* attr may be set.
   If the request succeeds, *pre|post* attr are set.
   

.. zeek:type:: NFS3::sattr_t

   :Type: :zeek:type:`record`

      mode: :zeek:type:`count` :zeek:attr:`&optional`
         Mode

      uid: :zeek:type:`count` :zeek:attr:`&optional`
         User ID.

      gid: :zeek:type:`count` :zeek:attr:`&optional`
         Group ID.

      size: :zeek:type:`count` :zeek:attr:`&optional`
         Size.

      atime: :zeek:type:`NFS3::time_how_t` :zeek:attr:`&optional`
         Time of last access.

      mtime: :zeek:type:`NFS3::time_how_t` :zeek:attr:`&optional`
         Time of last modification.

   NFS file attributes. Field names are based on RFC 1813.
   
   .. zeek:see:: nfs_proc_sattr

.. zeek:type:: NFS3::sattrargs_t

   :Type: :zeek:type:`record`

      fh: :zeek:type:`string`
         The file handle for the existing file system object.

      new_attributes: :zeek:type:`NFS3::sattr_t`
         The new attributes for the file.

   NFS *sattr* arguments.
   
   .. zeek:see:: nfs_proc_sattr

.. zeek:type:: NFS3::symlinkargs_t

   :Type: :zeek:type:`record`

      link: :zeek:type:`NFS3::diropargs_t`
         The location of the link to be created.

      symlinkdata: :zeek:type:`NFS3::symlinkdata_t`
         The symbolic link to be created.

   NFS *symlink* arguments.
   
   .. zeek:see:: nfs_proc_symlink

.. zeek:type:: NFS3::symlinkdata_t

   :Type: :zeek:type:`record`

      symlink_attributes: :zeek:type:`NFS3::sattr_t`
         The initial attributes for the symbolic link

      nfspath: :zeek:type:`string` :zeek:attr:`&optional`
         The string containing the symbolic link data.

   NFS symlinkdata attributes. Field names are based on RFC 1813
   
   .. zeek:see:: nfs_proc_symlink

.. zeek:type:: NFS3::wcc_attr_t

   :Type: :zeek:type:`record`

      size: :zeek:type:`count`
         The size.

      atime: :zeek:type:`time`
         Access time.

      mtime: :zeek:type:`time`
         Modification time.

   NFS *wcc* attributes.
   
   .. zeek:see:: NFS3::write_reply_t

.. zeek:type:: NFS3::write_reply_t

   :Type: :zeek:type:`record`

      preattr: :zeek:type:`NFS3::wcc_attr_t` :zeek:attr:`&optional`
         Pre operation attributes.

      postattr: :zeek:type:`NFS3::fattr_t` :zeek:attr:`&optional`
         Post operation attributes.

      size: :zeek:type:`count` :zeek:attr:`&optional`
         Size.

      commited: :zeek:type:`NFS3::stable_how_t` :zeek:attr:`&optional`
         TODO.

      verf: :zeek:type:`count` :zeek:attr:`&optional`
         Write verifier cookie.

   NFS *write* reply. If the request fails, *pre|post* attr may be set.
   If the request succeeds, *pre|post* attr may be set and all other
   fields are set.
   
   .. zeek:see:: nfs_proc_write

.. zeek:type:: NFS3::writeargs_t

   :Type: :zeek:type:`record`

      fh: :zeek:type:`string`
         File handle to write to.

      offset: :zeek:type:`count`
         Offset in file.

      size: :zeek:type:`count`
         Number of bytes to write.

      stable: :zeek:type:`NFS3::stable_how_t`
         How and when data is commited.

      data: :zeek:type:`string` :zeek:attr:`&optional`
         The actual data; not implemented yet.

   NFS *write* arguments.
   
   .. zeek:see:: nfs_proc_write

.. zeek:type:: NTLM::AVs

   :Type: :zeek:type:`record`

      nb_computer_name: :zeek:type:`string`
         The server's NetBIOS computer name

      nb_domain_name: :zeek:type:`string`
         The server's NetBIOS domain name

      dns_computer_name: :zeek:type:`string` :zeek:attr:`&optional`
         The FQDN of the computer

      dns_domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The FQDN of the domain

      dns_tree_name: :zeek:type:`string` :zeek:attr:`&optional`
         The FQDN of the forest

      constrained_auth: :zeek:type:`bool` :zeek:attr:`&optional`
         Indicates to the client that the account
         authentication is constrained

      timestamp: :zeek:type:`time` :zeek:attr:`&optional`
         The associated timestamp, if present

      single_host_id: :zeek:type:`count` :zeek:attr:`&optional`
         Indicates that the client is providing
         a machine ID created at computer startup to
         identify the calling machine

      target_name: :zeek:type:`string` :zeek:attr:`&optional`
         The SPN of the target server


.. zeek:type:: NTLM::Authenticate

   :Type: :zeek:type:`record`

      flags: :zeek:type:`NTLM::NegotiateFlags`
         The negotiate flags

      domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The domain or computer name hosting the account

      user_name: :zeek:type:`string` :zeek:attr:`&optional`
         The name of the user to be authenticated.

      workstation: :zeek:type:`string` :zeek:attr:`&optional`
         The name of the computer to which the user was logged on.

      session_key: :zeek:type:`string` :zeek:attr:`&optional`
         The session key

      version: :zeek:type:`NTLM::Version` :zeek:attr:`&optional`
         The Windows version information, if supplied


.. zeek:type:: NTLM::Challenge

   :Type: :zeek:type:`record`

      flags: :zeek:type:`NTLM::NegotiateFlags`
         The negotiate flags

      target_name: :zeek:type:`string` :zeek:attr:`&optional`
         The server authentication realm. If the server is
         domain-joined, the name of the domain. Otherwise
         the server name. See flags.target_type_domain
         and flags.target_type_server

      version: :zeek:type:`NTLM::Version` :zeek:attr:`&optional`
         The Windows version information, if supplied

      target_info: :zeek:type:`NTLM::AVs` :zeek:attr:`&optional`
         Attribute-value pairs specified by the server


.. zeek:type:: NTLM::Negotiate

   :Type: :zeek:type:`record`

      flags: :zeek:type:`NTLM::NegotiateFlags`
         The negotiate flags

      domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The domain name of the client, if known

      workstation: :zeek:type:`string` :zeek:attr:`&optional`
         The machine name of the client, if known

      version: :zeek:type:`NTLM::Version` :zeek:attr:`&optional`
         The Windows version information, if supplied


.. zeek:type:: NTLM::NegotiateFlags

   :Type: :zeek:type:`record`

      negotiate_56: :zeek:type:`bool`
         If set, requires 56-bit encryption

      negotiate_key_exch: :zeek:type:`bool`
         If set, requests an explicit key exchange

      negotiate_128: :zeek:type:`bool`
         If set, requests 128-bit session key negotiation

      negotiate_version: :zeek:type:`bool`
         If set, requests the protocol version number

      negotiate_target_info: :zeek:type:`bool`
         If set, indicates that the TargetInfo fields in the
         CHALLENGE_MESSAGE are populated

      request_non_nt_session_key: :zeek:type:`bool`
         If set, requests the usage of the LMOWF function

      negotiate_identify: :zeek:type:`bool`
         If set, requests and identify level token

      negotiate_extended_sessionsecurity: :zeek:type:`bool`
         If set, requests usage of NTLM v2 session security
         Note: NTML v2 session security is actually NTLM v1

      target_type_server: :zeek:type:`bool`
         If set, TargetName must be a server name

      target_type_domain: :zeek:type:`bool`
         If set, TargetName must be a domain name

      negotiate_always_sign: :zeek:type:`bool`
         If set, requests the presence of a signature block
         on all messages

      negotiate_oem_workstation_supplied: :zeek:type:`bool`
         If set, the workstation name is provided

      negotiate_oem_domain_supplied: :zeek:type:`bool`
         If set, the domain name is provided

      negotiate_anonymous_connection: :zeek:type:`bool`
         If set, the connection should be anonymous

      negotiate_ntlm: :zeek:type:`bool`
         If set, requests usage of NTLM v1

      negotiate_lm_key: :zeek:type:`bool`
         If set, requests LAN Manager session key computation

      negotiate_datagram: :zeek:type:`bool`
         If set, requests connectionless authentication

      negotiate_seal: :zeek:type:`bool`
         If set, requests session key negotiation for message
         confidentiality

      negotiate_sign: :zeek:type:`bool`
         If set, requests session key negotiation for message
         signatures

      request_target: :zeek:type:`bool`
         If set, the TargetName field is present

      negotiate_oem: :zeek:type:`bool`
         If set, requests OEM character set encoding

      negotiate_unicode: :zeek:type:`bool`
         If set, requests Unicode character set encoding


.. zeek:type:: NTLM::Version

   :Type: :zeek:type:`record`

      major: :zeek:type:`count`
         The major version of the Windows operating system in use

      minor: :zeek:type:`count`
         The minor version of the Windows operating system in use

      build: :zeek:type:`count`
         The build number of the Windows operating system in use

      ntlmssp: :zeek:type:`count`
         The current revision of NTLMSSP in use


.. zeek:type:: NTP::ControlMessage

   :Type: :zeek:type:`record`

      op_code: :zeek:type:`count`
         An integer specifying the command function. Values currently defined:
         
         * 1 read status command/response
         * 2 read variables command/response
         * 3 write variables command/response
         * 4 read clock variables command/response
         * 5 write clock variables command/response
         * 6 set trap address/port command/response
         * 7 trap response
         
         Other values are reserved.

      resp_bit: :zeek:type:`bool`
         The response bit. Set to zero for commands, one for responses.

      err_bit: :zeek:type:`bool`
         The error bit. Set to zero for normal response, one for error
         response.

      more_bit: :zeek:type:`bool`
         The more bit. Set to zero for last fragment, one for all others.

      sequence: :zeek:type:`count`
         The sequence number of the command or response.

      status: :zeek:type:`count`
         The current status of the system, peer or clock.

      association_id: :zeek:type:`count`
         A 16-bit integer identifying a valid association.

      data: :zeek:type:`string` :zeek:attr:`&optional`
         Message data for the command or response + Authenticator (optional).

      key_id: :zeek:type:`count` :zeek:attr:`&optional`
         This is an integer identifying the cryptographic
         key used to generate the message-authentication code.

      crypto_checksum: :zeek:type:`string` :zeek:attr:`&optional`
         This is a crypto-checksum computed by the encryption procedure.

   NTP control message as defined in :rfc:`1119` for mode=6
   This record contains the fields used by the NTP protocol
   for control operations.

.. zeek:type:: NTP::Message

   :Type: :zeek:type:`record`

      version: :zeek:type:`count`
         The NTP version number (1, 2, 3, 4).

      mode: :zeek:type:`count`
         The NTP mode being used. Possible values are:
         
           * 1 - symmetric active
           * 2 - symmetric passive
           * 3 - client
           * 4 - server
           * 5 - broadcast
           * 6 - NTP control message
           * 7 - reserved for private use

      std_msg: :zeek:type:`NTP::StandardMessage` :zeek:attr:`&optional`
         If mode 1-5, the standard fields for syncronization operations are
         here.  See :rfc:`5905`

      control_msg: :zeek:type:`NTP::ControlMessage` :zeek:attr:`&optional`
         If mode 6, the fields for control operations are here.
         See :rfc:`1119`

      mode7_msg: :zeek:type:`NTP::Mode7Message` :zeek:attr:`&optional`
         If mode 7, the fields for extra operations are here.
         Note that this is not defined in any RFC
         and is implementation dependent. We used the official implementation
         from the `NTP official project <www.ntp.org>`_.
         A mode 7 packet is used exchanging data between an NTP server
         and a client for purposes other than time synchronization, e.g.
         monitoring, statistics gathering and configuration.

   NTP message as defined in :rfc:`5905`.  Does include fields for mode 7,
   reserved for private use in :rfc:`5905`, but used in some implementation
   for commands such as "monlist".

.. zeek:type:: NTP::Mode7Message

   :Type: :zeek:type:`record`

      req_code: :zeek:type:`count`
         An implementation-specific code which specifies the
         operation to be (which has been) performed and/or the
         format and semantics of the data included in the packet.

      auth_bit: :zeek:type:`bool`
         The authenticated bit. If set, this packet is authenticated.

      sequence: :zeek:type:`count`
         For a multipacket response, contains the sequence
         number of this packet.  0 is the first in the sequence,
         127 (or less) is the last.  The More Bit must be set in
         all packets but the last.

      implementation: :zeek:type:`count`
         The number of the implementation this request code
         is defined by.  An implementation number of zero is used
         for requst codes/data formats which all implementations
         agree on.  Implementation number 255 is reserved (for
         extensions, in case we run out).

      err: :zeek:type:`count`
         Must be 0 for a request.  For a response, holds an error
         code relating to the request.  If nonzero, the operation
         requested wasn't performed.
         
           * 0 - no error
           * 1 - incompatible implementation number
           * 2 - unimplemented request code
           * 3 - format error (wrong data items, data size, packet size etc.)
           * 4 - no data available (e.g. request for details on unknown peer)
           * 5 - unknown
           * 6 - unknown
           * 7 - authentication failure (i.e. permission denied)

      data: :zeek:type:`string` :zeek:attr:`&optional`
         Rest of data

   NTP mode 7 message. Note that this is not defined in any RFC and is
   implementation dependent. We used the official implementation from the
   `NTP official project <www.ntp.org>`_.  A mode 7 packet is used
   exchanging data between an NTP server and a client for purposes other
   than time synchronization, e.g.  monitoring, statistics gathering and
   configuration.  For details see the documentation from the `NTP official
   project <www.ntp.org>`_, code v. ntp-4.2.8p13, in include/ntp_request.h.

.. zeek:type:: NTP::StandardMessage

   :Type: :zeek:type:`record`

      stratum: :zeek:type:`count`
         This value mainly identifies the type of server (primary server,
         secondary server, etc.). Possible values, as in :rfc:`5905`, are:
         
           * 0 -> unspecified or invalid
           * 1 -> primary server (e.g., equipped with a GPS receiver)
           * 2-15 -> secondary server (via NTP)
           * 16 -> unsynchronized
           * 17-255 -> reserved
         
         For stratum 0, a *kiss_code* can be given for debugging and
         monitoring.

      poll: :zeek:type:`interval`
         The maximum interval between successive messages.

      precision: :zeek:type:`interval`
         The precision of the system clock.

      root_delay: :zeek:type:`interval`
         Root delay. The total round-trip delay to the reference clock.

      root_disp: :zeek:type:`interval`
         Root Dispersion. The total dispersion to the reference clock.

      kiss_code: :zeek:type:`string` :zeek:attr:`&optional`
         For stratum 0, four-character ASCII string used for debugging and
         monitoring. Values are defined in :rfc:`1345`.

      ref_id: :zeek:type:`string` :zeek:attr:`&optional`
         Reference ID. For stratum 1, this is the ID assigned to the
         reference clock by IANA.
         For example: GOES, GPS, GAL, etc. (see :rfc:`5905`)

      ref_addr: :zeek:type:`addr` :zeek:attr:`&optional`
         Above stratum 1, when using IPv4, the IP address of the reference
         clock.  Note that the NTP protocol did not originally specify a
         large enough field to represent IPv6 addresses, so they use
         the first four bytes of the MD5 hash of the reference clock's
         IPv6 address (i.e. an IPv4 address here is not necessarily IPv4).

      ref_time: :zeek:type:`time`
         Reference timestamp. Time when the system clock was last set or
         correct.

      org_time: :zeek:type:`time`
         Origin timestamp. Time at the client when the request departed for
         the NTP server.

      rec_time: :zeek:type:`time`
         Receive timestamp. Time at the server when the request arrived from
         the NTP client.

      xmt_time: :zeek:type:`time`
         Transmit timestamp. Time at the server when the response departed

      key_id: :zeek:type:`count` :zeek:attr:`&optional`
         Key used to designate a secret MD5 key.

      digest: :zeek:type:`string` :zeek:attr:`&optional`
         MD5 hash computed over the key followed by the NTP packet header and
         extension fields.

      num_exts: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Number of extension fields (which are not currently parsed).

   NTP standard message as defined in :rfc:`5905` for modes 1-5
   This record contains the standard fields used by the NTP protocol
   for standard syncronization operations.

.. zeek:type:: NetStats

   :Type: :zeek:type:`record`

      pkts_recvd: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Packets received by Zeek.

      pkts_dropped: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Packets reported dropped by the system.

      pkts_link: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Packets seen on the link. Note that this may differ
         from *pkts_recvd* because of a potential capture_filter. See
         :doc:`/scripts/base/frameworks/packet-filter/main.zeek`. Depending on the
         packet capture system, this value may not be available and will then
         be always set to zero.

      bytes_recvd: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Bytes received by Zeek.

   Packet capture statistics.  All counts are cumulative.
   
   .. zeek:see:: get_net_stats

.. zeek:type:: PE::DOSHeader

   :Type: :zeek:type:`record`

      signature: :zeek:type:`string`
         The magic number of a portable executable file ("MZ").

      used_bytes_in_last_page: :zeek:type:`count`
         The number of bytes in the last page that are used.

      file_in_pages: :zeek:type:`count`
         The number of pages in the file that are part of the PE file itself.

      num_reloc_items: :zeek:type:`count`
         Number of relocation entries stored after the header.

      header_in_paragraphs: :zeek:type:`count`
         Number of paragraphs in the header.

      min_extra_paragraphs: :zeek:type:`count`
         Number of paragraps of additional memory that the program will need.

      max_extra_paragraphs: :zeek:type:`count`
         Maximum number of paragraphs of additional memory.

      init_relative_ss: :zeek:type:`count`
         Relative value of the stack segment.

      init_sp: :zeek:type:`count`
         Initial value of the SP register.

      checksum: :zeek:type:`count`
         Checksum. The 16-bit sum of all words in the file should be 0. Normally not set.

      init_ip: :zeek:type:`count`
         Initial value of the IP register.

      init_relative_cs: :zeek:type:`count`
         Initial value of the CS register (relative to the initial segment).

      addr_of_reloc_table: :zeek:type:`count`
         Offset of the first relocation table.

      overlay_num: :zeek:type:`count`
         Overlays allow you to append data to the end of the file. If this is the main program,
         this will be 0.

      oem_id: :zeek:type:`count`
         OEM identifier.

      oem_info: :zeek:type:`count`
         Additional OEM info, specific to oem_id.

      addr_of_new_exe_header: :zeek:type:`count`
         Address of the new EXE header.


.. zeek:type:: PE::FileHeader

   :Type: :zeek:type:`record`

      machine: :zeek:type:`count`
         The target machine that the file was compiled for.

      ts: :zeek:type:`time`
         The time that the file was created at.

      sym_table_ptr: :zeek:type:`count`
         Pointer to the symbol table.

      num_syms: :zeek:type:`count`
         Number of symbols.

      optional_header_size: :zeek:type:`count`
         The size of the optional header.

      characteristics: :zeek:type:`set` [:zeek:type:`count`]
         Bit flags that determine if this file is executable, non-relocatable, and/or a DLL.


.. zeek:type:: PE::OptionalHeader

   :Type: :zeek:type:`record`

      magic: :zeek:type:`count`
         PE32 or PE32+ indicator.

      major_linker_version: :zeek:type:`count`
         The major version of the linker used to create the PE.

      minor_linker_version: :zeek:type:`count`
         The minor version of the linker used to create the PE.

      size_of_code: :zeek:type:`count`
         Size of the .text section.

      size_of_init_data: :zeek:type:`count`
         Size of the .data section.

      size_of_uninit_data: :zeek:type:`count`
         Size of the .bss section.

      addr_of_entry_point: :zeek:type:`count`
         The relative virtual address (RVA) of the entry point.

      base_of_code: :zeek:type:`count`
         The relative virtual address (RVA) of the .text section.

      base_of_data: :zeek:type:`count` :zeek:attr:`&optional`
         The relative virtual address (RVA) of the .data section.

      image_base: :zeek:type:`count`
         Preferred memory location for the image to be based at.

      section_alignment: :zeek:type:`count`
         The alignment (in bytes) of sections when they're loaded in memory.

      file_alignment: :zeek:type:`count`
         The alignment (in bytes) of the raw data of sections.

      os_version_major: :zeek:type:`count`
         The major version of the required OS.

      os_version_minor: :zeek:type:`count`
         The minor version of the required OS.

      major_image_version: :zeek:type:`count`
         The major version of this image.

      minor_image_version: :zeek:type:`count`
         The minor version of this image.

      major_subsys_version: :zeek:type:`count`
         The major version of the subsystem required to run this file.

      minor_subsys_version: :zeek:type:`count`
         The minor version of the subsystem required to run this file.

      size_of_image: :zeek:type:`count`
         The size (in bytes) of the iamge as the image is loaded in memory.

      size_of_headers: :zeek:type:`count`
         The size (in bytes) of the headers, rounded up to file_alignment.

      checksum: :zeek:type:`count`
         The image file checksum.

      subsystem: :zeek:type:`count`
         The subsystem that's required to run this image.

      dll_characteristics: :zeek:type:`set` [:zeek:type:`count`]
         Bit flags that determine how to execute or load this file.

      table_sizes: :zeek:type:`vector` of :zeek:type:`count`
         A vector with the sizes of various tables and strings that are
         defined in the optional header data directories. Examples include
         the import table, the resource table, and debug information.


.. zeek:type:: PE::SectionHeader

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         The name of the section

      virtual_size: :zeek:type:`count`
         The total size of the section when loaded into memory.

      virtual_addr: :zeek:type:`count`
         The relative virtual address (RVA) of the section.

      size_of_raw_data: :zeek:type:`count`
         The size of the initialized data for the section, as it is
         in the file on disk.

      ptr_to_raw_data: :zeek:type:`count`
         The virtual address of the initialized dat for the section,
         as it is in the file on disk.

      ptr_to_relocs: :zeek:type:`count`
         The file pointer to the beginning of relocation entries for
         the section.

      ptr_to_line_nums: :zeek:type:`count`
         The file pointer to the beginning of line-number entries for
         the section.

      num_of_relocs: :zeek:type:`count`
         The number of relocation entries for the section.

      num_of_line_nums: :zeek:type:`count`
         The number of line-number entrie for the section.

      characteristics: :zeek:type:`set` [:zeek:type:`count`]
         Bit-flags that describe the characteristics of the section.

   Record for Portable Executable (PE) section headers.

.. zeek:type:: PacketSource

   :Type: :zeek:type:`record`

      live: :zeek:type:`bool`
         Whether the packet source is a live interface or offline pcap file.

      path: :zeek:type:`string`
         The interface name for a live interface or filesystem path of
         an offline pcap file.

      link_type: :zeek:type:`int`
         The data link-layer type of the packet source.

      netmask: :zeek:type:`count`
         The netmask assoicated with the source or ``NETMASK_UNKNOWN``.

   Properties of an I/O packet source being read by Zeek.

.. zeek:type:: PcapFilterID

   :Type: :zeek:type:`enum`

      .. zeek:enum:: None PcapFilterID

      .. zeek:enum:: PacketFilter::DefaultPcapFilter PcapFilterID

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


      .. zeek:enum:: PacketFilter::FilterTester PcapFilterID

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


   Enum type identifying dynamic BPF filters. These are used by
   :zeek:see:`Pcap::precompile_pcap_filter` and :zeek:see:`Pcap::precompile_pcap_filter`.

.. zeek:type:: ProcStats

   :Type: :zeek:type:`record`

      debug: :zeek:type:`bool`
         True if compiled with --enable-debug.

      start_time: :zeek:type:`time`
         Start time of process.

      real_time: :zeek:type:`interval`
         Elapsed real time since Zeek started running.

      user_time: :zeek:type:`interval`
         User CPU seconds.

      system_time: :zeek:type:`interval`
         System CPU seconds.

      mem: :zeek:type:`count`
         Maximum memory consumed, in KB.

      minor_faults: :zeek:type:`count`
         Page faults not requiring actual I/O.

      major_faults: :zeek:type:`count`
         Page faults requiring actual I/O.

      num_swap: :zeek:type:`count`
         Times swapped out.

      blocking_input: :zeek:type:`count`
         Blocking input operations.

      blocking_output: :zeek:type:`count`
         Blocking output operations.

      num_context: :zeek:type:`count`
         Number of involuntary context switches.

   Statistics about Zeek's process.
   
   .. zeek:see:: get_proc_stats
   
   .. note:: All process-level values refer to Zeek's main process only, not to
      the child process it spawns for doing communication.

.. zeek:type:: RADIUS::AttributeList

   :Type: :zeek:type:`vector` of :zeek:type:`string`


.. zeek:type:: RADIUS::Attributes

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`RADIUS::AttributeList`


.. zeek:type:: RADIUS::Message

   :Type: :zeek:type:`record`

      code: :zeek:type:`count`
         The type of message (Access-Request, Access-Accept, etc.).

      trans_id: :zeek:type:`count`
         The transaction ID.

      authenticator: :zeek:type:`string`
         The "authenticator" string.

      attributes: :zeek:type:`RADIUS::Attributes` :zeek:attr:`&optional`
         Any attributes.


.. zeek:type:: RDP::ClientChannelDef

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         A unique name for the channel

      options: :zeek:type:`count`
         Channel Def raw options as count

      initialized: :zeek:type:`bool`
         Absence of this flag indicates that this channel is
         a placeholder and that the server MUST NOT set it up.

      encrypt_rdp: :zeek:type:`bool`
         Unused, must be ignored by the server.

      encrypt_sc: :zeek:type:`bool`
         Unused, must be ignored by the server.

      encrypt_cs: :zeek:type:`bool`
         Unused, must be ignored by the server.

      pri_high: :zeek:type:`bool`
         Channel data must be sent with high MCS priority.

      pri_med: :zeek:type:`bool`
         Channel data must be sent with medium MCS priority.

      pri_low: :zeek:type:`bool`
         Channel data must be sent with low MCS priority.

      compress_rdp: :zeek:type:`bool`
         Virtual channel data must be compressed if RDP data is being compressed.

      compress: :zeek:type:`bool`
         Virtual channel data must be compressed.

      show_protocol: :zeek:type:`bool`
         Ignored by the server.

      persistent: :zeek:type:`bool`
         Channel must be persistent across remote control transactions.

   Name and flags for a single channel requested by the client.

.. zeek:type:: RDP::ClientChannelList

   :Type: :zeek:type:`vector` of :zeek:type:`RDP::ClientChannelDef`

   The list of channels requested by the client.

.. zeek:type:: RDP::ClientClusterData

   :Type: :zeek:type:`record`

      flags: :zeek:type:`count`
         Cluster information flags.

      redir_session_id: :zeek:type:`count`
         If the *redir_sessionid_field_valid* flag is set, this field
         contains a valid session identifier to which the client requests
         to connect.

      redir_supported: :zeek:type:`bool`
         The client can receive server session redirection packets.
         If this flag is set, the *svr_session_redir_version_mask*
         field MUST contain the server session redirection version that
         the client supports.

      svr_session_redir_version_mask: :zeek:type:`count`
         The server session redirection version that the client supports.

      redir_sessionid_field_valid: :zeek:type:`bool`
         Whether the *redir_session_id* field identifies a session on
         the server to associate with the connection.

      redir_smartcard: :zeek:type:`bool`
         The client logged on with a smart card.

   The TS_UD_CS_CLUSTER data block is sent by the client to the server
   either to advertise that it can support the Server Redirection PDUs
   or to request a connection to a given session identifier.

.. zeek:type:: RDP::ClientCoreData

   :Type: :zeek:type:`record`

      version_major: :zeek:type:`count`

      version_minor: :zeek:type:`count`

      desktop_width: :zeek:type:`count`

      desktop_height: :zeek:type:`count`

      color_depth: :zeek:type:`count`

      sas_sequence: :zeek:type:`count`

      keyboard_layout: :zeek:type:`count`

      client_build: :zeek:type:`count`

      client_name: :zeek:type:`string`

      keyboard_type: :zeek:type:`count`

      keyboard_sub: :zeek:type:`count`

      keyboard_function_key: :zeek:type:`count`

      ime_file_name: :zeek:type:`string`

      post_beta2_color_depth: :zeek:type:`count` :zeek:attr:`&optional`

      client_product_id: :zeek:type:`string` :zeek:attr:`&optional`

      serial_number: :zeek:type:`count` :zeek:attr:`&optional`

      high_color_depth: :zeek:type:`count` :zeek:attr:`&optional`

      supported_color_depths: :zeek:type:`count` :zeek:attr:`&optional`

      ec_flags: :zeek:type:`RDP::EarlyCapabilityFlags` :zeek:attr:`&optional`

      dig_product_id: :zeek:type:`string` :zeek:attr:`&optional`


.. zeek:type:: RDP::ClientSecurityData

   :Type: :zeek:type:`record`

      encryption_methods: :zeek:type:`count`
         Cryptographic encryption methods supported by the client and used in
         conjunction with Standard RDP Security.  Known flags:
         
         - 0x00000001: support for 40-bit session encryption keys
         - 0x00000002: support for 128-bit session encryption keys
         - 0x00000008: support for 56-bit session encryption keys
         - 0x00000010: support for FIPS compliant encryption and MAC methods

      ext_encryption_methods: :zeek:type:`count`
         Only used in French locale and designates the encryption method.  If
         non-zero, then encryption_methods should be set to 0.

   The TS_UD_CS_SEC data block contains security-related information used
   to advertise client cryptographic support.

.. zeek:type:: RDP::EarlyCapabilityFlags

   :Type: :zeek:type:`record`

      support_err_info_pdu: :zeek:type:`bool`

      want_32bpp_session: :zeek:type:`bool`

      support_statusinfo_pdu: :zeek:type:`bool`

      strong_asymmetric_keys: :zeek:type:`bool`

      support_monitor_layout_pdu: :zeek:type:`bool`

      support_netchar_autodetect: :zeek:type:`bool`

      support_dynvc_gfx_protocol: :zeek:type:`bool`

      support_dynamic_time_zone: :zeek:type:`bool`

      support_heartbeat_pdu: :zeek:type:`bool`


.. zeek:type:: ReassemblerStats

   :Type: :zeek:type:`record`

      file_size: :zeek:type:`count`
         Byte size of File reassembly tracking.

      frag_size: :zeek:type:`count`
         Byte size of Fragment reassembly tracking.

      tcp_size: :zeek:type:`count`
         Byte size of TCP reassembly tracking.

      unknown_size: :zeek:type:`count`
         Byte size of reassembly tracking for unknown purposes.

   Holds statistics for all types of reassembly.
   
   .. zeek:see:: get_reassembler_stats

.. zeek:type:: ReporterStats

   :Type: :zeek:type:`record`

      weirds: :zeek:type:`count`
         Number of total weirds encountered, before any rate-limiting.

      weirds_by_type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`count`
         Number of times each individual weird is encountered, before any
         rate-limiting is applied.

   Statistics about reporter messages and weirds.
   
   .. zeek:see:: get_reporter_stats

.. zeek:type:: SMB1::Find_First2_Request_Args

   :Type: :zeek:type:`record`

      search_attrs: :zeek:type:`count`
         File attributes to apply as a constraint to the search

      search_count: :zeek:type:`count`
         Max search results

      flags: :zeek:type:`count`
         Misc. flags for how the server should manage the transaction
         once results are returned

      info_level: :zeek:type:`count`
         How detailed the information returned in the results should be

      search_storage_type: :zeek:type:`count`
         Specify whether to search for directories or files

      file_name: :zeek:type:`string`
         The string to serch for (note: may contain wildcards)


.. zeek:type:: SMB1::Find_First2_Response_Args

   :Type: :zeek:type:`record`

      sid: :zeek:type:`count`
         The server generated search identifier

      search_count: :zeek:type:`count`
         Number of results returned by the search

      end_of_search: :zeek:type:`bool`
         Whether or not the search can be continued using
         the TRANS2_FIND_NEXT2 transaction

      ext_attr_error: :zeek:type:`string` :zeek:attr:`&optional`
         An extended attribute name that couldn't be retrieved


.. zeek:type:: SMB1::Header

   :Type: :zeek:type:`record`

      command: :zeek:type:`count`
         The command number

      status: :zeek:type:`count`
         The status code

      flags: :zeek:type:`count`
         Flag set 1

      flags2: :zeek:type:`count`
         Flag set 2

      tid: :zeek:type:`count`
         Tree ID

      pid: :zeek:type:`count`
         Process ID

      uid: :zeek:type:`count`
         User ID

      mid: :zeek:type:`count`
         Multiplex ID

   An SMB1 header.
   
   .. zeek:see:: smb1_message smb1_empty_response smb1_error
      smb1_check_directory_request smb1_check_directory_response
      smb1_close_request smb1_create_directory_request
      smb1_create_directory_response smb1_echo_request
      smb1_echo_response smb1_negotiate_request
      smb1_negotiate_response smb1_nt_cancel_request
      smb1_nt_create_andx_request smb1_nt_create_andx_response
      smb1_query_information_request smb1_read_andx_request
      smb1_read_andx_response smb1_session_setup_andx_request
      smb1_session_setup_andx_response smb1_transaction_request
      smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request
      smb1_tree_connect_andx_request smb1_tree_connect_andx_response
      smb1_tree_disconnect smb1_write_andx_request
      smb1_write_andx_response

.. zeek:type:: SMB1::NegotiateCapabilities

   :Type: :zeek:type:`record`

      raw_mode: :zeek:type:`bool`
         The server supports SMB_COM_READ_RAW and SMB_COM_WRITE_RAW

      mpx_mode: :zeek:type:`bool`
         The server supports SMB_COM_READ_MPX and SMB_COM_WRITE_MPX

      unicode: :zeek:type:`bool`
         The server supports unicode strings

      large_files: :zeek:type:`bool`
         The server supports large files with 64 bit offsets

      nt_smbs: :zeek:type:`bool`
         The server supports the SMBs particilar to the NT LM 0.12 dialect. Implies nt_find.

      rpc_remote_apis: :zeek:type:`bool`
         The server supports remote admin API requests via DCE-RPC

      status32: :zeek:type:`bool`
         The server can respond with 32 bit status codes in Status.Status

      level_2_oplocks: :zeek:type:`bool`
         The server supports level 2 oplocks

      lock_and_read: :zeek:type:`bool`
         The server supports SMB_COM_LOCK_AND_READ

      nt_find: :zeek:type:`bool`
         Reserved

      dfs: :zeek:type:`bool`
         The server is DFS aware

      infolevel_passthru: :zeek:type:`bool`
         The server supports NT information level requests passing through

      large_readx: :zeek:type:`bool`
         The server supports large SMB_COM_READ_ANDX (up to 64k)

      large_writex: :zeek:type:`bool`
         The server supports large SMB_COM_WRITE_ANDX (up to 64k)

      unix: :zeek:type:`bool`
         The server supports CIFS Extensions for UNIX

      bulk_transfer: :zeek:type:`bool`
         The server supports SMB_BULK_READ, SMB_BULK_WRITE
         Note: No known implementations support this

      compressed_data: :zeek:type:`bool`
         The server supports compressed data transfer. Requires bulk_transfer.
         Note: No known implementations support this

      extended_security: :zeek:type:`bool`
         The server supports extended security exchanges


.. zeek:type:: SMB1::NegotiateRawMode

   :Type: :zeek:type:`record`

      read_raw: :zeek:type:`bool`
         Read raw supported

      write_raw: :zeek:type:`bool`
         Write raw supported


.. zeek:type:: SMB1::NegotiateResponse

   :Type: :zeek:type:`record`

      core: :zeek:type:`SMB1::NegotiateResponseCore` :zeek:attr:`&optional`
         If the server does not understand any of the dialect strings, or if
         PC NETWORK PROGRAM 1.0 is the chosen dialect.

      lanman: :zeek:type:`SMB1::NegotiateResponseLANMAN` :zeek:attr:`&optional`
         If the chosen dialect is greater than core up to and including
         LANMAN 2.1.

      ntlm: :zeek:type:`SMB1::NegotiateResponseNTLM` :zeek:attr:`&optional`
         If the chosen dialect is NT LM 0.12.


.. zeek:type:: SMB1::NegotiateResponseCore

   :Type: :zeek:type:`record`

      dialect_index: :zeek:type:`count`
         Index of selected dialect


.. zeek:type:: SMB1::NegotiateResponseLANMAN

   :Type: :zeek:type:`record`

      word_count: :zeek:type:`count`
         Count of parameter words (should be 13)

      dialect_index: :zeek:type:`count`
         Index of selected dialect

      security_mode: :zeek:type:`SMB1::NegotiateResponseSecurity`
         Security mode

      max_buffer_size: :zeek:type:`count`
         Max transmit buffer size (>= 1024)

      max_mpx_count: :zeek:type:`count`
         Max pending multiplexed requests

      max_number_vcs: :zeek:type:`count`
         Max number of virtual circuits (VCs - transport-layer connections)
         between client and server

      raw_mode: :zeek:type:`SMB1::NegotiateRawMode`
         Raw mode

      session_key: :zeek:type:`count`
         Unique token identifying this session

      server_time: :zeek:type:`time`
         Current date and time at server

      encryption_key: :zeek:type:`string`
         The challenge encryption key

      primary_domain: :zeek:type:`string`
         The server's primary domain


.. zeek:type:: SMB1::NegotiateResponseNTLM

   :Type: :zeek:type:`record`

      word_count: :zeek:type:`count`
         Count of parameter words (should be 17)

      dialect_index: :zeek:type:`count`
         Index of selected dialect

      security_mode: :zeek:type:`SMB1::NegotiateResponseSecurity`
         Security mode

      max_buffer_size: :zeek:type:`count`
         Max transmit buffer size

      max_mpx_count: :zeek:type:`count`
         Max pending multiplexed requests

      max_number_vcs: :zeek:type:`count`
         Max number of virtual circuits (VCs - transport-layer connections)
         between client and server

      max_raw_size: :zeek:type:`count`
         Max raw buffer size

      session_key: :zeek:type:`count`
         Unique token identifying this session

      capabilities: :zeek:type:`SMB1::NegotiateCapabilities`
         Server capabilities

      server_time: :zeek:type:`time`
         Current date and time at server

      encryption_key: :zeek:type:`string` :zeek:attr:`&optional`
         The challenge encryption key.
         Present only for non-extended security (i.e. capabilities$extended_security = F)

      domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The name of the domain.
         Present only for non-extended security (i.e. capabilities$extended_security = F)

      guid: :zeek:type:`string` :zeek:attr:`&optional`
         A globally unique identifier assigned to the server.
         Present only for extended security (i.e. capabilities$extended_security = T)

      security_blob: :zeek:type:`string`
         Opaque security blob associated with the security package if capabilities$extended_security = T
         Otherwise, the challenge for challenge/response authentication.


.. zeek:type:: SMB1::NegotiateResponseSecurity

   :Type: :zeek:type:`record`

      user_level: :zeek:type:`bool`
         This indicates whether the server, as a whole, is operating under
         Share Level or User Level security.

      challenge_response: :zeek:type:`bool`
         This indicates whether or not the server supports Challenge/Response
         authentication. If the bit is false, then plaintext passwords must
         be used.

      signatures_enabled: :zeek:type:`bool` :zeek:attr:`&optional`
         This indicates if the server is capable of performing MAC message
         signing. Note: Requires NT LM 0.12 or later.

      signatures_required: :zeek:type:`bool` :zeek:attr:`&optional`
         This indicates if the server is requiring the use of a MAC in each
         packet. If false, message signing is optional. Note: Requires NT LM 0.12
         or later.


.. zeek:type:: SMB1::SessionSetupAndXCapabilities

   :Type: :zeek:type:`record`

      unicode: :zeek:type:`bool`
         The client can use unicode strings

      large_files: :zeek:type:`bool`
         The client can deal with files having 64 bit offsets

      nt_smbs: :zeek:type:`bool`
         The client understands the SMBs introduced with NT LM 0.12
         Implies nt_find

      status32: :zeek:type:`bool`
         The client can receive 32 bit errors encoded in Status.Status

      level_2_oplocks: :zeek:type:`bool`
         The client understands Level II oplocks

      nt_find: :zeek:type:`bool`
         Reserved. Implied by nt_smbs.


.. zeek:type:: SMB1::SessionSetupAndXRequest

   :Type: :zeek:type:`record`

      word_count: :zeek:type:`count`
         Count of parameter words
            - 10 for pre NT LM 0.12
            - 12 for NT LM 0.12 with extended security
            - 13 for NT LM 0.12 without extended security

      max_buffer_size: :zeek:type:`count`
         Client maximum buffer size

      max_mpx_count: :zeek:type:`count`
         Actual maximum multiplexed pending request

      vc_number: :zeek:type:`count`
         Virtual circuit number. First VC == 0

      session_key: :zeek:type:`count`
         Session key (valid iff vc_number > 0)

      native_os: :zeek:type:`string`
         Client's native operating system

      native_lanman: :zeek:type:`string`
         Client's native LAN Manager type

      account_name: :zeek:type:`string` :zeek:attr:`&optional`
         Account name
         Note: not set for NT LM 0.12 with extended security

      account_password: :zeek:type:`string` :zeek:attr:`&optional`
         If challenge/response auth is not being used, this is the password.
         Otherwise, it's the response to the server's challenge.
         Note: Only set for pre NT LM 0.12

      primary_domain: :zeek:type:`string` :zeek:attr:`&optional`
         Client's primary domain, if known
         Note: not set for NT LM 0.12 with extended security

      case_insensitive_password: :zeek:type:`string` :zeek:attr:`&optional`
         Case insensitive password
         Note: only set for NT LM 0.12 without extended security

      case_sensitive_password: :zeek:type:`string` :zeek:attr:`&optional`
         Case sensitive password
         Note: only set for NT LM 0.12 without extended security

      security_blob: :zeek:type:`string` :zeek:attr:`&optional`
         Security blob
         Note: only set for NT LM 0.12 with extended security

      capabilities: :zeek:type:`SMB1::SessionSetupAndXCapabilities` :zeek:attr:`&optional`
         Client capabilities
         Note: only set for NT LM 0.12


.. zeek:type:: SMB1::SessionSetupAndXResponse

   :Type: :zeek:type:`record`

      word_count: :zeek:type:`count`
         Count of parameter words (should be 3 for pre NT LM 0.12 and 4 for NT LM 0.12)

      is_guest: :zeek:type:`bool` :zeek:attr:`&optional`
         Were we logged in as a guest user?

      native_os: :zeek:type:`string` :zeek:attr:`&optional`
         Server's native operating system

      native_lanman: :zeek:type:`string` :zeek:attr:`&optional`
         Server's native LAN Manager type

      primary_domain: :zeek:type:`string` :zeek:attr:`&optional`
         Server's primary domain

      security_blob: :zeek:type:`string` :zeek:attr:`&optional`
         Security blob if NTLM


.. zeek:type:: SMB1::Trans2_Args

   :Type: :zeek:type:`record`

      total_param_count: :zeek:type:`count`
         Total parameter count

      total_data_count: :zeek:type:`count`
         Total data count

      max_param_count: :zeek:type:`count`
         Max parameter count

      max_data_count: :zeek:type:`count`
         Max data count

      max_setup_count: :zeek:type:`count`
         Max setup count

      flags: :zeek:type:`count`
         Flags

      trans_timeout: :zeek:type:`count`
         Timeout

      param_count: :zeek:type:`count`
         Parameter count

      param_offset: :zeek:type:`count`
         Parameter offset

      data_count: :zeek:type:`count`
         Data count

      data_offset: :zeek:type:`count`
         Data offset

      setup_count: :zeek:type:`count`
         Setup count


.. zeek:type:: SMB1::Trans2_Sec_Args

   :Type: :zeek:type:`record`

      total_param_count: :zeek:type:`count`
         Total parameter count

      total_data_count: :zeek:type:`count`
         Total data count

      param_count: :zeek:type:`count`
         Parameter count

      param_offset: :zeek:type:`count`
         Parameter offset

      param_displacement: :zeek:type:`count`
         Parameter displacement

      data_count: :zeek:type:`count`
         Data count

      data_offset: :zeek:type:`count`
         Data offset

      data_displacement: :zeek:type:`count`
         Data displacement

      FID: :zeek:type:`count`
         File ID


.. zeek:type:: SMB1::Trans_Sec_Args

   :Type: :zeek:type:`record`

      total_param_count: :zeek:type:`count`
         Total parameter count

      total_data_count: :zeek:type:`count`
         Total data count

      param_count: :zeek:type:`count`
         Parameter count

      param_offset: :zeek:type:`count`
         Parameter offset

      param_displacement: :zeek:type:`count`
         Parameter displacement

      data_count: :zeek:type:`count`
         Data count

      data_offset: :zeek:type:`count`
         Data offset

      data_displacement: :zeek:type:`count`
         Data displacement


.. zeek:type:: SMB2::CloseResponse

   :Type: :zeek:type:`record`

      alloc_size: :zeek:type:`count`
         The size, in bytes of the data that is allocated to the file.

      eof: :zeek:type:`count`
         The size, in bytes, of the file.

      times: :zeek:type:`SMB::MACTimes`
         The creation, last access, last write, and change times.

      attrs: :zeek:type:`SMB2::FileAttrs`
         The attributes of the file.

   The response to an SMB2 *close* request, which is used by the client to close an instance
   of a file that was opened previously.
   
   For more information, see MS-SMB2:2.2.16
   
   .. zeek:see:: smb2_close_response

.. zeek:type:: SMB2::CompressionCapabilities

   :Type: :zeek:type:`record`

      alg_count: :zeek:type:`count`
         The number of algorithms.

      algs: :zeek:type:`vector` of :zeek:type:`count`
         An array of compression algorithms.

   Compression information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.3
   

.. zeek:type:: SMB2::CreateRequest

   :Type: :zeek:type:`record`

      filename: :zeek:type:`string`
         Name of the file

      disposition: :zeek:type:`count`
         Defines the action the server MUST take if the file that is specified already exists.

      create_options: :zeek:type:`count`
         Specifies the options to be applied when creating or opening the file.

   The request sent by the client to request either creation of or access to a file.
   
   For more information, see MS-SMB2:2.2.13
   
   .. zeek:see:: smb2_create_request

.. zeek:type:: SMB2::CreateResponse

   :Type: :zeek:type:`record`

      file_id: :zeek:type:`SMB2::GUID`
         The SMB2 GUID for the file.

      size: :zeek:type:`count`
         Size of the file.

      times: :zeek:type:`SMB::MACTimes`
         Timestamps associated with the file in question.

      attrs: :zeek:type:`SMB2::FileAttrs`
         File attributes.

      create_action: :zeek:type:`count`
         The action taken in establishing the open.

   The response to an SMB2 *create_request* request, which is sent by the client to request
   either creation of or access to a file.
   
   For more information, see MS-SMB2:2.2.14
   
   .. zeek:see:: smb2_create_response

.. zeek:type:: SMB2::EncryptionCapabilities

   :Type: :zeek:type:`record`

      cipher_count: :zeek:type:`count`
         The number of ciphers.

      ciphers: :zeek:type:`vector` of :zeek:type:`count`
         An array of ciphers.

   Encryption information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.2
   

.. zeek:type:: SMB2::FileAttrs

   :Type: :zeek:type:`record`

      read_only: :zeek:type:`bool`
         The file is read only. Applications can read the file but cannot
         write to it or delete it.

      hidden: :zeek:type:`bool`
         The file is hidden. It is not to be included in an ordinary directory listing.

      system: :zeek:type:`bool`
         The file is part of or is used exclusively by the operating system.

      directory: :zeek:type:`bool`
         The file is a directory.

      archive: :zeek:type:`bool`
         The file has not been archived since it was last modified. Applications use
         this attribute to mark files for backup or removal.

      normal: :zeek:type:`bool`
         The file has no other attributes set. This attribute is valid only if used alone.

      temporary: :zeek:type:`bool`
         The file is temporary. This is a hint to the cache manager that it does not need
         to flush the file to backing storage.

      sparse_file: :zeek:type:`bool`
         A file that is a sparse file.

      reparse_point: :zeek:type:`bool`
         A file or directory that has an associated reparse point.

      compressed: :zeek:type:`bool`
         The file or directory is compressed. For a file, this means that all of the data
         in the file is compressed. For a directory, this means that compression is the
         default for newly created files and subdirectories.

      offline: :zeek:type:`bool`
         The data in this file is not available immediately. This attribute indicates that
         the file data is physically moved to offline storage. This attribute is used by
         Remote Storage, which is hierarchical storage management software.

      not_content_indexed: :zeek:type:`bool`
         A file or directory that is not indexed by the content indexing service.

      encrypted: :zeek:type:`bool`
         A file or directory that is encrypted. For a file, all data streams in the file
         are encrypted. For a directory, encryption is the default for newly created files
         and subdirectories.

      integrity_stream: :zeek:type:`bool`
         A file or directory that is configured with integrity support. For a file, all
         data streams in the file have integrity support. For a directory, integrity support
         is the default for newly created files and subdirectories, unless the caller
         specifies otherwise.

      no_scrub_data: :zeek:type:`bool`
         A file or directory that is configured to be excluded from the data integrity scan.

   A series of boolean flags describing basic and extended file attributes for SMB2.
   
   For more information, see MS-CIFS:2.2.1.2.3 and MS-FSCC:2.6
   
   .. zeek:see:: smb2_create_response

.. zeek:type:: SMB2::FileEA

   :Type: :zeek:type:`record`

      ea_name: :zeek:type:`string`
         Specifies the extended attribute name

      ea_value: :zeek:type:`string`
         Contains the extended attribute value

   This information class is used to query or set extended attribute (EA) information for a file.
   
   For more infomation, see MS-SMB2:2.2.39 and MS-FSCC:2.4.15
   

.. zeek:type:: SMB2::FileEAs

   :Type: :zeek:type:`vector` of :zeek:type:`SMB2::FileEA`

   A vector of extended attribute (EA) information for a file.
   
   For more infomation, see MS-SMB2:2.2.39 and MS-FSCC:2.4.15
   

.. zeek:type:: SMB2::Fscontrol

   :Type: :zeek:type:`record`

      free_space_start_filtering: :zeek:type:`int`
         minimum amount of free disk space required to begin document filtering

      free_space_threshold: :zeek:type:`int`
         minimum amount of free disk space required to continue document filtering

      free_space_threshold: :zeek:type:`int`
         minimum amount of free disk space required to continue document filtering

      delete_quota_threshold: :zeek:type:`count`
         default per-user disk quota

      default_quota_limit: :zeek:type:`count`
         default per-user disk limit

      fs_control_flags: :zeek:type:`count`
         file systems control flags passed as unsigned int

   A series of integers flags used to set quota and content indexing control information for a file system volume in SMB2.
   
   For more information, see MS-SMB2:2.2.39 and MS-FSCC:2.5.2
   

.. zeek:type:: SMB2::GUID

   :Type: :zeek:type:`record`

      persistent: :zeek:type:`count`
         A file handle that remains persistent when reconnected after a disconnect

      volatile: :zeek:type:`count`
         A file handle that can be changed when reconnected after a disconnect

   An SMB2 globally unique identifier which identifies a file.
   
   For more information, see MS-SMB2:2.2.14.1
   
   .. zeek:see:: smb2_close_request smb2_create_response smb2_read_request
      smb2_file_rename smb2_file_delete smb2_write_request

.. zeek:type:: SMB2::Header

   :Type: :zeek:type:`record`

      credit_charge: :zeek:type:`count`
         The number of credits that this request consumes

      status: :zeek:type:`count`
         In a request, this is an indication to the server about the client's channel
         change. In a response, this is the status field

      command: :zeek:type:`count`
         The command code of the packet

      credits: :zeek:type:`count`
         The number of credits the client is requesting, or the number of credits
         granted to the client in a response.

      flags: :zeek:type:`count`
         A flags field, which indicates how to process the operation (e.g. asynchronously)

      message_id: :zeek:type:`count`
         A value that uniquely identifies the message request/response pair across all
         messages that are sent on the same transport protocol connection

      process_id: :zeek:type:`count`
         A value that uniquely identifies the process that generated the event.

      tree_id: :zeek:type:`count`
         A value that uniquely identifies the tree connect for the command.

      session_id: :zeek:type:`count`
         A value that uniquely identifies the established session for the command.

      signature: :zeek:type:`string`
         The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the ``flags``
         field.

   An SMB2 header.
   
   For more information, see MS-SMB2:2.2.1.1 and MS-SMB2:2.2.1.2
   
   .. zeek:see:: smb2_message smb2_close_request smb2_close_response
      smb2_create_request smb2_create_response smb2_negotiate_request
      smb2_negotiate_response smb2_read_request
      smb2_session_setup_request smb2_session_setup_response
      smb2_file_rename smb2_file_delete
      smb2_tree_connect_request smb2_tree_connect_response
      smb2_write_request

.. zeek:type:: SMB2::NegotiateContextValue

   :Type: :zeek:type:`record`

      context_type: :zeek:type:`count`
         Specifies the type of context (preauth or encryption).

      data_length: :zeek:type:`count`
         The length in byte of the data field.

      preauth_info: :zeek:type:`SMB2::PreAuthIntegrityCapabilities` :zeek:attr:`&optional`
         The preauthentication information.

      encryption_info: :zeek:type:`SMB2::EncryptionCapabilities` :zeek:attr:`&optional`
         The encryption information.

      compression_info: :zeek:type:`SMB2::CompressionCapabilities` :zeek:attr:`&optional`
         The compression information.

      netname: :zeek:type:`string` :zeek:attr:`&optional`
         Indicates the server name the client must connect to.

   The context type information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1
   

.. zeek:type:: SMB2::NegotiateContextValues

   :Type: :zeek:type:`vector` of :zeek:type:`SMB2::NegotiateContextValue`


.. zeek:type:: SMB2::NegotiateResponse

   :Type: :zeek:type:`record`

      dialect_revision: :zeek:type:`count`
         The preferred common SMB2 Protocol dialect number from the array that was sent in the SMB2
         NEGOTIATE Request.

      security_mode: :zeek:type:`count`
         The security mode field specifies whether SMB signing is enabled, required at the server, or both.

      server_guid: :zeek:type:`string`
         A globally unique identifier that is generate by the server to uniquely identify the server.

      system_time: :zeek:type:`time`
         The system time of the SMB2 server when the SMB2 NEGOTIATE Request was processed.

      server_start_time: :zeek:type:`time`
         The SMB2 server start time.

      negotiate_context_count: :zeek:type:`count`
         The number of negotiate context values in SMB v. 3.1.1, otherwise reserved to 0.

      negotiate_context_values: :zeek:type:`SMB2::NegotiateContextValues`
         An array of context values in SMB v. 3.1.1.

   The response to an SMB2 *negotiate* request, which is used by tghe client to notify the server
   what dialects of the SMB2 protocol the client understands.
   
   For more information, see MS-SMB2:2.2.4
   
   .. zeek:see:: smb2_negotiate_response

.. zeek:type:: SMB2::PreAuthIntegrityCapabilities

   :Type: :zeek:type:`record`

      hash_alg_count: :zeek:type:`count`
         The number of hash algorithms.

      salt_length: :zeek:type:`count`
         The salt length.

      hash_alg: :zeek:type:`vector` of :zeek:type:`count`
         An array of hash algorithms (counts).

      salt: :zeek:type:`string`
         The salt.

   Preauthentication information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.1
   

.. zeek:type:: SMB2::SessionSetupFlags

   :Type: :zeek:type:`record`

      guest: :zeek:type:`bool`
         If set, the client has been authenticated as a guest user.

      anonymous: :zeek:type:`bool`
         If set, the client has been authenticated as an anonymous user.

      encrypt: :zeek:type:`bool`
         If set, the server requires encryption of messages on this session.

   A flags field that indicates additional information about the session that's sent in the
   *session_setup* response.
   
   For more information, see MS-SMB2:2.2.6
   
   .. zeek:see:: smb2_session_setup_response

.. zeek:type:: SMB2::SessionSetupRequest

   :Type: :zeek:type:`record`

      security_mode: :zeek:type:`count`
         The security mode field specifies whether SMB signing is enabled or required at the client.

   The request sent by the client to request a new authenticated session
   within a new or existing SMB 2 Protocol transport connection to the server.
   
   For more information, see MS-SMB2:2.2.5
   
   .. zeek:see:: smb2_session_setup_request

.. zeek:type:: SMB2::SessionSetupResponse

   :Type: :zeek:type:`record`

      flags: :zeek:type:`SMB2::SessionSetupFlags`
         Additional information about the session

   The response to an SMB2 *session_setup* request, which is sent by the client to request a
   new authenticated session within a new or existing SMB 2 Protocol transport connection
   to the server.
   
   For more information, see MS-SMB2:2.2.6
   
   .. zeek:see:: smb2_session_setup_response

.. zeek:type:: SMB2::Transform_header

   :Type: :zeek:type:`record`

      signature: :zeek:type:`string`
         The 16-byte signature of the encrypted message, generated by using Session.EncryptionKey.

      nonce: :zeek:type:`string`
         An implementation specific value assigned for every encrypted message.

      orig_msg_size: :zeek:type:`count`
         The size, in bytes, of the SMB2 message.

      flags: :zeek:type:`count`
         A flags field, interpreted in different ways depending of the SMB2 dialect.

      session_id: :zeek:type:`count`
         A value that uniquely identifies the established session for the command.

   An SMB2 transform header (for SMB 3.x dialects with encryption enabled).
   
   For more information, see MS-SMB2:2.2.41
   
   .. zeek:see:: smb2_transform_header smb2_message smb2_close_request smb2_close_response
      smb2_create_request smb2_create_response smb2_negotiate_request
      smb2_negotiate_response smb2_read_request
      smb2_session_setup_request smb2_session_setup_response
      smb2_file_rename smb2_file_delete
      smb2_tree_connect_request smb2_tree_connect_response
      smb2_write_request

.. zeek:type:: SMB2::TreeConnectResponse

   :Type: :zeek:type:`record`

      share_type: :zeek:type:`count`
         The type of share being accessed. Physical disk, named pipe, or printer.

   The response to an SMB2 *tree_connect* request, which is sent by the client to request
   access to a particular share on the server.
   
   For more information, see MS-SMB2:2.2.9
   
   .. zeek:see:: smb2_tree_connect_response

.. zeek:type:: SMB::MACTimes

   :Type: :zeek:type:`record`

      modified: :zeek:type:`time` :zeek:attr:`&log`
         The time when data was last written to the file.

      accessed: :zeek:type:`time` :zeek:attr:`&log`
         The time when the file was last accessed.

      created: :zeek:type:`time` :zeek:attr:`&log`
         The time the file was created.

      changed: :zeek:type:`time` :zeek:attr:`&log`
         The time when the file was last modified.
   :Attributes: :zeek:attr:`&log`

   MAC times for a file.
   
   For more information, see MS-SMB2:2.2.16
   
   .. zeek:see:: smb1_nt_create_andx_response smb2_create_response

.. zeek:type:: SNMP::Binding

   :Type: :zeek:type:`record`

      oid: :zeek:type:`string`

      value: :zeek:type:`SNMP::ObjectValue`

   The ``VarBind`` data structure from either :rfc:`1157` or
   :rfc:`3416`, which maps an Object Identifier to a value.

.. zeek:type:: SNMP::Bindings

   :Type: :zeek:type:`vector` of :zeek:type:`SNMP::Binding`

   A ``VarBindList`` data structure from either :rfc:`1157` or :rfc:`3416`.
   A sequences of :zeek:see:`SNMP::Binding`, which maps an OIDs to values.

.. zeek:type:: SNMP::BulkPDU

   :Type: :zeek:type:`record`

      request_id: :zeek:type:`int`

      non_repeaters: :zeek:type:`count`

      max_repititions: :zeek:type:`count`

      bindings: :zeek:type:`SNMP::Bindings`

   A ``BulkPDU`` data structure from :rfc:`3416`.

.. zeek:type:: SNMP::Header

   :Type: :zeek:type:`record`

      version: :zeek:type:`count`

      v1: :zeek:type:`SNMP::HeaderV1` :zeek:attr:`&optional`
         Set when ``version`` is 0.

      v2: :zeek:type:`SNMP::HeaderV2` :zeek:attr:`&optional`
         Set when ``version`` is 1.

      v3: :zeek:type:`SNMP::HeaderV3` :zeek:attr:`&optional`
         Set when ``version`` is 3.

   A generic SNMP header data structure that may include data from
   any version of SNMP.  The value of the ``version`` field
   determines what header field is initialized.

.. zeek:type:: SNMP::HeaderV1

   :Type: :zeek:type:`record`

      community: :zeek:type:`string`

   The top-level message data structure of an SNMPv1 datagram, not
   including the PDU data.  See :rfc:`1157`.

.. zeek:type:: SNMP::HeaderV2

   :Type: :zeek:type:`record`

      community: :zeek:type:`string`

   The top-level message data structure of an SNMPv2 datagram, not
   including the PDU data.  See :rfc:`1901`.

.. zeek:type:: SNMP::HeaderV3

   :Type: :zeek:type:`record`

      id: :zeek:type:`count`

      max_size: :zeek:type:`count`

      flags: :zeek:type:`count`

      auth_flag: :zeek:type:`bool`

      priv_flag: :zeek:type:`bool`

      reportable_flag: :zeek:type:`bool`

      security_model: :zeek:type:`count`

      security_params: :zeek:type:`string`

      pdu_context: :zeek:type:`SNMP::ScopedPDU_Context` :zeek:attr:`&optional`

   The top-level message data structure of an SNMPv3 datagram, not
   including the PDU data.  See :rfc:`3412`.

.. zeek:type:: SNMP::ObjectValue

   :Type: :zeek:type:`record`

      tag: :zeek:type:`count`

      oid: :zeek:type:`string` :zeek:attr:`&optional`

      signed: :zeek:type:`int` :zeek:attr:`&optional`

      unsigned: :zeek:type:`count` :zeek:attr:`&optional`

      address: :zeek:type:`addr` :zeek:attr:`&optional`

      octets: :zeek:type:`string` :zeek:attr:`&optional`

   A generic SNMP object value, that may include any of the
   valid ``ObjectSyntax`` values from :rfc:`1155` or :rfc:`3416`.
   The value is decoded whenever possible and assigned to
   the appropriate field, which can be determined from the value
   of the ``tag`` field.  For tags that can't be mapped to an
   appropriate type, the ``octets`` field holds the BER encoded
   ASN.1 content if there is any (though, ``octets`` is may also
   be used for other tags such as OCTET STRINGS or Opaque).  Null
   values will only have their corresponding tag value set.

.. zeek:type:: SNMP::PDU

   :Type: :zeek:type:`record`

      request_id: :zeek:type:`int`

      error_status: :zeek:type:`int`

      error_index: :zeek:type:`int`

      bindings: :zeek:type:`SNMP::Bindings`

   A ``PDU`` data structure from either :rfc:`1157` or :rfc:`3416`.

.. zeek:type:: SNMP::ScopedPDU_Context

   :Type: :zeek:type:`record`

      engine_id: :zeek:type:`string`

      name: :zeek:type:`string`

   The ``ScopedPduData`` data structure of an SNMPv3 datagram, not
   including the PDU data (i.e. just the "context" fields).
   See :rfc:`3412`.

.. zeek:type:: SNMP::TrapPDU

   :Type: :zeek:type:`record`

      enterprise: :zeek:type:`string`

      agent: :zeek:type:`addr`

      generic_trap: :zeek:type:`int`

      specific_trap: :zeek:type:`int`

      time_stamp: :zeek:type:`count`

      bindings: :zeek:type:`SNMP::Bindings`

   A ``Trap-PDU`` data structure from :rfc:`1157`.

.. zeek:type:: SOCKS::Address

   :Type: :zeek:type:`record`

      host: :zeek:type:`addr` :zeek:attr:`&optional` :zeek:attr:`&log`

      name: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
   :Attributes: :zeek:attr:`&log`

   This record is for a SOCKS client or server to provide either a
   name or an address to represent a desired or established connection.

.. zeek:type:: SSH::Algorithm_Prefs

   :Type: :zeek:type:`record`

      client_to_server: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`
         The algorithm preferences for client to server communication

      server_to_client: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`
         The algorithm preferences for server to client communication

   The client and server each have some preferences for the algorithms used
   in each direction.

.. zeek:type:: SSH::Capabilities

   :Type: :zeek:type:`record`

      kex_algorithms: :zeek:type:`string_vec`
         Key exchange algorithms

      server_host_key_algorithms: :zeek:type:`string_vec`
         The algorithms supported for the server host key

      encryption_algorithms: :zeek:type:`SSH::Algorithm_Prefs`
         Symmetric encryption algorithm preferences

      mac_algorithms: :zeek:type:`SSH::Algorithm_Prefs`
         Symmetric MAC algorithm preferences

      compression_algorithms: :zeek:type:`SSH::Algorithm_Prefs`
         Compression algorithm preferences

      languages: :zeek:type:`SSH::Algorithm_Prefs` :zeek:attr:`&optional`
         Language preferences

      is_server: :zeek:type:`bool`
         Are these the capabilities of the server?

   This record lists the preferences of an SSH endpoint for
   algorithm selection. During the initial :abbr:`SSH (Secure Shell)`
   key exchange, each endpoint lists the algorithms
   that it supports, in order of preference. See
   :rfc:`4253#section-7.1` for details.

.. zeek:type:: SSL::PSKIdentity

   :Type: :zeek:type:`record`

      identity: :zeek:type:`string`
         PSK identity

      obfuscated_ticket_age: :zeek:type:`count`


.. zeek:type:: SSL::SignatureAndHashAlgorithm

   :Type: :zeek:type:`record`

      HashAlgorithm: :zeek:type:`count`
         Hash algorithm number

      SignatureAlgorithm: :zeek:type:`count`
         Signature algorithm number


.. zeek:type:: SYN_packet

   :Type: :zeek:type:`record`

      is_orig: :zeek:type:`bool`
         True if the packet was sent the connection's originator.

      DF: :zeek:type:`bool`
         True if the *don't fragment* is set in the IP header.

      ttl: :zeek:type:`count`
         The IP header's time-to-live.

      size: :zeek:type:`count`
         The size of the packet's payload as specified in the IP header.

      win_size: :zeek:type:`count`
         The window size from the TCP header.

      win_scale: :zeek:type:`int`
         The window scale option if present, or -1 if not.

      MSS: :zeek:type:`count`
         The maximum segment size if present, or 0 if not.

      SACK_OK: :zeek:type:`bool`
         True if the *SACK* option is present.

   Fields of a SYN packet.
   
   .. zeek:see:: connection_SYN_packet

.. zeek:type:: TCP::Option

   :Type: :zeek:type:`record`

      kind: :zeek:type:`count`
         The kind number associated with the option.  Other optional fields
         of this record may be set depending on this value.

      length: :zeek:type:`count`
         The total length of the option in bytes, including the kind byte and
         length byte (if present).

      data: :zeek:type:`string` :zeek:attr:`&optional`
         This field is set to the raw option bytes if the kind is not
         otherwise known/parsed.  It's also set for known kinds whose length
         was invalid.

      mss: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 2: Maximum Segment Size.

      window_scale: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 3: Window scale.

      sack: :zeek:type:`index_vec` :zeek:attr:`&optional`
         Kind 5: Selective ACKnowledgement (SACK).  This is a list of 2, 4,
         6, or 8 numbers with each consecutive pair being a 32-bit
         begin-pointer and 32-bit end pointer.

      send_timestamp: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 8: 4-byte sender timestamp value.

      echo_timestamp: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 8: 4-byte echo reply timestamp value.

   A TCP Option field parsed from a TCP header.

.. zeek:type:: TCP::OptionList

   :Type: :zeek:type:`vector` of :zeek:type:`TCP::Option`

   The full list of TCP Option fields parsed from a TCP header.

.. zeek:type:: ThreadStats

   :Type: :zeek:type:`record`

      num_threads: :zeek:type:`count`

   Statistics about threads.
   
   .. zeek:see:: get_thread_stats

.. zeek:type:: TimerStats

   :Type: :zeek:type:`record`

      current: :zeek:type:`count`
         Current number of pending timers.

      max: :zeek:type:`count`
         Maximum number of concurrent timers pending so far.

      cumulative: :zeek:type:`count`
         Cumulative number of timers scheduled.

   Statistics of timers.
   
   .. zeek:see:: get_timer_stats

.. zeek:type:: Tunnel::EncapsulatingConn

   :Type: :zeek:type:`record`

      cid: :zeek:type:`conn_id` :zeek:attr:`&log`
         The 4-tuple of the encapsulating "connection". In case of an
         IP-in-IP tunnel the ports will be set to 0. The direction
         (i.e., orig and resp) are set according to the first tunneled
         packet seen and not according to the side that established
         the tunnel.

      tunnel_type: :zeek:type:`Tunnel::Type` :zeek:attr:`&log`
         The type of tunnel.

      uid: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         A globally unique identifier that, for non-IP-in-IP tunnels,
         cross-references the *uid* field of :zeek:type:`connection`.
   :Attributes: :zeek:attr:`&log`

   Records the identity of an encapsulating parent of a tunneled connection.

.. zeek:type:: Unified2::IDSEvent

   :Type: :zeek:type:`record`

      sensor_id: :zeek:type:`count`

      event_id: :zeek:type:`count`

      ts: :zeek:type:`time`

      signature_id: :zeek:type:`count`

      generator_id: :zeek:type:`count`

      signature_revision: :zeek:type:`count`

      classification_id: :zeek:type:`count`

      priority_id: :zeek:type:`count`

      src_ip: :zeek:type:`addr`

      dst_ip: :zeek:type:`addr`

      src_p: :zeek:type:`port`

      dst_p: :zeek:type:`port`

      impact_flag: :zeek:type:`count`

      impact: :zeek:type:`count`

      blocked: :zeek:type:`count`

      mpls_label: :zeek:type:`count` :zeek:attr:`&optional`
         Not available in "legacy" IDS events.

      vlan_id: :zeek:type:`count` :zeek:attr:`&optional`
         Not available in "legacy" IDS events.

      packet_action: :zeek:type:`count` :zeek:attr:`&optional`
         Only available in "legacy" IDS events.


.. zeek:type:: Unified2::Packet

   :Type: :zeek:type:`record`

      sensor_id: :zeek:type:`count`

      event_id: :zeek:type:`count`

      event_second: :zeek:type:`count`

      packet_ts: :zeek:type:`time`

      link_type: :zeek:type:`count`

      data: :zeek:type:`string`


.. zeek:type:: X509::BasicConstraints

   :Type: :zeek:type:`record`

      ca: :zeek:type:`bool` :zeek:attr:`&log`
         CA flag set?

      path_len: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Maximum path length
   :Attributes: :zeek:attr:`&log`


.. zeek:type:: X509::Certificate

   :Type: :zeek:type:`record`

      version: :zeek:type:`count` :zeek:attr:`&log`
         Version number.

      serial: :zeek:type:`string` :zeek:attr:`&log`
         Serial number.

      subject: :zeek:type:`string` :zeek:attr:`&log`
         Subject.

      issuer: :zeek:type:`string` :zeek:attr:`&log`
         Issuer.

      cn: :zeek:type:`string` :zeek:attr:`&optional`
         Last (most specific) common name.

      not_valid_before: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp before when certificate is not valid.

      not_valid_after: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp after when certificate is not valid.

      key_alg: :zeek:type:`string` :zeek:attr:`&log`
         Name of the key algorithm

      sig_alg: :zeek:type:`string` :zeek:attr:`&log`
         Name of the signature algorithm

      key_type: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Key type, if key parseable by openssl (either rsa, dsa or ec)

      key_length: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Key length in bits

      exponent: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Exponent, if RSA-certificate

      curve: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Curve, if EC-certificate


.. zeek:type:: X509::Extension

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         Long name of extension. oid if name not known

      short_name: :zeek:type:`string` :zeek:attr:`&optional`
         Short name of extension if known

      oid: :zeek:type:`string`
         Oid of extension

      critical: :zeek:type:`bool`
         True if extension is critical

      value: :zeek:type:`string`
         Extension content parsed to string for known extensions. Raw data otherwise.


.. zeek:type:: X509::Result

   :Type: :zeek:type:`record`

      result: :zeek:type:`int`
         OpenSSL result code

      result_string: :zeek:type:`string`
         Result as string

      chain_certs: :zeek:type:`vector` of :zeek:type:`opaque` of x509 :zeek:attr:`&optional`
         References to the final certificate chain, if verification successful. End-host certificate is first.

   Result of an X509 certificate chain verification

.. zeek:type:: X509::SubjectAlternativeName

   :Type: :zeek:type:`record`

      dns: :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`
         List of DNS entries in SAN

      uri: :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`
         List of URI entries in SAN

      email: :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`
         List of email entries in SAN

      ip: :zeek:type:`addr_vec` :zeek:attr:`&optional` :zeek:attr:`&log`
         List of IP entries in SAN

      other_fields: :zeek:type:`bool`
         True if the certificate contained other, not recognized or parsed name fields


.. zeek:type:: addr_set

   :Type: :zeek:type:`set` [:zeek:type:`addr`]

   A set of addresses.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: addr_vec

   :Type: :zeek:type:`vector` of :zeek:type:`addr`

   A vector of addresses.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: any_vec

   :Type: :zeek:type:`vector` of :zeek:type:`any`

   A vector of any, used by some builtin functions to store a list of varying
   types.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: bittorrent_benc_dir

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`bittorrent_benc_value`

   A table of BitTorrent "benc" values.
   
   .. zeek:see:: bt_tracker_response

.. zeek:type:: bittorrent_benc_value

   :Type: :zeek:type:`record`

      i: :zeek:type:`int` :zeek:attr:`&optional`
         TODO.

      s: :zeek:type:`string` :zeek:attr:`&optional`
         TODO.

      d: :zeek:type:`string` :zeek:attr:`&optional`
         TODO.

      l: :zeek:type:`string` :zeek:attr:`&optional`
         TODO.

   BitTorrent "benc" value. Note that "benc" = Bencode ("Bee-Encode"), per
   http://en.wikipedia.org/wiki/Bencode.
   
   .. zeek:see:: bittorrent_benc_dir

.. zeek:type:: bittorrent_peer

   :Type: :zeek:type:`record`

      h: :zeek:type:`addr`
         The peer's address.

      p: :zeek:type:`port`
         The peer's port.

   A BitTorrent peer.
   
   .. zeek:see:: bittorrent_peer_set

.. zeek:type:: bittorrent_peer_set

   :Type: :zeek:type:`set` [:zeek:type:`bittorrent_peer`]

   A set of BitTorrent peers.
   
   .. zeek:see:: bt_tracker_response

.. zeek:type:: bt_tracker_headers

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`

   Header table type used by BitTorrent analyzer.
   
   .. zeek:see:: bt_tracker_request bt_tracker_response
      bt_tracker_response_not_ok

.. zeek:type:: call_argument

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         The name of the parameter.

      type_name: :zeek:type:`string`
         The name of the parameters's type.

      default_val: :zeek:type:`any` :zeek:attr:`&optional`
         The value of the :zeek:attr:`&default` attribute if defined.

      value: :zeek:type:`any` :zeek:attr:`&optional`
         The value of the parameter as passed into a given call instance.
         Might be unset in the case a :zeek:attr:`&default` attribute is
         defined.

   Meta-information about a parameter to a function/event.
   
   .. zeek:see:: call_argument_vector new_event

.. zeek:type:: call_argument_vector

   :Type: :zeek:type:`vector` of :zeek:type:`call_argument`

   Vector type used to capture parameters of a function/event call.
   
   .. zeek:see:: call_argument new_event

.. zeek:type:: conn_id

   :Type: :zeek:type:`record`

      orig_h: :zeek:type:`addr` :zeek:attr:`&log`
         The originator's IP address.

      orig_p: :zeek:type:`port` :zeek:attr:`&log`
         The originator's port number.

      resp_h: :zeek:type:`addr` :zeek:attr:`&log`
         The responder's IP address.

      resp_p: :zeek:type:`port` :zeek:attr:`&log`
         The responder's port number.
   :Attributes: :zeek:attr:`&log`

   A connection's identifying 4-tuple of endpoints and ports.
   
   .. note:: It's actually a 5-tuple: the transport-layer protocol is stored as
      part of the port values, `orig_p` and `resp_p`, and can be extracted from
      them with :zeek:id:`get_port_transport_proto`.

.. zeek:type:: connection

   :Type: :zeek:type:`record`

      id: :zeek:type:`conn_id`
         The connection's identifying 4-tuple.

      orig: :zeek:type:`endpoint`
         Statistics about originator side.

      resp: :zeek:type:`endpoint`
         Statistics about responder side.

      start_time: :zeek:type:`time`
         The timestamp of the connection's first packet.

      duration: :zeek:type:`interval`
         The duration of the conversation. Roughly speaking, this is the
         interval between first and last data packet (low-level TCP details
         may adjust it somewhat in ambiguous cases).

      service: :zeek:type:`set` [:zeek:type:`string`]
         The set of services the connection is using as determined by Zeek's
         dynamic protocol detection. Each entry is the label of an analyzer
         that confirmed that it could parse the connection payload.  While
         typically, there will be at most one entry for each connection, in
         principle it is possible that more than one protocol analyzer is able
         to parse the same data. If so, all will be recorded. Also note that
         the recorded services are independent of any transport-level protocols.

      history: :zeek:type:`string`
         State history of connections. See *history* in :zeek:see:`Conn::Info`.

      uid: :zeek:type:`string`
         A globally unique connection identifier. For each connection, Zeek
         creates an ID that is very likely unique across independent Zeek runs.
         These IDs can thus be used to tag and locate information associated
         with that connection.

      tunnel: :zeek:type:`EncapsulatingConnVector` :zeek:attr:`&optional`
         If the connection is tunneled, this field contains information about
         the encapsulating "connection(s)" with the outermost one starting
         at index zero.  It's also always the first such encapsulation seen
         for the connection unless the :zeek:id:`tunnel_changed` event is
         handled and reassigns this field to the new encapsulation.

      vlan: :zeek:type:`int` :zeek:attr:`&optional`
         The outer VLAN, if applicable for this connection.

      inner_vlan: :zeek:type:`int` :zeek:attr:`&optional`
         The inner VLAN, if applicable for this connection.

      successful: :zeek:type:`bool`
         Flag that will be true if :zeek:see:`connection_successful` has
         already been generated for the connection. See the documentation of
         that event for a definition of what makes a connection "succesful".

      dpd: :zeek:type:`DPD::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/dpd/main.zeek` is loaded)


      dpd_state: :zeek:type:`DPD::State` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/dpd/main.zeek` is loaded)


      conn: :zeek:type:`Conn::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/conn/main.zeek` is loaded)


      extract_orig: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`Conn::default_extract` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/conn/contents.zeek` is loaded)


      extract_resp: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`Conn::default_extract` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/conn/contents.zeek` is loaded)


      thresholds: :zeek:type:`ConnThreshold::Thresholds` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/conn/thresholds.zeek` is loaded)


      dce_rpc: :zeek:type:`DCE_RPC::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dce-rpc/main.zeek` is loaded)


      dce_rpc_state: :zeek:type:`DCE_RPC::State` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dce-rpc/main.zeek` is loaded)


      dce_rpc_backing: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`DCE_RPC::BackingState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dce-rpc/main.zeek` is loaded)


      dhcp: :zeek:type:`DHCP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dhcp/main.zeek` is loaded)


      dnp3: :zeek:type:`DNP3::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dnp3/main.zeek` is loaded)


      dns: :zeek:type:`DNS::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dns/main.zeek` is loaded)


      dns_state: :zeek:type:`DNS::State` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dns/main.zeek` is loaded)


      ftp: :zeek:type:`FTP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ftp/main.zeek` is loaded)


      ftp_data_reuse: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ftp/main.zeek` is loaded)


      ssl: :zeek:type:`SSL::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ssl/main.zeek` is loaded)


      http: :zeek:type:`HTTP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/main.zeek` is loaded)


      http_state: :zeek:type:`HTTP::State` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/main.zeek` is loaded)


      irc: :zeek:type:`IRC::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/main.zeek` is loaded)

         IRC session information.

      krb: :zeek:type:`KRB::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/main.zeek` is loaded)


      modbus: :zeek:type:`Modbus::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/modbus/main.zeek` is loaded)


      mysql: :zeek:type:`MySQL::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/mysql/main.zeek` is loaded)


      ntlm: :zeek:type:`NTLM::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ntlm/main.zeek` is loaded)


      ntp: :zeek:type:`NTP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ntp/main.zeek` is loaded)


      radius: :zeek:type:`RADIUS::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/radius/main.zeek` is loaded)


      rdp: :zeek:type:`RDP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/rdp/main.zeek` is loaded)


      rfb: :zeek:type:`RFB::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/rfb/main.zeek` is loaded)


      sip: :zeek:type:`SIP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/sip/main.zeek` is loaded)


      sip_state: :zeek:type:`SIP::State` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/sip/main.zeek` is loaded)


      snmp: :zeek:type:`SNMP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/snmp/main.zeek` is loaded)


      smb_state: :zeek:type:`SMB::State` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smb/main.zeek` is loaded)


      smtp: :zeek:type:`SMTP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/main.zeek` is loaded)


      smtp_state: :zeek:type:`SMTP::State` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/main.zeek` is loaded)


      socks: :zeek:type:`SOCKS::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/socks/main.zeek` is loaded)


      ssh: :zeek:type:`SSH::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ssh/main.zeek` is loaded)


      syslog: :zeek:type:`Syslog::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/syslog/main.zeek` is loaded)


      known_services_done: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/conn/known-services.zeek` is loaded)


      mqtt: :zeek:type:`MQTT::ConnectInfo` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/mqtt/main.zeek` is loaded)


      mqtt_state: :zeek:type:`MQTT::State` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/mqtt/main.zeek` is loaded)


      speculative_service: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/conn/speculative-service.zeek` is loaded)


   A connection. This is Zeek's basic connection type describing IP- and
   transport-layer information about the conversation. Note that Zeek uses a
   liberal interpretation of "connection" and associates instances of this type
   also with UDP and ICMP flows.

.. zeek:type:: count_set

   :Type: :zeek:type:`set` [:zeek:type:`count`]

   A set of counts.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: dns_answer

   :Type: :zeek:type:`record`

      answer_type: :zeek:type:`count`
         Answer type. One of :zeek:see:`DNS_QUERY`, :zeek:see:`DNS_ANS`,
         :zeek:see:`DNS_AUTH` and :zeek:see:`DNS_ADDL`.

      query: :zeek:type:`string`
         Query.

      qtype: :zeek:type:`count`
         Query type.

      qclass: :zeek:type:`count`
         Query class.

      TTL: :zeek:type:`interval`
         Time-to-live.

   The general part of a DNS reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply
      dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TXT_reply dns_WKS_reply

.. zeek:type:: dns_dnskey_rr

   :Type: :zeek:type:`record`

      query: :zeek:type:`string`
         Query.

      answer_type: :zeek:type:`count`
         Ans type.

      flags: :zeek:type:`count`
         flags filed.

      protocol: :zeek:type:`count`
         Protocol, should be always 3 for DNSSEC.

      algorithm: :zeek:type:`count`
         Algorithm for Public Key.

      public_key: :zeek:type:`string`
         Public Key

      is_query: :zeek:type:`count`
         The RR is a query/Response.

   A DNSSEC DNSKEY record.
   
   .. zeek:see:: dns_DNSKEY

.. zeek:type:: dns_ds_rr

   :Type: :zeek:type:`record`

      query: :zeek:type:`string`
         Query.

      answer_type: :zeek:type:`count`
         Ans type.

      key_tag: :zeek:type:`count`
         flags filed.

      algorithm: :zeek:type:`count`
         Algorithm for Public Key.

      digest_type: :zeek:type:`count`
         Digest Type.

      digest_val: :zeek:type:`string`
         Digest Value.

      is_query: :zeek:type:`count`
         The RR is a query/Response.

   A DNSSEC DS record.
   
   .. zeek:see:: dns_DS

.. zeek:type:: dns_edns_additional

   :Type: :zeek:type:`record`

      query: :zeek:type:`string`
         Query.

      qtype: :zeek:type:`count`
         Query type.

      t: :zeek:type:`count`
         TODO.

      payload_size: :zeek:type:`count`
         TODO.

      extended_rcode: :zeek:type:`count`
         Extended return code.

      version: :zeek:type:`count`
         Version.

      z_field: :zeek:type:`count`
         TODO.

      TTL: :zeek:type:`interval`
         Time-to-live.

      is_query: :zeek:type:`count`
         TODO.

   An additional DNS EDNS record.
   
   .. zeek:see:: dns_EDNS_addl

.. zeek:type:: dns_mapping

   :Type: :zeek:type:`record`

      creation_time: :zeek:type:`time`
         The time when the mapping was created, which corresponds to when
         the DNS query was sent out.

      req_host: :zeek:type:`string`
         If the mapping is the result of a name lookup, the queried host name;
         otherwise empty.

      req_addr: :zeek:type:`addr`
         If the mapping is the result of a pointer lookup, the queried
         address; otherwise null.

      valid: :zeek:type:`bool`
         True if the lookup returned success. Only then are the result fields
         valid.

      hostname: :zeek:type:`string`
         If the mapping is the result of a pointer lookup, the resolved
         hostname; otherwise empty.

      addrs: :zeek:type:`addr_set`
         If the mapping is the result of an address lookup, the resolved
         address(es); otherwise empty.


.. zeek:type:: dns_msg

   :Type: :zeek:type:`record`

      id: :zeek:type:`count`
         Transaction ID.

      opcode: :zeek:type:`count`
         Operation code.

      rcode: :zeek:type:`count`
         Return code.

      QR: :zeek:type:`bool`
         Query response flag.

      AA: :zeek:type:`bool`
         Authoritative answer flag.

      TC: :zeek:type:`bool`
         Truncated packet flag.

      RD: :zeek:type:`bool`
         Recursion desired flag.

      RA: :zeek:type:`bool`
         Recursion available flag.

      Z: :zeek:type:`count`
         TODO.

      num_queries: :zeek:type:`count`
         Number of query records.

      num_answers: :zeek:type:`count`
         Number of answer records.

      num_auth: :zeek:type:`count`
         Number of authoritative records.

      num_addl: :zeek:type:`count`
         Number of additional records.

   A DNS message.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_message dns_query_reply dns_rejected dns_request

.. zeek:type:: dns_nsec3_rr

   :Type: :zeek:type:`record`

      query: :zeek:type:`string`
         Query.

      answer_type: :zeek:type:`count`
         Ans type.

      nsec_flags: :zeek:type:`count`
         flags field.

      nsec_hash_algo: :zeek:type:`count`
         Hash algorithm.

      nsec_iter: :zeek:type:`count`
         Iterations.

      nsec_salt_len: :zeek:type:`count`
         Salt length.

      nsec_salt: :zeek:type:`string`
         Salt value

      nsec_hlen: :zeek:type:`count`
         Hash length.

      nsec_hash: :zeek:type:`string`
         Hash value.

      bitmaps: :zeek:type:`string_vec`
         Type Bit Maps.

      is_query: :zeek:type:`count`
         The RR is a query/Response.

   A DNSSEC NSEC3 record.
   
   .. zeek:see:: dns_NSEC3

.. zeek:type:: dns_rrsig_rr

   :Type: :zeek:type:`record`

      query: :zeek:type:`string`
         Query.

      answer_type: :zeek:type:`count`
         Ans type.

      type_covered: :zeek:type:`count`
         qtype covered by RRSIG RR.

      algorithm: :zeek:type:`count`
         Algorithm.

      labels: :zeek:type:`count`
         Labels in the owner's name.

      orig_ttl: :zeek:type:`interval`
         Original TTL.

      sig_exp: :zeek:type:`time`
         Time when signed RR expires.

      sig_incep: :zeek:type:`time`
         Time when signed.

      key_tag: :zeek:type:`count`
         Key tag value.

      signer_name: :zeek:type:`string`
         Signature.

      signature: :zeek:type:`string`
         Hash of the RRDATA.

      is_query: :zeek:type:`count`
         The RR is a query/Response.

   A DNSSEC RRSIG record.
   
   .. zeek:see:: dns_RRSIG

.. zeek:type:: dns_soa

   :Type: :zeek:type:`record`

      mname: :zeek:type:`string`
         Primary source of data for zone.

      rname: :zeek:type:`string`
         Mailbox for responsible person.

      serial: :zeek:type:`count`
         Version number of zone.

      refresh: :zeek:type:`interval`
         Seconds before refreshing.

      retry: :zeek:type:`interval`
         How long before retrying failed refresh.

      expire: :zeek:type:`interval`
         When zone no longer authoritative.

      minimum: :zeek:type:`interval`
         Minimum TTL to use when exporting.

   A DNS SOA record.
   
   .. zeek:see:: dns_SOA_reply

.. zeek:type:: dns_tsig_additional

   :Type: :zeek:type:`record`

      query: :zeek:type:`string`
         Query.

      qtype: :zeek:type:`count`
         Query type.

      alg_name: :zeek:type:`string`
         Algorithm name.

      sig: :zeek:type:`string`
         Signature.

      time_signed: :zeek:type:`time`
         Time when signed.

      fudge: :zeek:type:`time`
         TODO.

      orig_id: :zeek:type:`count`
         TODO.

      rr_error: :zeek:type:`count`
         TODO.

      is_query: :zeek:type:`count`
         TODO.

   An additional DNS TSIG record.
   
   .. zeek:see:: dns_TSIG_addl

.. zeek:type:: endpoint

   :Type: :zeek:type:`record`

      size: :zeek:type:`count`
         Logical size of data sent (for TCP: derived from sequence numbers).

      state: :zeek:type:`count`
         Endpoint state. For a TCP connection, one of the constants:
         :zeek:see:`TCP_INACTIVE` :zeek:see:`TCP_SYN_SENT`
         :zeek:see:`TCP_SYN_ACK_SENT` :zeek:see:`TCP_PARTIAL`
         :zeek:see:`TCP_ESTABLISHED` :zeek:see:`TCP_CLOSED` :zeek:see:`TCP_RESET`.
         For UDP, one of :zeek:see:`UDP_ACTIVE` and :zeek:see:`UDP_INACTIVE`.

      num_pkts: :zeek:type:`count` :zeek:attr:`&optional`
         Number of packets sent. Only set if :zeek:id:`use_conn_size_analyzer`
         is true.

      num_bytes_ip: :zeek:type:`count` :zeek:attr:`&optional`
         Number of IP-level bytes sent. Only set if
         :zeek:id:`use_conn_size_analyzer` is true.

      flow_label: :zeek:type:`count`
         The current IPv6 flow label that the connection endpoint is using.
         Always 0 if the connection is over IPv4.

      l2_addr: :zeek:type:`string` :zeek:attr:`&optional`
         The link-layer address seen in the first packet (if available).

   Statistics about a :zeek:type:`connection` endpoint.
   
   .. zeek:see:: connection

.. zeek:type:: endpoint_stats

   :Type: :zeek:type:`record`

      num_pkts: :zeek:type:`count`
         Number of packets.

      num_rxmit: :zeek:type:`count`
         Number of retransmissions.

      num_rxmit_bytes: :zeek:type:`count`
         Number of retransmitted bytes.

      num_in_order: :zeek:type:`count`
         Number of in-order packets.

      num_OO: :zeek:type:`count`
         Number of out-of-order packets.

      num_repl: :zeek:type:`count`
         Number of replicated packets (last packet was sent again).

      endian_type: :zeek:type:`count`
         Endian type used by the endpoint, if it could be determined from
         the sequence numbers used. This is one of :zeek:see:`ENDIAN_UNKNOWN`,
         :zeek:see:`ENDIAN_BIG`, :zeek:see:`ENDIAN_LITTLE`, and
         :zeek:see:`ENDIAN_CONFUSED`.

   Statistics about what a TCP endpoint sent.
   
   .. zeek:see:: conn_stats

.. zeek:type:: entropy_test_result

   :Type: :zeek:type:`record`

      entropy: :zeek:type:`double`
         Information density.

      chi_square: :zeek:type:`double`
         Chi-Square value.

      mean: :zeek:type:`double`
         Arithmetic Mean.

      monte_carlo_pi: :zeek:type:`double`
         Monte-carlo value for pi.

      serial_correlation: :zeek:type:`double`
         Serial correlation coefficient.

   Computed entropy values. The record captures a number of measures that are
   computed in parallel. See `A Pseudorandom Number Sequence Test Program
   <http://www.fourmilab.ch/random>`_ for more information, Zeek uses the same
   code.
   
   .. zeek:see:: entropy_test_add entropy_test_finish entropy_test_init find_entropy

.. zeek:type:: fa_file

   :Type: :zeek:type:`record`

      id: :zeek:type:`string`
         An identifier associated with a single file.

      parent_id: :zeek:type:`string` :zeek:attr:`&optional`
         Identifier associated with a container file from which this one was
         extracted as part of the file analysis.

      source: :zeek:type:`string`
         An identification of the source of the file data. E.g. it may be
         a network protocol over which it was transferred, or a local file
         path which was read, or some other input source.
         Examples are: "HTTP", "SMTP", "IRC_DATA", or the file path.

      is_orig: :zeek:type:`bool` :zeek:attr:`&optional`
         If the source of this file is a network connection, this field
         may be set to indicate the directionality.

      conns: :zeek:type:`table` [:zeek:type:`conn_id`] of :zeek:type:`connection` :zeek:attr:`&optional`
         The set of connections over which the file was transferred.

      last_active: :zeek:type:`time`
         The time at which the last activity for the file was seen.

      seen_bytes: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Number of bytes provided to the file analysis engine for the file.

      total_bytes: :zeek:type:`count` :zeek:attr:`&optional`
         Total number of bytes that are supposed to comprise the full file.

      missing_bytes: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of bytes in the file stream that were completely missed
         during the process of analysis e.g. due to dropped packets.

      overflow_bytes: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of bytes in the file stream that were not delivered to
         stream file analyzers.  Generally, this consists of bytes that
         couldn't be reassembled, either because reassembly simply isn't
         enabled, or due to size limitations of the reassembly buffer.

      timeout_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`default_file_timeout_interval` :zeek:attr:`&optional`
         The amount of time between receiving new data for this file that
         the analysis engine will wait before giving up on it.

      bof_buffer_size: :zeek:type:`count` :zeek:attr:`&default` = :zeek:see:`default_file_bof_buffer_size` :zeek:attr:`&optional`
         The number of bytes at the beginning of a file to save for later
         inspection in the *bof_buffer* field.

      bof_buffer: :zeek:type:`string` :zeek:attr:`&optional`
         The content of the beginning of a file up to *bof_buffer_size* bytes.
         This is also the buffer that's used for file/mime type detection.

      info: :zeek:type:`Files::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/files/main.zeek` is loaded)


      ftp: :zeek:type:`FTP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ftp/files.zeek` is loaded)


      http: :zeek:type:`HTTP::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)


      irc: :zeek:type:`IRC::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/files.zeek` is loaded)


      pe: :zeek:type:`PE::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/files/pe/main.zeek` is loaded)


      u2_events: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`Unified2::IDSEvent` :zeek:attr:`&optional` :zeek:attr:`&create_expire` = ``5.0 secs`` :zeek:attr:`&expire_func` = :zeek:type:`function`
         (present if :doc:`/scripts/policy/files/unified2/main.zeek` is loaded)

         Recently received IDS events.  This is primarily used
         for tying together Unified2 events and packets.

      logcert: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssl/log-hostcerts-only.zeek` is loaded)

   :Attributes: :zeek:attr:`&redef`

   A file that Zeek is analyzing.  This is Zeek's type for describing the basic
   internal metadata collected about a "file", which is essentially just a
   byte stream that is e.g. pulled from a network connection or possibly
   some other input source.

.. zeek:type:: fa_metadata

   :Type: :zeek:type:`record`

      mime_type: :zeek:type:`string` :zeek:attr:`&optional`
         The strongest matching MIME type if one was discovered.

      mime_types: :zeek:type:`mime_matches` :zeek:attr:`&optional`
         All matching MIME types if any were discovered.

      inferred: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Specifies whether the MIME type was inferred using signatures,
         or provided directly by the protocol the file appeared in.

   Metadata that's been inferred about a particular file.

.. zeek:type:: files_tag_set

   :Type: :zeek:type:`set` [:zeek:type:`Files::Tag`]

   A set of file analyzer tags.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: flow_id

   :Type: :zeek:type:`record`

      src_h: :zeek:type:`addr` :zeek:attr:`&log`
         The source IP address.

      src_p: :zeek:type:`port` :zeek:attr:`&log`
         The source port number.

      dst_h: :zeek:type:`addr` :zeek:attr:`&log`
         The destination IP address.

      dst_p: :zeek:type:`port` :zeek:attr:`&log`
         The desintation port number.
   :Attributes: :zeek:attr:`&log`

   The identifying 4-tuple of a uni-directional flow.
   
   .. note:: It's actually a 5-tuple: the transport-layer protocol is stored as
      part of the port values, `src_p` and `dst_p`, and can be extracted from
      them with :zeek:id:`get_port_transport_proto`.

.. zeek:type:: ftp_port

   :Type: :zeek:type:`record`

      h: :zeek:type:`addr`
         The host's address.

      p: :zeek:type:`port`
         The host's port.

      valid: :zeek:type:`bool`
         True if format was right. Only then are *h* and *p* valid.

   A parsed host/port combination describing server endpoint for an upcoming
   data transfer.
   
   .. zeek:see:: fmt_ftp_port parse_eftp_port parse_ftp_epsv parse_ftp_pasv
      parse_ftp_port

.. zeek:type:: geo_location

   :Type: :zeek:type:`record`

      country_code: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         The country code.

      region: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         The region.

      city: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         The city.

      latitude: :zeek:type:`double` :zeek:attr:`&optional` :zeek:attr:`&log`
         Latitude.

      longitude: :zeek:type:`double` :zeek:attr:`&optional` :zeek:attr:`&log`
         Longitude.
   :Attributes: :zeek:attr:`&log`

   GeoIP location information.
   
   .. zeek:see:: lookup_location

.. zeek:type:: gtp_access_point_name

   :Type: :zeek:type:`string`


.. zeek:type:: gtp_cause

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_charging_characteristics

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_charging_gateway_addr

   :Type: :zeek:type:`addr`


.. zeek:type:: gtp_charging_id

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_create_pdp_ctx_request_elements

   :Type: :zeek:type:`record`

      imsi: :zeek:type:`gtp_imsi` :zeek:attr:`&optional`

      rai: :zeek:type:`gtp_rai` :zeek:attr:`&optional`

      recovery: :zeek:type:`gtp_recovery` :zeek:attr:`&optional`

      select_mode: :zeek:type:`gtp_selection_mode` :zeek:attr:`&optional`

      data1: :zeek:type:`gtp_teid1`

      cp: :zeek:type:`gtp_teid_control_plane` :zeek:attr:`&optional`

      nsapi: :zeek:type:`gtp_nsapi`

      linked_nsapi: :zeek:type:`gtp_nsapi` :zeek:attr:`&optional`

      charge_character: :zeek:type:`gtp_charging_characteristics` :zeek:attr:`&optional`

      trace_ref: :zeek:type:`gtp_trace_reference` :zeek:attr:`&optional`

      trace_type: :zeek:type:`gtp_trace_type` :zeek:attr:`&optional`

      end_user_addr: :zeek:type:`gtp_end_user_addr` :zeek:attr:`&optional`

      ap_name: :zeek:type:`gtp_access_point_name` :zeek:attr:`&optional`

      opts: :zeek:type:`gtp_proto_config_options` :zeek:attr:`&optional`

      signal_addr: :zeek:type:`gtp_gsn_addr`

      user_addr: :zeek:type:`gtp_gsn_addr`

      msisdn: :zeek:type:`gtp_msisdn` :zeek:attr:`&optional`

      qos_prof: :zeek:type:`gtp_qos_profile`

      tft: :zeek:type:`gtp_tft` :zeek:attr:`&optional`

      trigger_id: :zeek:type:`gtp_trigger_id` :zeek:attr:`&optional`

      omc_id: :zeek:type:`gtp_omc_id` :zeek:attr:`&optional`

      ext: :zeek:type:`gtp_private_extension` :zeek:attr:`&optional`


.. zeek:type:: gtp_create_pdp_ctx_response_elements

   :Type: :zeek:type:`record`

      cause: :zeek:type:`gtp_cause`

      reorder_req: :zeek:type:`gtp_reordering_required` :zeek:attr:`&optional`

      recovery: :zeek:type:`gtp_recovery` :zeek:attr:`&optional`

      data1: :zeek:type:`gtp_teid1` :zeek:attr:`&optional`

      cp: :zeek:type:`gtp_teid_control_plane` :zeek:attr:`&optional`

      charging_id: :zeek:type:`gtp_charging_id` :zeek:attr:`&optional`

      end_user_addr: :zeek:type:`gtp_end_user_addr` :zeek:attr:`&optional`

      opts: :zeek:type:`gtp_proto_config_options` :zeek:attr:`&optional`

      cp_addr: :zeek:type:`gtp_gsn_addr` :zeek:attr:`&optional`

      user_addr: :zeek:type:`gtp_gsn_addr` :zeek:attr:`&optional`

      qos_prof: :zeek:type:`gtp_qos_profile` :zeek:attr:`&optional`

      charge_gateway: :zeek:type:`gtp_charging_gateway_addr` :zeek:attr:`&optional`

      ext: :zeek:type:`gtp_private_extension` :zeek:attr:`&optional`


.. zeek:type:: gtp_delete_pdp_ctx_request_elements

   :Type: :zeek:type:`record`

      teardown_ind: :zeek:type:`gtp_teardown_ind` :zeek:attr:`&optional`

      nsapi: :zeek:type:`gtp_nsapi`

      ext: :zeek:type:`gtp_private_extension` :zeek:attr:`&optional`


.. zeek:type:: gtp_delete_pdp_ctx_response_elements

   :Type: :zeek:type:`record`

      cause: :zeek:type:`gtp_cause`

      ext: :zeek:type:`gtp_private_extension` :zeek:attr:`&optional`


.. zeek:type:: gtp_end_user_addr

   :Type: :zeek:type:`record`

      pdp_type_org: :zeek:type:`count`

      pdp_type_num: :zeek:type:`count`

      pdp_ip: :zeek:type:`addr` :zeek:attr:`&optional`
         Set if the End User Address information element is IPv4/IPv6.

      pdp_other_addr: :zeek:type:`string` :zeek:attr:`&optional`
         Set if the End User Address information element isn't IPv4/IPv6.


.. zeek:type:: gtp_gsn_addr

   :Type: :zeek:type:`record`

      ip: :zeek:type:`addr` :zeek:attr:`&optional`
         If the GSN Address information element has length 4 or 16, then this
         field is set to be the informational element's value interpreted as
         an IPv4 or IPv6 address, respectively.

      other: :zeek:type:`string` :zeek:attr:`&optional`
         This field is set if it's not an IPv4 or IPv6 address.


.. zeek:type:: gtp_imsi

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_msisdn

   :Type: :zeek:type:`string`


.. zeek:type:: gtp_nsapi

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_omc_id

   :Type: :zeek:type:`string`


.. zeek:type:: gtp_private_extension

   :Type: :zeek:type:`record`

      id: :zeek:type:`count`

      value: :zeek:type:`string`


.. zeek:type:: gtp_proto_config_options

   :Type: :zeek:type:`string`


.. zeek:type:: gtp_qos_profile

   :Type: :zeek:type:`record`

      priority: :zeek:type:`count`

      data: :zeek:type:`string`


.. zeek:type:: gtp_rai

   :Type: :zeek:type:`record`

      mcc: :zeek:type:`count`

      mnc: :zeek:type:`count`

      lac: :zeek:type:`count`

      rac: :zeek:type:`count`


.. zeek:type:: gtp_recovery

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_reordering_required

   :Type: :zeek:type:`bool`


.. zeek:type:: gtp_selection_mode

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_teardown_ind

   :Type: :zeek:type:`bool`


.. zeek:type:: gtp_teid1

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_teid_control_plane

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_tft

   :Type: :zeek:type:`string`


.. zeek:type:: gtp_trace_reference

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_trace_type

   :Type: :zeek:type:`count`


.. zeek:type:: gtp_trigger_id

   :Type: :zeek:type:`string`


.. zeek:type:: gtp_update_pdp_ctx_request_elements

   :Type: :zeek:type:`record`

      imsi: :zeek:type:`gtp_imsi` :zeek:attr:`&optional`

      rai: :zeek:type:`gtp_rai` :zeek:attr:`&optional`

      recovery: :zeek:type:`gtp_recovery` :zeek:attr:`&optional`

      data1: :zeek:type:`gtp_teid1`

      cp: :zeek:type:`gtp_teid_control_plane` :zeek:attr:`&optional`

      nsapi: :zeek:type:`gtp_nsapi`

      trace_ref: :zeek:type:`gtp_trace_reference` :zeek:attr:`&optional`

      trace_type: :zeek:type:`gtp_trace_type` :zeek:attr:`&optional`

      cp_addr: :zeek:type:`gtp_gsn_addr`

      user_addr: :zeek:type:`gtp_gsn_addr`

      qos_prof: :zeek:type:`gtp_qos_profile`

      tft: :zeek:type:`gtp_tft` :zeek:attr:`&optional`

      trigger_id: :zeek:type:`gtp_trigger_id` :zeek:attr:`&optional`

      omc_id: :zeek:type:`gtp_omc_id` :zeek:attr:`&optional`

      ext: :zeek:type:`gtp_private_extension` :zeek:attr:`&optional`

      end_user_addr: :zeek:type:`gtp_end_user_addr` :zeek:attr:`&optional`


.. zeek:type:: gtp_update_pdp_ctx_response_elements

   :Type: :zeek:type:`record`

      cause: :zeek:type:`gtp_cause`

      recovery: :zeek:type:`gtp_recovery` :zeek:attr:`&optional`

      data1: :zeek:type:`gtp_teid1` :zeek:attr:`&optional`

      cp: :zeek:type:`gtp_teid_control_plane` :zeek:attr:`&optional`

      charging_id: :zeek:type:`gtp_charging_id` :zeek:attr:`&optional`

      cp_addr: :zeek:type:`gtp_gsn_addr` :zeek:attr:`&optional`

      user_addr: :zeek:type:`gtp_gsn_addr` :zeek:attr:`&optional`

      qos_prof: :zeek:type:`gtp_qos_profile` :zeek:attr:`&optional`

      charge_gateway: :zeek:type:`gtp_charging_gateway_addr` :zeek:attr:`&optional`

      ext: :zeek:type:`gtp_private_extension` :zeek:attr:`&optional`


.. zeek:type:: gtpv1_hdr

   :Type: :zeek:type:`record`

      version: :zeek:type:`count`
         The 3-bit version field, which for GTPv1 should be 1.

      pt_flag: :zeek:type:`bool`
         Protocol Type value differentiates GTP (value 1) from GTP' (value 0).

      rsv: :zeek:type:`bool`
         Reserved field, should be 0.

      e_flag: :zeek:type:`bool`
         Extension Header flag.  When 0, the *next_type* field may or may not
         be present, but shouldn't be meaningful.  When 1, *next_type* is
         present and meaningful.

      s_flag: :zeek:type:`bool`
         Sequence Number flag.  When 0, the *seq* field may or may not
         be present, but shouldn't be meaningful.  When 1, *seq* is
         present and meaningful.

      pn_flag: :zeek:type:`bool`
         N-PDU flag.  When 0, the *n_pdu* field may or may not
         be present, but shouldn't be meaningful.  When 1, *n_pdu* is
         present and meaningful.

      msg_type: :zeek:type:`count`
         Message Type.  A value of 255 indicates user-plane data is encapsulated.

      length: :zeek:type:`count`
         Length of the GTP packet payload (the rest of the packet following
         the mandatory 8-byte GTP header).

      teid: :zeek:type:`count`
         Tunnel Endpoint Identifier.  Unambiguously identifies a tunnel
         endpoint in receiving GTP-U or GTP-C protocol entity.

      seq: :zeek:type:`count` :zeek:attr:`&optional`
         Sequence Number.  Set if any *e_flag*, *s_flag*, or *pn_flag* field
         is set.

      n_pdu: :zeek:type:`count` :zeek:attr:`&optional`
         N-PDU Number.  Set if any *e_flag*, *s_flag*, or *pn_flag* field is set.

      next_type: :zeek:type:`count` :zeek:attr:`&optional`
         Next Extension Header Type.  Set if any *e_flag*, *s_flag*, or
         *pn_flag* field is set.

   A GTPv1 (GPRS Tunneling Protocol) header.

.. zeek:type:: http_message_stat

   :Type: :zeek:type:`record`

      start: :zeek:type:`time`
         When the request/reply line was complete.

      interrupted: :zeek:type:`bool`
         Whether the message was interrupted.

      finish_msg: :zeek:type:`string`
         Reason phrase if interrupted.

      body_length: :zeek:type:`count`
         Length of body processed (before finished/interrupted).

      content_gap_length: :zeek:type:`count`
         Total length of gaps within *body_length*.

      header_length: :zeek:type:`count`
         Length of headers (including the req/reply line, but not CR/LF's).

   HTTP message statistics.
   
   .. zeek:see:: http_message_done

.. zeek:type:: http_stats_rec

   :Type: :zeek:type:`record`

      num_requests: :zeek:type:`count`
         Number of requests.

      num_replies: :zeek:type:`count`
         Number of replies.

      request_version: :zeek:type:`double`
         HTTP version of the requests.

      reply_version: :zeek:type:`double`
         HTTP Version of the replies.

   HTTP session statistics.
   
   .. zeek:see:: http_stats

.. zeek:type:: icmp6_nd_option

   :Type: :zeek:type:`record`

      otype: :zeek:type:`count`
         8-bit identifier of the type of option.

      len: :zeek:type:`count`
         8-bit integer representing the length of the option (including the
         type and length fields) in units of 8 octets.

      link_address: :zeek:type:`string` :zeek:attr:`&optional`
         Source Link-Layer Address (Type 1) or Target Link-Layer Address (Type 2).
         Byte ordering of this is dependent on the actual link-layer.

      prefix: :zeek:type:`icmp6_nd_prefix_info` :zeek:attr:`&optional`
         Prefix Information (Type 3).

      redirect: :zeek:type:`icmp_context` :zeek:attr:`&optional`
         Redirected header (Type 4).  This field contains the context of the
         original, redirected packet.

      mtu: :zeek:type:`count` :zeek:attr:`&optional`
         Recommended MTU for the link (Type 5).

      payload: :zeek:type:`string` :zeek:attr:`&optional`
         The raw data of the option (everything after type & length fields),
         useful for unknown option types or when the full option payload is
         truncated in the captured packet.  In those cases, option fields
         won't be pre-extracted into the fields above.

   Options extracted from ICMPv6 neighbor discovery messages as specified
   by :rfc:`4861`.
   
   .. zeek:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_advertisement icmp_neighbor_solicitation icmp_redirect
      icmp6_nd_options

.. zeek:type:: icmp6_nd_options

   :Type: :zeek:type:`vector` of :zeek:type:`icmp6_nd_option`

   A type alias for a vector of ICMPv6 neighbor discovery message options.

.. zeek:type:: icmp6_nd_prefix_info

   :Type: :zeek:type:`record`

      prefix_len: :zeek:type:`count`
         Number of leading bits of the *prefix* that are valid.

      L_flag: :zeek:type:`bool`
         Flag indicating the prefix can be used for on-link determination.

      A_flag: :zeek:type:`bool`
         Autonomous address-configuration flag.

      valid_lifetime: :zeek:type:`interval`
         Length of time in seconds that the prefix is valid for purpose of
         on-link determination (0xffffffff represents infinity).

      preferred_lifetime: :zeek:type:`interval`
         Length of time in seconds that the addresses generated from the
         prefix via stateless address autoconfiguration remain preferred
         (0xffffffff represents infinity).

      prefix: :zeek:type:`addr`
         An IP address or prefix of an IP address.  Use the *prefix_len* field
         to convert this into a :zeek:type:`subnet`.

   Values extracted from a Prefix Information option in an ICMPv6 neighbor
   discovery message as specified by :rfc:`4861`.
   
   .. zeek:see:: icmp6_nd_option

.. zeek:type:: icmp_conn

   :Type: :zeek:type:`record`

      orig_h: :zeek:type:`addr`
         The originator's IP address.

      resp_h: :zeek:type:`addr`
         The responder's IP address.

      itype: :zeek:type:`count`
         The ICMP type of the packet that triggered the instantiation of the record.

      icode: :zeek:type:`count`
         The ICMP code of the packet that triggered the instantiation of the record.

      len: :zeek:type:`count`
         The length of the ICMP payload of the packet that triggered the instantiation of the record.

      hlim: :zeek:type:`count`
         The encapsulating IP header's Hop Limit value.

      v6: :zeek:type:`bool`
         True if it's an ICMPv6 packet.

   Specifics about an ICMP conversation. ICMP events typically pass this in
   addition to :zeek:type:`conn_id`.
   
   .. zeek:see:: icmp_echo_reply icmp_echo_request icmp_redirect icmp_sent
      icmp_time_exceeded icmp_unreachable

.. zeek:type:: icmp_context

   :Type: :zeek:type:`record`

      id: :zeek:type:`conn_id`
         The packet's 4-tuple.

      len: :zeek:type:`count`
         The length of the IP packet (headers + payload).

      proto: :zeek:type:`count`
         The packet's transport-layer protocol.

      frag_offset: :zeek:type:`count`
         The packet's fragmentation offset.

      bad_hdr_len: :zeek:type:`bool`
         True if the packet's IP header is not fully included in the context
         or if there is not enough of the transport header to determine source
         and destination ports. If that is the case, the appropriate fields
         of this record will be set to null values.

      bad_checksum: :zeek:type:`bool`
         True if the packet's IP checksum is not correct.

      MF: :zeek:type:`bool`
         True if the packet's *more fragments* flag is set.

      DF: :zeek:type:`bool`
         True if the packet's *don't fragment* flag is set.

   Packet context part of an ICMP message. The fields of this record reflect the
   packet that is described by the context.
   
   .. zeek:see:: icmp_time_exceeded icmp_unreachable

.. zeek:type:: icmp_hdr

   :Type: :zeek:type:`record`

      icmp_type: :zeek:type:`count`
         type of message

   Values extracted from an ICMP header.
   
   .. zeek:see:: pkt_hdr discarder_check_icmp

.. zeek:type:: id_table

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`script_id`

   Table type used to map script-level identifiers to meta-information
   describing them.
   
   .. zeek:see:: global_ids script_id
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: index_vec

   :Type: :zeek:type:`vector` of :zeek:type:`count`

   A vector of counts, used by some builtin functions to store a list of indices.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: interval_set

   :Type: :zeek:type:`set` [:zeek:type:`interval`]

   A set of intervals.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: ip4_hdr

   :Type: :zeek:type:`record`

      hl: :zeek:type:`count`
         Header length in bytes.

      tos: :zeek:type:`count`
         Type of service.

      len: :zeek:type:`count`
         Total length.

      id: :zeek:type:`count`
         Identification.

      ttl: :zeek:type:`count`
         Time to live.

      p: :zeek:type:`count`
         Protocol.

      src: :zeek:type:`addr`
         Source address.

      dst: :zeek:type:`addr`
         Destination address.

   Values extracted from an IPv4 header.
   
   .. zeek:see:: pkt_hdr ip6_hdr discarder_check_ip

.. zeek:type:: ip6_ah

   :Type: :zeek:type:`record`

      nxt: :zeek:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :zeek:id:`IPPROTO_ICMP`.

      len: :zeek:type:`count`
         Length of header in 4-octet units, excluding first two units.

      rsv: :zeek:type:`count`
         Reserved field.

      spi: :zeek:type:`count`
         Security Parameter Index.

      seq: :zeek:type:`count` :zeek:attr:`&optional`
         Sequence number, unset in the case that *len* field is zero.

      data: :zeek:type:`string` :zeek:attr:`&optional`
         Authentication data, unset in the case that *len* field is zero.

   Values extracted from an IPv6 Authentication extension header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. zeek:type:: ip6_dstopts

   :Type: :zeek:type:`record`

      nxt: :zeek:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :zeek:id:`IPPROTO_ICMP`.

      len: :zeek:type:`count`
         Length of header in 8-octet units, excluding first unit.

      options: :zeek:type:`ip6_options`
         The TLV encoded options;

   Values extracted from an IPv6 Destination options extension header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr ip6_option

.. zeek:type:: ip6_esp

   :Type: :zeek:type:`record`

      spi: :zeek:type:`count`
         Security Parameters Index.

      seq: :zeek:type:`count`
         Sequence number.

   Values extracted from an IPv6 ESP extension header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. zeek:type:: ip6_ext_hdr

   :Type: :zeek:type:`record`

      id: :zeek:type:`count`
         The RFC 1700 et seq. IANA assigned number identifying the type of
         the extension header.

      hopopts: :zeek:type:`ip6_hopopts` :zeek:attr:`&optional`
         Hop-by-hop option extension header.

      dstopts: :zeek:type:`ip6_dstopts` :zeek:attr:`&optional`
         Destination option extension header.

      routing: :zeek:type:`ip6_routing` :zeek:attr:`&optional`
         Routing extension header.

      fragment: :zeek:type:`ip6_fragment` :zeek:attr:`&optional`
         Fragment header.

      ah: :zeek:type:`ip6_ah` :zeek:attr:`&optional`
         Authentication extension header.

      esp: :zeek:type:`ip6_esp` :zeek:attr:`&optional`
         Encapsulating security payload header.

      mobility: :zeek:type:`ip6_mobility_hdr` :zeek:attr:`&optional`
         Mobility header.

   A general container for a more specific IPv6 extension header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_hopopts ip6_dstopts ip6_routing ip6_fragment
      ip6_ah ip6_esp

.. zeek:type:: ip6_ext_hdr_chain

   :Type: :zeek:type:`vector` of :zeek:type:`ip6_ext_hdr`

   A type alias for a vector of IPv6 extension headers.

.. zeek:type:: ip6_fragment

   :Type: :zeek:type:`record`

      nxt: :zeek:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :zeek:id:`IPPROTO_ICMP`.

      rsv1: :zeek:type:`count`
         8-bit reserved field.

      offset: :zeek:type:`count`
         Fragmentation offset.

      rsv2: :zeek:type:`count`
         2-bit reserved field.

      more: :zeek:type:`bool`
         More fragments.

      id: :zeek:type:`count`
         Fragment identification.

   Values extracted from an IPv6 Fragment extension header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. zeek:type:: ip6_hdr

   :Type: :zeek:type:`record`

      class: :zeek:type:`count`
         Traffic class.

      flow: :zeek:type:`count`
         Flow label.

      len: :zeek:type:`count`
         Payload length.

      nxt: :zeek:type:`count`
         Protocol number of the next header
         (RFC 1700 et seq., IANA assigned number)
         e.g. :zeek:id:`IPPROTO_ICMP`.

      hlim: :zeek:type:`count`
         Hop limit.

      src: :zeek:type:`addr`
         Source address.

      dst: :zeek:type:`addr`
         Destination address.

      exts: :zeek:type:`ip6_ext_hdr_chain`
         Extension header chain.

   Values extracted from an IPv6 header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_ext_hdr ip6_hopopts ip6_dstopts
      ip6_routing ip6_fragment ip6_ah ip6_esp

.. zeek:type:: ip6_hopopts

   :Type: :zeek:type:`record`

      nxt: :zeek:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :zeek:id:`IPPROTO_ICMP`.

      len: :zeek:type:`count`
         Length of header in 8-octet units, excluding first unit.

      options: :zeek:type:`ip6_options`
         The TLV encoded options;

   Values extracted from an IPv6 Hop-by-Hop options extension header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr ip6_option

.. zeek:type:: ip6_mobility_back

   :Type: :zeek:type:`record`

      status: :zeek:type:`count`
         Status.

      k: :zeek:type:`bool`
         Key Management Mobility Capability.

      seq: :zeek:type:`count`
         Sequence number.

      life: :zeek:type:`count`
         Lifetime.

      options: :zeek:type:`vector` of :zeek:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Binding Acknowledgement message.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. zeek:type:: ip6_mobility_be

   :Type: :zeek:type:`record`

      status: :zeek:type:`count`
         Status.

      hoa: :zeek:type:`addr`
         Home Address.

      options: :zeek:type:`vector` of :zeek:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Binding Error message.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. zeek:type:: ip6_mobility_brr

   :Type: :zeek:type:`record`

      rsv: :zeek:type:`count`
         Reserved.

      options: :zeek:type:`vector` of :zeek:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Binding Refresh Request message.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. zeek:type:: ip6_mobility_bu

   :Type: :zeek:type:`record`

      seq: :zeek:type:`count`
         Sequence number.

      a: :zeek:type:`bool`
         Acknowledge bit.

      h: :zeek:type:`bool`
         Home Registration bit.

      l: :zeek:type:`bool`
         Link-Local Address Compatibility bit.

      k: :zeek:type:`bool`
         Key Management Mobility Capability bit.

      life: :zeek:type:`count`
         Lifetime.

      options: :zeek:type:`vector` of :zeek:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Binding Update message.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. zeek:type:: ip6_mobility_cot

   :Type: :zeek:type:`record`

      nonce_idx: :zeek:type:`count`
         Care-of Nonce Index.

      cookie: :zeek:type:`count`
         Care-of Init Cookie.

      token: :zeek:type:`count`
         Care-of Keygen Token.

      options: :zeek:type:`vector` of :zeek:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Care-of Test message.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. zeek:type:: ip6_mobility_coti

   :Type: :zeek:type:`record`

      rsv: :zeek:type:`count`
         Reserved.

      cookie: :zeek:type:`count`
         Care-of Init Cookie.

      options: :zeek:type:`vector` of :zeek:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Care-of Test Init message.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. zeek:type:: ip6_mobility_hdr

   :Type: :zeek:type:`record`

      nxt: :zeek:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :zeek:id:`IPPROTO_ICMP`.

      len: :zeek:type:`count`
         Length of header in 8-octet units, excluding first unit.

      mh_type: :zeek:type:`count`
         Mobility header type used to identify header's the message.

      rsv: :zeek:type:`count`
         Reserved field.

      chksum: :zeek:type:`count`
         Mobility header checksum.

      msg: :zeek:type:`ip6_mobility_msg`
         Mobility header message

   Values extracted from an IPv6 Mobility header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. zeek:type:: ip6_mobility_hot

   :Type: :zeek:type:`record`

      nonce_idx: :zeek:type:`count`
         Home Nonce Index.

      cookie: :zeek:type:`count`
         Home Init Cookie.

      token: :zeek:type:`count`
         Home Keygen Token.

      options: :zeek:type:`vector` of :zeek:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Home Test message.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. zeek:type:: ip6_mobility_hoti

   :Type: :zeek:type:`record`

      rsv: :zeek:type:`count`
         Reserved.

      cookie: :zeek:type:`count`
         Home Init Cookie.

      options: :zeek:type:`vector` of :zeek:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Home Test Init message.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. zeek:type:: ip6_mobility_msg

   :Type: :zeek:type:`record`

      id: :zeek:type:`count`
         The type of message from the header's MH Type field.

      brr: :zeek:type:`ip6_mobility_brr` :zeek:attr:`&optional`
         Binding Refresh Request.

      hoti: :zeek:type:`ip6_mobility_hoti` :zeek:attr:`&optional`
         Home Test Init.

      coti: :zeek:type:`ip6_mobility_coti` :zeek:attr:`&optional`
         Care-of Test Init.

      hot: :zeek:type:`ip6_mobility_hot` :zeek:attr:`&optional`
         Home Test.

      cot: :zeek:type:`ip6_mobility_cot` :zeek:attr:`&optional`
         Care-of Test.

      bu: :zeek:type:`ip6_mobility_bu` :zeek:attr:`&optional`
         Binding Update.

      back: :zeek:type:`ip6_mobility_back` :zeek:attr:`&optional`
         Binding Acknowledgement.

      be: :zeek:type:`ip6_mobility_be` :zeek:attr:`&optional`
         Binding Error.

   Values extracted from an IPv6 Mobility header's message data.
   
   .. zeek:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr

.. zeek:type:: ip6_option

   :Type: :zeek:type:`record`

      otype: :zeek:type:`count`
         Option type.

      len: :zeek:type:`count`
         Option data length.

      data: :zeek:type:`string`
         Option data.

   Values extracted from an IPv6 extension header's (e.g. hop-by-hop or
   destination option headers) option field.
   
   .. zeek:see:: ip6_hdr ip6_ext_hdr ip6_hopopts ip6_dstopts

.. zeek:type:: ip6_options

   :Type: :zeek:type:`vector` of :zeek:type:`ip6_option`

   A type alias for a vector of IPv6 options.

.. zeek:type:: ip6_routing

   :Type: :zeek:type:`record`

      nxt: :zeek:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :zeek:id:`IPPROTO_ICMP`.

      len: :zeek:type:`count`
         Length of header in 8-octet units, excluding first unit.

      rtype: :zeek:type:`count`
         Routing type.

      segleft: :zeek:type:`count`
         Segments left.

      data: :zeek:type:`string`
         Type-specific data.

   Values extracted from an IPv6 Routing extension header.
   
   .. zeek:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. zeek:type:: irc_join_info

   :Type: :zeek:type:`record`

      nick: :zeek:type:`string`

      channel: :zeek:type:`string`

      password: :zeek:type:`string`

      usermode: :zeek:type:`string`

   IRC join information.
   
   .. zeek:see:: irc_join_list

.. zeek:type:: irc_join_list

   :Type: :zeek:type:`set` [:zeek:type:`irc_join_info`]

   Set of IRC join information.
   
   .. zeek:see:: irc_join_message

.. zeek:type:: l2_hdr

   :Type: :zeek:type:`record`

      encap: :zeek:type:`link_encap`
         L2 link encapsulation.

      len: :zeek:type:`count`
         Total frame length on wire.

      cap_len: :zeek:type:`count`
         Captured length.

      src: :zeek:type:`string` :zeek:attr:`&optional`
         L2 source (if Ethernet).

      dst: :zeek:type:`string` :zeek:attr:`&optional`
         L2 destination (if Ethernet).

      vlan: :zeek:type:`count` :zeek:attr:`&optional`
         Outermost VLAN tag if any (and Ethernet).

      inner_vlan: :zeek:type:`count` :zeek:attr:`&optional`
         Innermost VLAN tag if any (and Ethernet).

      eth_type: :zeek:type:`count` :zeek:attr:`&optional`
         Innermost Ethertype (if Ethernet).

      proto: :zeek:type:`layer3_proto`
         L3 protocol.

   Values extracted from the layer 2 header.
   
   .. zeek:see:: pkt_hdr

.. zeek:type:: load_sample_info

   :Type: :zeek:type:`set` [:zeek:type:`string`]


.. zeek:type:: mime_header_list

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`mime_header_rec`

   A list of MIME headers.
   
   .. zeek:see:: mime_header_rec http_all_headers mime_all_headers

.. zeek:type:: mime_header_rec

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         The header name.

      value: :zeek:type:`string`
         The header value.

   A MIME header key/value pair.
   
   .. zeek:see:: mime_header_list http_all_headers mime_all_headers mime_one_header

.. zeek:type:: mime_match

   :Type: :zeek:type:`record`

      strength: :zeek:type:`int`
         How strongly the signature matched.  Used for
         prioritization when multiple file magic signatures
         match.

      mime: :zeek:type:`string`
         The MIME type of the file magic signature match.

   A structure indicating a MIME type and strength of a match against
   file magic signatures.
   
   :zeek:see:`file_magic`

.. zeek:type:: mime_matches

   :Type: :zeek:type:`vector` of :zeek:type:`mime_match`

   A vector of file magic signature matches, ordered by strength of
   the signature, strongest first.
   
   :zeek:see:`file_magic`

.. zeek:type:: pcap_packet

   :Type: :zeek:type:`record`

      ts_sec: :zeek:type:`count`
         The non-fractional part of the packet's timestamp (i.e., full seconds since the epoch).

      ts_usec: :zeek:type:`count`
         The fractional part of the packet's timestamp.

      caplen: :zeek:type:`count`
         The number of bytes captured (<= *len*).

      len: :zeek:type:`count`
         The length of the packet in bytes, including link-level header.

      data: :zeek:type:`string`
         The payload of the packet, including link-level header.

      link_type: :zeek:type:`link_encap`
         Layer 2 link encapsulation type.

   Policy-level representation of a packet passed on by libpcap. The data
   includes the complete packet as returned by libpcap, including the link-layer
   header.
   
   .. zeek:see:: dump_packet get_current_packet

.. zeek:type:: pkt_hdr

   :Type: :zeek:type:`record`

      ip: :zeek:type:`ip4_hdr` :zeek:attr:`&optional`
         The IPv4 header if an IPv4 packet.

      ip6: :zeek:type:`ip6_hdr` :zeek:attr:`&optional`
         The IPv6 header if an IPv6 packet.

      tcp: :zeek:type:`tcp_hdr` :zeek:attr:`&optional`
         The TCP header if a TCP packet.

      udp: :zeek:type:`udp_hdr` :zeek:attr:`&optional`
         The UDP header if a UDP packet.

      icmp: :zeek:type:`icmp_hdr` :zeek:attr:`&optional`
         The ICMP header if an ICMP packet.

   A packet header, consisting of an IP header and transport-layer header.
   
   .. zeek:see:: new_packet

.. zeek:type:: pkt_profile_modes

   :Type: :zeek:type:`enum`

      .. zeek:enum:: PKT_PROFILE_MODE_NONE pkt_profile_modes

         No output.

      .. zeek:enum:: PKT_PROFILE_MODE_SECS pkt_profile_modes

         Output every :zeek:see:`pkt_profile_freq` seconds.

      .. zeek:enum:: PKT_PROFILE_MODE_PKTS pkt_profile_modes

         Output every :zeek:see:`pkt_profile_freq` packets.

      .. zeek:enum:: PKT_PROFILE_MODE_BYTES pkt_profile_modes

         Output every :zeek:see:`pkt_profile_freq` bytes.

   Output modes for packet profiling information.
   
   .. zeek:see:: pkt_profile_mode pkt_profile_freq pkt_profile_file

.. zeek:type:: pm_callit_request

   :Type: :zeek:type:`record`

      program: :zeek:type:`count`
         The RPC program.

      version: :zeek:type:`count`
         The program version.

      proc: :zeek:type:`count`
         The procedure being called.

      arg_size: :zeek:type:`count`
         The size of the argument.

   An RPC portmapper *callit* request.
   
   .. zeek:see:: pm_attempt_callit pm_request_callit

.. zeek:type:: pm_mapping

   :Type: :zeek:type:`record`

      program: :zeek:type:`count`
         The RPC program.

      version: :zeek:type:`count`
         The program version.

      p: :zeek:type:`port`
         The port.

   An RPC portmapper mapping.
   
   .. zeek:see:: pm_mappings

.. zeek:type:: pm_mappings

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`pm_mapping`

   Table of RPC portmapper mappings.
   
   .. zeek:see:: pm_request_dump

.. zeek:type:: pm_port_request

   :Type: :zeek:type:`record`

      program: :zeek:type:`count`
         The RPC program.

      version: :zeek:type:`count`
         The program version.

      is_tcp: :zeek:type:`bool`
         True if using TCP.

   An RPC portmapper request.
   
   .. zeek:see:: pm_attempt_getport pm_request_getport

.. zeek:type:: psk_identity_vec

   :Type: :zeek:type:`vector` of :zeek:type:`SSL::PSKIdentity`


.. zeek:type:: raw_pkt_hdr

   :Type: :zeek:type:`record`

      l2: :zeek:type:`l2_hdr`
         The layer 2 header.

      ip: :zeek:type:`ip4_hdr` :zeek:attr:`&optional`
         The IPv4 header if an IPv4 packet.

      ip6: :zeek:type:`ip6_hdr` :zeek:attr:`&optional`
         The IPv6 header if an IPv6 packet.

      tcp: :zeek:type:`tcp_hdr` :zeek:attr:`&optional`
         The TCP header if a TCP packet.

      udp: :zeek:type:`udp_hdr` :zeek:attr:`&optional`
         The UDP header if a UDP packet.

      icmp: :zeek:type:`icmp_hdr` :zeek:attr:`&optional`
         The ICMP header if an ICMP packet.

   A raw packet header, consisting of L2 header and everything in
   :zeek:see:`pkt_hdr`. .
   
   .. zeek:see:: raw_packet pkt_hdr

.. zeek:type:: record_field

   :Type: :zeek:type:`record`

      type_name: :zeek:type:`string`
         The name of the field's type.

      log: :zeek:type:`bool`
         True if the field is declared with :zeek:attr:`&log` attribute.

      value: :zeek:type:`any` :zeek:attr:`&optional`
         The current value of the field in the record instance passed into
         :zeek:see:`record_fields` (if it has one).

      default_val: :zeek:type:`any` :zeek:attr:`&optional`
         The value of the :zeek:attr:`&default` attribute if defined.

   Meta-information about a record field.
   
   .. zeek:see:: record_fields record_field_table

.. zeek:type:: record_field_table

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`record_field`

   Table type used to map record field declarations to meta-information
   describing them.
   
   .. zeek:see:: record_fields record_field
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: rotate_info

   :Type: :zeek:type:`record`

      old_name: :zeek:type:`string`
         Original filename.

      new_name: :zeek:type:`string`
         File name after rotation.

      open: :zeek:type:`time`
         Time when opened.

      close: :zeek:type:`time`
         Time when closed.

   .. zeek:see:: rotate_file rotate_file_by_name

.. zeek:type:: script_id

   :Type: :zeek:type:`record`

      type_name: :zeek:type:`string`
         The name of the identifier's type.

      exported: :zeek:type:`bool`
         True if the identifier is exported.

      constant: :zeek:type:`bool`
         True if the identifier is a constant.

      enum_constant: :zeek:type:`bool`
         True if the identifier is an enum value.

      option_value: :zeek:type:`bool`
         True if the identifier is an option.

      redefinable: :zeek:type:`bool`
         True if the identifier is declared with the :zeek:attr:`&redef` attribute.

      value: :zeek:type:`any` :zeek:attr:`&optional`
         The current value of the identifier.

   Meta-information about a script-level identifier.
   
   .. zeek:see:: global_ids id_table

.. zeek:type:: signature_and_hashalgorithm_vec

   :Type: :zeek:type:`vector` of :zeek:type:`SSL::SignatureAndHashAlgorithm`

   A vector of Signature and Hash Algorithms.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: signature_state

   :Type: :zeek:type:`record`

      sig_id: :zeek:type:`string`
         ID of the matching signature.

      conn: :zeek:type:`connection`
         Matching connection.

      is_orig: :zeek:type:`bool`
         True if matching endpoint is originator.

      payload_size: :zeek:type:`count`
         Payload size of the first matching packet of current endpoint.

   Description of a signature match.
   
   .. zeek:see:: signature_match

.. zeek:type:: string_array

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`

   An ordered array of strings. The entries are indexed by successive numbers.
   Note that it depends on the usage whether the first index is zero or one.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: string_set

   :Type: :zeek:type:`set` [:zeek:type:`string`]

   A set of strings.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: string_vec

   :Type: :zeek:type:`vector` of :zeek:type:`string`

   A vector of strings.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: subnet_vec

   :Type: :zeek:type:`vector` of :zeek:type:`subnet`

   A vector of subnets.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: sw_align

   :Type: :zeek:type:`record`

      str: :zeek:type:`string`
         String a substring is part of.

      index: :zeek:type:`count`
         Offset substring is located.

   Helper type for return value of Smith-Waterman algorithm.
   
   .. zeek:see:: str_smith_waterman sw_substring_vec sw_substring sw_align_vec sw_params

.. zeek:type:: sw_align_vec

   :Type: :zeek:type:`vector` of :zeek:type:`sw_align`

   Helper type for return value of Smith-Waterman algorithm.
   
   .. zeek:see:: str_smith_waterman sw_substring_vec sw_substring sw_align sw_params

.. zeek:type:: sw_params

   :Type: :zeek:type:`record`

      min_strlen: :zeek:type:`count` :zeek:attr:`&default` = ``3`` :zeek:attr:`&optional`
         Minimum size of a substring, minimum "granularity".

      sw_variant: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Smith-Waterman flavor to use.

   Parameters for the Smith-Waterman algorithm.
   
   .. zeek:see:: str_smith_waterman

.. zeek:type:: sw_substring

   :Type: :zeek:type:`record`

      str: :zeek:type:`string`
         A substring.

      aligns: :zeek:type:`sw_align_vec`
         All strings of which it's a substring.

      new: :zeek:type:`bool`
         True if start of new alignment.

   Helper type for return value of Smith-Waterman algorithm.
   
   .. zeek:see:: str_smith_waterman sw_substring_vec sw_align_vec sw_align sw_params
   

.. zeek:type:: sw_substring_vec

   :Type: :zeek:type:`vector` of :zeek:type:`sw_substring`

   Return type for Smith-Waterman algorithm.
   
   .. zeek:see:: str_smith_waterman sw_substring sw_align_vec sw_align sw_params
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: table_string_of_count

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`count`

   A table of counts indexed by strings.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: table_string_of_string

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`

   A table of strings indexed by strings.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: tcp_hdr

   :Type: :zeek:type:`record`

      sport: :zeek:type:`port`
         source port.

      dport: :zeek:type:`port`
         destination port

      seq: :zeek:type:`count`
         sequence number

      ack: :zeek:type:`count`
         acknowledgement number

      hl: :zeek:type:`count`
         header length (in bytes)

      dl: :zeek:type:`count`
         data length (xxx: not in original tcphdr!)

      flags: :zeek:type:`count`
         flags

      win: :zeek:type:`count`
         window

   Values extracted from a TCP header.
   
   .. zeek:see:: pkt_hdr discarder_check_tcp

.. zeek:type:: teredo_auth

   :Type: :zeek:type:`record`

      id: :zeek:type:`string`
         Teredo client identifier.

      value: :zeek:type:`string`
         HMAC-SHA1 over shared secret key between client and
         server, nonce, confirmation byte, origin indication
         (if present), and the IPv6 packet.

      nonce: :zeek:type:`count`
         Nonce chosen by Teredo client to be repeated by
         Teredo server.

      confirm: :zeek:type:`count`
         Confirmation byte to be set to 0 by Teredo client
         and non-zero by server if client needs new key.

   A Teredo origin indication header.  See :rfc:`4380` for more information
   about the Teredo protocol.
   
   .. zeek:see:: teredo_bubble teredo_origin_indication teredo_authentication
      teredo_hdr

.. zeek:type:: teredo_hdr

   :Type: :zeek:type:`record`

      auth: :zeek:type:`teredo_auth` :zeek:attr:`&optional`
         Teredo authentication header.

      origin: :zeek:type:`teredo_origin` :zeek:attr:`&optional`
         Teredo origin indication header.

      hdr: :zeek:type:`pkt_hdr`
         IPv6 and transport protocol headers.

   A Teredo packet header.  See :rfc:`4380` for more information about the
   Teredo protocol.
   
   .. zeek:see:: teredo_bubble teredo_origin_indication teredo_authentication

.. zeek:type:: teredo_origin

   :Type: :zeek:type:`record`

      p: :zeek:type:`port`
         Unobfuscated UDP port of Teredo client.

      a: :zeek:type:`addr`
         Unobfuscated IPv4 address of Teredo client.

   A Teredo authentication header.  See :rfc:`4380` for more information
   about the Teredo protocol.
   
   .. zeek:see:: teredo_bubble teredo_origin_indication teredo_authentication
      teredo_hdr

.. zeek:type:: transport_proto

   :Type: :zeek:type:`enum`

      .. zeek:enum:: unknown_transport transport_proto

         An unknown transport-layer protocol.

      .. zeek:enum:: tcp transport_proto

         TCP.

      .. zeek:enum:: udp transport_proto

         UDP.

      .. zeek:enum:: icmp transport_proto

         ICMP.

   A connection's transport-layer protocol. Note that Zeek uses the term
   "connection" broadly, using flow semantics for ICMP and UDP.

.. zeek:type:: udp_hdr

   :Type: :zeek:type:`record`

      sport: :zeek:type:`port`
         source port

      dport: :zeek:type:`port`
         destination port

      ulen: :zeek:type:`count`
         udp length

   Values extracted from a UDP header.
   
   .. zeek:see:: pkt_hdr discarder_check_udp

.. zeek:type:: var_sizes

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`count`

   Table type used to map variable names to their memory allocation.
   
   .. zeek:see:: global_sizes
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. zeek:type:: x509_opaque_vector

   :Type: :zeek:type:`vector` of :zeek:type:`opaque` of x509

   A vector of x509 opaques.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

Functions
#########
.. zeek:id:: add_interface

   :Type: :zeek:type:`function` (iold: :zeek:type:`string`, inew: :zeek:type:`string`) : :zeek:type:`string`

   Internal function.

.. zeek:id:: add_signature_file

   :Type: :zeek:type:`function` (sold: :zeek:type:`string`, snew: :zeek:type:`string`) : :zeek:type:`string`

   Internal function.

.. zeek:id:: discarder_check_icmp

   :Type: :zeek:type:`function` (p: :zeek:type:`pkt_hdr`) : :zeek:type:`bool`

   Function for skipping packets based on their ICMP header. If defined, this
   function will be called for all ICMP packets before Zeek performs any further
   analysis. If the function signals to discard a packet, no further processing
   will be performed on it.
   

   :p: The IP and ICMP headers of the considered packet.
   

   :returns: True if the packet should not be analyzed any further.
   
   .. zeek:see:: discarder_check_ip discarder_check_tcp discarder_check_udp
      discarder_maxlen
   
   .. note:: This is very low-level functionality and potentially expensive.
      Avoid using it.

.. zeek:id:: discarder_check_ip

   :Type: :zeek:type:`function` (p: :zeek:type:`pkt_hdr`) : :zeek:type:`bool`

   Function for skipping packets based on their IP header. If defined, this
   function will be called for all IP packets before Zeek performs any further
   analysis. If the function signals to discard a packet, no further processing
   will be performed on it.
   

   :p: The IP header of the considered packet.
   

   :returns: True if the packet should not be analyzed any further.
   
   .. zeek:see:: discarder_check_tcp discarder_check_udp discarder_check_icmp
      discarder_maxlen
   
   .. note:: This is very low-level functionality and potentially expensive.
      Avoid using it.

.. zeek:id:: discarder_check_tcp

   :Type: :zeek:type:`function` (p: :zeek:type:`pkt_hdr`, d: :zeek:type:`string`) : :zeek:type:`bool`

   Function for skipping packets based on their TCP header. If defined, this
   function will be called for all TCP packets before Zeek performs any further
   analysis. If the function signals to discard a packet, no further processing
   will be performed on it.
   

   :p: The IP and TCP headers of the considered packet.
   

   :d: Up to :zeek:see:`discarder_maxlen` bytes of the TCP payload.
   

   :returns: True if the packet should not be analyzed any further.
   
   .. zeek:see:: discarder_check_ip discarder_check_udp discarder_check_icmp
      discarder_maxlen
   
   .. note:: This is very low-level functionality and potentially expensive.
      Avoid using it.

.. zeek:id:: discarder_check_udp

   :Type: :zeek:type:`function` (p: :zeek:type:`pkt_hdr`, d: :zeek:type:`string`) : :zeek:type:`bool`

   Function for skipping packets based on their UDP header. If defined, this
   function will be called for all UDP packets before Zeek performs any further
   analysis. If the function signals to discard a packet, no further processing
   will be performed on it.
   

   :p: The IP and UDP headers of the considered packet.
   

   :d: Up to :zeek:see:`discarder_maxlen` bytes of the UDP payload.
   

   :returns: True if the packet should not be analyzed any further.
   
   .. zeek:see:: discarder_check_ip discarder_check_tcp discarder_check_icmp
      discarder_maxlen
   
   .. note:: This is very low-level functionality and potentially expensive.
      Avoid using it.

.. zeek:id:: max_count

   :Type: :zeek:type:`function` (a: :zeek:type:`count`, b: :zeek:type:`count`) : :zeek:type:`count`

   Returns maximum of two ``count`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The maximum of *a* and *b*.

.. zeek:id:: max_double

   :Type: :zeek:type:`function` (a: :zeek:type:`double`, b: :zeek:type:`double`) : :zeek:type:`double`

   Returns maximum of two ``double`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The maximum of *a* and *b*.

.. zeek:id:: max_interval

   :Type: :zeek:type:`function` (a: :zeek:type:`interval`, b: :zeek:type:`interval`) : :zeek:type:`interval`

   Returns maximum of two ``interval`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The maximum of *a* and *b*.

.. zeek:id:: min_count

   :Type: :zeek:type:`function` (a: :zeek:type:`count`, b: :zeek:type:`count`) : :zeek:type:`count`

   Returns minimum of two ``count`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The minimum of *a* and *b*.

.. zeek:id:: min_double

   :Type: :zeek:type:`function` (a: :zeek:type:`double`, b: :zeek:type:`double`) : :zeek:type:`double`

   Returns minimum of two ``double`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The minimum of *a* and *b*.

.. zeek:id:: min_interval

   :Type: :zeek:type:`function` (a: :zeek:type:`interval`, b: :zeek:type:`interval`) : :zeek:type:`interval`

   Returns minimum of two ``interval`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The minimum of *a* and *b*.


