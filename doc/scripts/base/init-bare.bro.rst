:tocdepth: 3

base/init-bare.bro
==================
.. bro:namespace:: Cluster
.. bro:namespace:: DCE_RPC
.. bro:namespace:: DHCP
.. bro:namespace:: GLOBAL
.. bro:namespace:: JSON
.. bro:namespace:: KRB
.. bro:namespace:: MOUNT3
.. bro:namespace:: NCP
.. bro:namespace:: NFS3
.. bro:namespace:: NTLM
.. bro:namespace:: PE
.. bro:namespace:: Pcap
.. bro:namespace:: RADIUS
.. bro:namespace:: RDP
.. bro:namespace:: Reporter
.. bro:namespace:: SMB
.. bro:namespace:: SMB1
.. bro:namespace:: SMB2
.. bro:namespace:: SNMP
.. bro:namespace:: SOCKS
.. bro:namespace:: SSH
.. bro:namespace:: SSL
.. bro:namespace:: Threading
.. bro:namespace:: Tunnel
.. bro:namespace:: Unified2
.. bro:namespace:: Weird
.. bro:namespace:: X509


:Namespaces: Cluster, DCE_RPC, DHCP, GLOBAL, JSON, KRB, MOUNT3, NCP, NFS3, NTLM, PE, Pcap, RADIUS, RDP, Reporter, SMB, SMB1, SMB2, SNMP, SOCKS, SSH, SSL, Threading, Tunnel, Unified2, Weird, X509
:Imports: :doc:`base/bif/bro.bif.bro </scripts/base/bif/bro.bif.bro>`, :doc:`base/bif/const.bif.bro </scripts/base/bif/const.bif.bro>`, :doc:`base/bif/event.bif.bro </scripts/base/bif/event.bif.bro>`, :doc:`base/bif/option.bif.bro </scripts/base/bif/option.bif.bro>`, :doc:`base/bif/plugins/Bro_KRB.types.bif.bro </scripts/base/bif/plugins/Bro_KRB.types.bif.bro>`, :doc:`base/bif/plugins/Bro_SNMP.types.bif.bro </scripts/base/bif/plugins/Bro_SNMP.types.bif.bro>`, :doc:`base/bif/reporter.bif.bro </scripts/base/bif/reporter.bif.bro>`, :doc:`base/bif/stats.bif.bro </scripts/base/bif/stats.bif.bro>`, :doc:`base/bif/strings.bif.bro </scripts/base/bif/strings.bif.bro>`, :doc:`base/bif/types.bif.bro </scripts/base/bif/types.bif.bro>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================ ======================================================================
:bro:id:`Weird::sampling_duration`: :bro:type:`interval` :bro:attr:`&redef`      How long a weird of a given type is allowed to keep state/counters in
                                                                                 memory.
:bro:id:`Weird::sampling_rate`: :bro:type:`count` :bro:attr:`&redef`             The rate-limiting sampling rate.
:bro:id:`Weird::sampling_threshold`: :bro:type:`count` :bro:attr:`&redef`        How many weirds of a given type to tolerate before sampling begins.
:bro:id:`Weird::sampling_whitelist`: :bro:type:`set` :bro:attr:`&redef`          Prevents rate-limiting sampling of any weirds named in the table.
:bro:id:`default_file_bof_buffer_size`: :bro:type:`count` :bro:attr:`&redef`     Default amount of bytes that file analysis will buffer in order to use
                                                                                 for mime type matching.
:bro:id:`default_file_timeout_interval`: :bro:type:`interval` :bro:attr:`&redef` Default amount of time a file can be inactive before the file analysis
                                                                                 gives up and discards any internal state related to the file.
================================================================================ ======================================================================

Redefinable Options
###################
======================================================================================= ================================================================================
:bro:id:`DCE_RPC::max_cmd_reassembly`: :bro:type:`count` :bro:attr:`&redef`             The maximum number of simultaneous fragmented commands that
                                                                                        the DCE_RPC analyzer will tolerate before the it will generate
                                                                                        a weird and skip further input.
:bro:id:`DCE_RPC::max_frag_data`: :bro:type:`count` :bro:attr:`&redef`                  The maximum number of fragmented bytes that the DCE_RPC analyzer
                                                                                        will tolerate on a command before the analyzer will generate a weird
                                                                                        and skip further input.
:bro:id:`KRB::keytab`: :bro:type:`string` :bro:attr:`&redef`                            Kerberos keytab file name.
:bro:id:`NCP::max_frame_size`: :bro:type:`count` :bro:attr:`&redef`                     The maximum number of bytes to allocate when parsing NCP frames.
:bro:id:`NFS3::return_data`: :bro:type:`bool` :bro:attr:`&redef`                        If true, :bro:see:`nfs_proc_read` and :bro:see:`nfs_proc_write`
                                                                                        events return the file data that has been read/written.
:bro:id:`NFS3::return_data_first_only`: :bro:type:`bool` :bro:attr:`&redef`             If :bro:id:`NFS3::return_data` is true, whether to *only* return data
                                                                                        if the read or write offset is 0, i.e., only return data for the
                                                                                        beginning of the file.
:bro:id:`NFS3::return_data_max`: :bro:type:`count` :bro:attr:`&redef`                   If :bro:id:`NFS3::return_data` is true, how much data should be
                                                                                        returned at most.
:bro:id:`Pcap::bufsize`: :bro:type:`count` :bro:attr:`&redef`                           Number of Mbytes to provide as buffer space when capturing from live
                                                                                        interfaces.
:bro:id:`Pcap::snaplen`: :bro:type:`count` :bro:attr:`&redef`                           Number of bytes per packet to capture from live interfaces.
:bro:id:`Reporter::errors_to_stderr`: :bro:type:`bool` :bro:attr:`&redef`               Tunable for sending reporter error messages to STDERR.
:bro:id:`Reporter::info_to_stderr`: :bro:type:`bool` :bro:attr:`&redef`                 Tunable for sending reporter info messages to STDERR.
:bro:id:`Reporter::warnings_to_stderr`: :bro:type:`bool` :bro:attr:`&redef`             Tunable for sending reporter warning messages to STDERR.
:bro:id:`SMB::pipe_filenames`: :bro:type:`set` :bro:attr:`&redef`                       A set of file names used as named pipes over SMB.
:bro:id:`Threading::heartbeat_interval`: :bro:type:`interval` :bro:attr:`&redef`        The heartbeat interval used by the threading framework.
:bro:id:`Tunnel::delay_gtp_confirmation`: :bro:type:`bool` :bro:attr:`&redef`           With this set, the GTP analyzer waits until the most-recent upflow
                                                                                        and downflow packets are a valid GTPv1 encapsulation before
                                                                                        issuing :bro:see:`protocol_confirmation`.
:bro:id:`Tunnel::delay_teredo_confirmation`: :bro:type:`bool` :bro:attr:`&redef`        With this set, the Teredo analyzer waits until it sees both sides
                                                                                        of a connection using a valid Teredo encapsulation before issuing
                                                                                        a :bro:see:`protocol_confirmation`.
:bro:id:`Tunnel::enable_ayiya`: :bro:type:`bool` :bro:attr:`&redef`                     Toggle whether to do IPv{4,6}-in-AYIYA decapsulation.
:bro:id:`Tunnel::enable_gre`: :bro:type:`bool` :bro:attr:`&redef`                       Toggle whether to do GRE decapsulation.
:bro:id:`Tunnel::enable_gtpv1`: :bro:type:`bool` :bro:attr:`&redef`                     Toggle whether to do GTPv1 decapsulation.
:bro:id:`Tunnel::enable_ip`: :bro:type:`bool` :bro:attr:`&redef`                        Toggle whether to do IPv{4,6}-in-IPv{4,6} decapsulation.
:bro:id:`Tunnel::enable_teredo`: :bro:type:`bool` :bro:attr:`&redef`                    Toggle whether to do IPv6-in-Teredo decapsulation.
:bro:id:`Tunnel::ip_tunnel_timeout`: :bro:type:`interval` :bro:attr:`&redef`            How often to cleanup internal state for inactive IP tunnels
                                                                                        (includes GRE tunnels).
:bro:id:`Tunnel::max_depth`: :bro:type:`count` :bro:attr:`&redef`                       The maximum depth of a tunnel to decapsulate until giving up.
:bro:id:`backdoor_stat_backoff`: :bro:type:`double` :bro:attr:`&redef`                  Deprecated.
:bro:id:`backdoor_stat_period`: :bro:type:`interval` :bro:attr:`&redef`                 Deprecated.
:bro:id:`bits_per_uid`: :bro:type:`count` :bro:attr:`&redef`                            Number of bits in UIDs that are generated to identify connections and
                                                                                        files.
:bro:id:`check_for_unused_event_handlers`: :bro:type:`bool` :bro:attr:`&redef`          If true, warns about unused event handlers at startup.
:bro:id:`chunked_io_buffer_soft_cap`: :bro:type:`count` :bro:attr:`&redef`              The number of IO chunks allowed to be buffered between the child
                                                                                        and parent process of remote communication before Bro starts dropping
                                                                                        connections to remote peers in an attempt to catch up.
:bro:id:`cmd_line_bpf_filter`: :bro:type:`string` :bro:attr:`&redef`                    BPF filter the user has set via the -f command line options.
:bro:id:`detect_filtered_trace`: :bro:type:`bool` :bro:attr:`&redef`                    Whether to attempt to automatically detect SYN/FIN/RST-filtered trace
                                                                                        and not report missing segments for such connections.
:bro:id:`dns_resolver`: :bro:type:`addr` :bro:attr:`&redef`                             The address of the DNS resolver to use.
:bro:id:`dns_session_timeout`: :bro:type:`interval` :bro:attr:`&redef`                  Time to wait before timing out a DNS request.
:bro:id:`dpd_buffer_size`: :bro:type:`count` :bro:attr:`&redef`                         Size of per-connection buffer used for dynamic protocol detection.
:bro:id:`dpd_ignore_ports`: :bro:type:`bool` :bro:attr:`&redef`                         If true, don't consider any ports for deciding which protocol analyzer to
                                                                                        use.
:bro:id:`dpd_match_only_beginning`: :bro:type:`bool` :bro:attr:`&redef`                 If true, stops signature matching if :bro:see:`dpd_buffer_size` has been
                                                                                        reached.
:bro:id:`dpd_reassemble_first_packets`: :bro:type:`bool` :bro:attr:`&redef`             Reassemble the beginning of all TCP connections before doing
                                                                                        signature matching.
:bro:id:`enable_syslog`: :bro:type:`bool` :bro:attr:`&redef`                            Deprecated.
:bro:id:`encap_hdr_size`: :bro:type:`count` :bro:attr:`&redef`                          If positive, indicates the encapsulation header size that should
                                                                                        be skipped.
:bro:id:`exit_only_after_terminate`: :bro:type:`bool` :bro:attr:`&redef`                Flag to prevent Bro from exiting automatically when input is exhausted.
:bro:id:`expensive_profiling_multiple`: :bro:type:`count` :bro:attr:`&redef`            Multiples of :bro:see:`profiling_interval` at which (more expensive) memory
                                                                                        profiling is done (0 disables).
:bro:id:`forward_remote_events`: :bro:type:`bool` :bro:attr:`&redef`                    If true, broadcast events received from one peer to all other peers.
:bro:id:`forward_remote_state_changes`: :bro:type:`bool` :bro:attr:`&redef`             If true, broadcast state updates received from one peer to all other peers.
:bro:id:`frag_timeout`: :bro:type:`interval` :bro:attr:`&redef`                         How long to hold onto fragments for possible reassembly.
:bro:id:`global_hash_seed`: :bro:type:`string` :bro:attr:`&redef`                       Seed for hashes computed internally for probabilistic data structures.
:bro:id:`icmp_inactivity_timeout`: :bro:type:`interval` :bro:attr:`&redef`              If an ICMP flow is inactive, time it out after this interval.
:bro:id:`ignore_checksums`: :bro:type:`bool` :bro:attr:`&redef`                         If true, don't verify checksums.
:bro:id:`ignore_keep_alive_rexmit`: :bro:type:`bool` :bro:attr:`&redef`                 Ignore certain TCP retransmissions for :bro:see:`conn_stats`.
:bro:id:`interconn_default_pkt_size`: :bro:type:`count` :bro:attr:`&redef`              Deprecated.
:bro:id:`interconn_max_interarrival`: :bro:type:`interval` :bro:attr:`&redef`           Deprecated.
:bro:id:`interconn_max_keystroke_pkt_size`: :bro:type:`count` :bro:attr:`&redef`        Deprecated.
:bro:id:`interconn_min_interarrival`: :bro:type:`interval` :bro:attr:`&redef`           Deprecated.
:bro:id:`interconn_stat_backoff`: :bro:type:`double` :bro:attr:`&redef`                 Deprecated.
:bro:id:`interconn_stat_period`: :bro:type:`interval` :bro:attr:`&redef`                Deprecated.
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef`                       Ports which the core considers being likely used by servers.
:bro:id:`log_encryption_key`: :bro:type:`string` :bro:attr:`&redef`                     Deprecated.
:bro:id:`log_max_size`: :bro:type:`double` :bro:attr:`&redef`                           Deprecated.
:bro:id:`log_rotate_base_time`: :bro:type:`string` :bro:attr:`&redef`                   Deprecated.
:bro:id:`log_rotate_interval`: :bro:type:`interval` :bro:attr:`&redef`                  Deprecated.
:bro:id:`max_files_in_cache`: :bro:type:`count` :bro:attr:`&redef`                      The maximum number of open files to keep cached at a given time.
:bro:id:`max_remote_events_processed`: :bro:type:`count` :bro:attr:`&redef`             With a similar trade-off, this gives the number of remote events
                                                                                        to process in a batch before interleaving other activity.
:bro:id:`max_timer_expires`: :bro:type:`count` :bro:attr:`&redef`                       The maximum number of timers to expire after processing each new
                                                                                        packet.
:bro:id:`mmdb_dir`: :bro:type:`string` :bro:attr:`&redef`                               The directory containing MaxMind DB (.mmdb) files to use for GeoIP support.
:bro:id:`non_analyzed_lifetime`: :bro:type:`interval` :bro:attr:`&redef`                If a connection belongs to an application that we don't analyze,
                                                                                        time it out after this interval.
:bro:id:`ntp_session_timeout`: :bro:type:`interval` :bro:attr:`&redef`                  Time to wait before timing out an NTP request.
:bro:id:`old_comm_usage_is_ok`: :bro:type:`bool` :bro:attr:`&redef`                     Whether usage of the old communication system is considered an error or
                                                                                        not.
:bro:id:`packet_filter_default`: :bro:type:`bool` :bro:attr:`&redef`                    Default mode for Bro's user-space dynamic packet filter.
:bro:id:`partial_connection_ok`: :bro:type:`bool` :bro:attr:`&redef`                    If true, instantiate connection state when a partial connection
                                                                                        (one missing its initial establishment negotiation) is seen.
:bro:id:`passive_fingerprint_file`: :bro:type:`string` :bro:attr:`&redef`               ``p0f`` fingerprint file to use.
:bro:id:`peer_description`: :bro:type:`string` :bro:attr:`&redef`                       Description transmitted to remote communication peers for identification.
:bro:id:`pkt_profile_freq`: :bro:type:`double` :bro:attr:`&redef`                       Frequency associated with packet profiling.
:bro:id:`pkt_profile_mode`: :bro:type:`pkt_profile_modes` :bro:attr:`&redef`            Output mode for packet profiling information.
:bro:id:`profiling_interval`: :bro:type:`interval` :bro:attr:`&redef`                   Update interval for profiling (0 disables).
:bro:id:`record_all_packets`: :bro:type:`bool` :bro:attr:`&redef`                       If a trace file is given with ``-w``, dump *all* packets seen by Bro into it.
:bro:id:`remote_check_sync_consistency`: :bro:type:`bool` :bro:attr:`&redef`            Whether for :bro:attr:`&synchronized` state to send the old value as a
                                                                                        consistency check.
:bro:id:`remote_trace_sync_interval`: :bro:type:`interval` :bro:attr:`&redef`           Synchronize trace processing at a regular basis in pseudo-realtime mode.
:bro:id:`remote_trace_sync_peers`: :bro:type:`count` :bro:attr:`&redef`                 Number of peers across which to synchronize trace processing in
                                                                                        pseudo-realtime mode.
:bro:id:`report_gaps_for_partial`: :bro:type:`bool` :bro:attr:`&redef`                  Whether we want :bro:see:`content_gap` for partial
                                                                                        connections.
:bro:id:`rpc_timeout`: :bro:type:`interval` :bro:attr:`&redef`                          Time to wait before timing out an RPC request.
:bro:id:`segment_profiling`: :bro:type:`bool` :bro:attr:`&redef`                        If true, then write segment profiling information (very high volume!)
                                                                                        in addition to profiling statistics.
:bro:id:`sig_max_group_size`: :bro:type:`count` :bro:attr:`&redef`                      Maximum size of regular expression groups for signature matching.
:bro:id:`skip_http_data`: :bro:type:`bool` :bro:attr:`&redef`                           Skip HTTP data for performance considerations.
:bro:id:`ssl_ca_certificate`: :bro:type:`string` :bro:attr:`&redef`                     The CA certificate file to authorize remote Bros/Broccolis.
:bro:id:`ssl_passphrase`: :bro:type:`string` :bro:attr:`&redef`                         The passphrase for our private key.
:bro:id:`ssl_private_key`: :bro:type:`string` :bro:attr:`&redef`                        File containing our private key and our certificate.
:bro:id:`state_dir`: :bro:type:`string` :bro:attr:`&redef`                              Specifies a directory for Bro to store its persistent state.
:bro:id:`state_write_delay`: :bro:type:`interval` :bro:attr:`&redef`                    Length of the delays inserted when storing state incrementally.
:bro:id:`stp_delta`: :bro:type:`interval` :bro:attr:`&redef`                            Internal to the stepping stone detector.
:bro:id:`stp_idle_min`: :bro:type:`interval` :bro:attr:`&redef`                         Internal to the stepping stone detector.
:bro:id:`suppress_local_output`: :bro:type:`bool` :bro:attr:`&redef`                    Deprecated.
:bro:id:`table_expire_delay`: :bro:type:`interval` :bro:attr:`&redef`                   When expiring table entries, wait this amount of time before checking the
                                                                                        next chunk of entries.
:bro:id:`table_expire_interval`: :bro:type:`interval` :bro:attr:`&redef`                Check for expired table entries after this amount of time.
:bro:id:`table_incremental_step`: :bro:type:`count` :bro:attr:`&redef`                  When expiring/serializing table entries, don't work on more than this many
                                                                                        table entries at a time.
:bro:id:`tcp_SYN_ack_ok`: :bro:type:`bool` :bro:attr:`&redef`                           If true, instantiate connection state when a SYN/ACK is seen but not the
                                                                                        initial SYN (even if :bro:see:`partial_connection_ok` is false).
:bro:id:`tcp_SYN_timeout`: :bro:type:`interval` :bro:attr:`&redef`                      Check up on the result of an initial SYN after this much time.
:bro:id:`tcp_attempt_delay`: :bro:type:`interval` :bro:attr:`&redef`                    Wait this long upon seeing an initial SYN before timing out the
                                                                                        connection attempt.
:bro:id:`tcp_close_delay`: :bro:type:`interval` :bro:attr:`&redef`                      Upon seeing a normal connection close, flush state after this much time.
:bro:id:`tcp_connection_linger`: :bro:type:`interval` :bro:attr:`&redef`                When checking a closed connection for further activity, consider it
                                                                                        inactive if there hasn't been any for this long.
:bro:id:`tcp_content_deliver_all_orig`: :bro:type:`bool` :bro:attr:`&redef`             If true, all TCP originator-side traffic is reported via
                                                                                        :bro:see:`tcp_contents`.
:bro:id:`tcp_content_deliver_all_resp`: :bro:type:`bool` :bro:attr:`&redef`             If true, all TCP responder-side traffic is reported via
                                                                                        :bro:see:`tcp_contents`.
:bro:id:`tcp_content_delivery_ports_orig`: :bro:type:`table` :bro:attr:`&redef`         Defines destination TCP ports for which the contents of the originator stream
                                                                                        should be delivered via :bro:see:`tcp_contents`.
:bro:id:`tcp_content_delivery_ports_resp`: :bro:type:`table` :bro:attr:`&redef`         Defines destination TCP ports for which the contents of the responder stream
                                                                                        should be delivered via :bro:see:`tcp_contents`.
:bro:id:`tcp_excessive_data_without_further_acks`: :bro:type:`count` :bro:attr:`&redef` If we've seen this much data without any of it being acked, we give up
                                                                                        on that connection to avoid memory exhaustion due to buffering all that
                                                                                        stuff.
:bro:id:`tcp_inactivity_timeout`: :bro:type:`interval` :bro:attr:`&redef`               If a TCP connection is inactive, time it out after this interval.
:bro:id:`tcp_match_undelivered`: :bro:type:`bool` :bro:attr:`&redef`                    If true, pass any undelivered to the signature engine before flushing the state.
:bro:id:`tcp_max_above_hole_without_any_acks`: :bro:type:`count` :bro:attr:`&redef`     If we're not seeing our peer's ACKs, the maximum volume of data above a
                                                                                        sequence hole that we'll tolerate before assuming that there's been a packet
                                                                                        drop and we should give up on tracking a connection.
:bro:id:`tcp_max_initial_window`: :bro:type:`count` :bro:attr:`&redef`                  Maximum amount of data that might plausibly be sent in an initial flight
                                                                                        (prior to receiving any acks).
:bro:id:`tcp_max_old_segments`: :bro:type:`count` :bro:attr:`&redef`                    Number of TCP segments to buffer beyond what's been acknowledged already
                                                                                        to detect retransmission inconsistencies.
:bro:id:`tcp_partial_close_delay`: :bro:type:`interval` :bro:attr:`&redef`              Generate a :bro:id:`connection_partial_close` event this much time after one
                                                                                        half of a partial connection closes, assuming there has been no subsequent
                                                                                        activity.
:bro:id:`tcp_reassembler_ports_orig`: :bro:type:`set` :bro:attr:`&redef`                For services without a handler, these sets define originator-side ports
                                                                                        that still trigger reassembly.
:bro:id:`tcp_reassembler_ports_resp`: :bro:type:`set` :bro:attr:`&redef`                For services without a handler, these sets define responder-side ports
                                                                                        that still trigger reassembly.
:bro:id:`tcp_reset_delay`: :bro:type:`interval` :bro:attr:`&redef`                      Upon seeing a RST, flush state after this much time.
:bro:id:`tcp_session_timer`: :bro:type:`interval` :bro:attr:`&redef`                    After a connection has closed, wait this long for further activity
                                                                                        before checking whether to time out its state.
:bro:id:`tcp_storm_interarrival_thresh`: :bro:type:`interval` :bro:attr:`&redef`        FINs/RSTs must come with this much time or less between them to be
                                                                                        considered a "storm".
:bro:id:`tcp_storm_thresh`: :bro:type:`count` :bro:attr:`&redef`                        Number of FINs/RSTs in a row that constitute a "storm".
:bro:id:`time_machine_profiling`: :bro:type:`bool` :bro:attr:`&redef`                   If true, output profiling for Time-Machine queries.
:bro:id:`timer_mgr_inactivity_timeout`: :bro:type:`interval` :bro:attr:`&redef`         Per-incident timer managers are drained after this amount of inactivity.
:bro:id:`truncate_http_URI`: :bro:type:`int` :bro:attr:`&redef`                         Maximum length of HTTP URIs passed to events.
:bro:id:`udp_content_deliver_all_orig`: :bro:type:`bool` :bro:attr:`&redef`             If true, all UDP originator-side traffic is reported via
                                                                                        :bro:see:`udp_contents`.
:bro:id:`udp_content_deliver_all_resp`: :bro:type:`bool` :bro:attr:`&redef`             If true, all UDP responder-side traffic is reported via
                                                                                        :bro:see:`udp_contents`.
:bro:id:`udp_content_delivery_ports_orig`: :bro:type:`table` :bro:attr:`&redef`         Defines UDP destination ports for which the contents of the originator stream
                                                                                        should be delivered via :bro:see:`udp_contents`.
:bro:id:`udp_content_delivery_ports_resp`: :bro:type:`table` :bro:attr:`&redef`         Defines UDP destination ports for which the contents of the responder stream
                                                                                        should be delivered via :bro:see:`udp_contents`.
:bro:id:`udp_inactivity_timeout`: :bro:type:`interval` :bro:attr:`&redef`               If a UDP flow is inactive, time it out after this interval.
:bro:id:`use_conn_size_analyzer`: :bro:type:`bool` :bro:attr:`&redef`                   Whether to use the ``ConnSize`` analyzer to count the number of packets and
                                                                                        IP-level bytes transferred by each endpoint.
:bro:id:`watchdog_interval`: :bro:type:`interval` :bro:attr:`&redef`                    Bro's watchdog interval.
======================================================================================= ================================================================================

Constants
#########
========================================================= =======================================================================
:bro:id:`CONTENTS_BOTH`: :bro:type:`count`                Record both originator and responder contents.
:bro:id:`CONTENTS_NONE`: :bro:type:`count`                Turn off recording of contents.
:bro:id:`CONTENTS_ORIG`: :bro:type:`count`                Record originator contents.
:bro:id:`CONTENTS_RESP`: :bro:type:`count`                Record responder contents.
:bro:id:`DNS_ADDL`: :bro:type:`count`                     An additional record.
:bro:id:`DNS_ANS`: :bro:type:`count`                      An answer record.
:bro:id:`DNS_AUTH`: :bro:type:`count`                     An authoritative record.
:bro:id:`DNS_QUERY`: :bro:type:`count`                    A query.
:bro:id:`ENDIAN_BIG`: :bro:type:`count`                   Big endian.
:bro:id:`ENDIAN_CONFUSED`: :bro:type:`count`              Tried to determine endian, but failed.
:bro:id:`ENDIAN_LITTLE`: :bro:type:`count`                Little endian.
:bro:id:`ENDIAN_UNKNOWN`: :bro:type:`count`               Endian not yet determined.
:bro:id:`ICMP_UNREACH_ADMIN_PROHIB`: :bro:type:`count`    Administratively prohibited.
:bro:id:`ICMP_UNREACH_HOST`: :bro:type:`count`            Host unreachable.
:bro:id:`ICMP_UNREACH_NEEDFRAG`: :bro:type:`count`        Fragment needed.
:bro:id:`ICMP_UNREACH_NET`: :bro:type:`count`             Network unreachable.
:bro:id:`ICMP_UNREACH_PORT`: :bro:type:`count`            Port unreachable.
:bro:id:`ICMP_UNREACH_PROTOCOL`: :bro:type:`count`        Protocol unreachable.
:bro:id:`IPPROTO_AH`: :bro:type:`count`                   IPv6 authentication header.
:bro:id:`IPPROTO_DSTOPTS`: :bro:type:`count`              IPv6 destination options header.
:bro:id:`IPPROTO_ESP`: :bro:type:`count`                  IPv6 encapsulating security payload header.
:bro:id:`IPPROTO_FRAGMENT`: :bro:type:`count`             IPv6 fragment header.
:bro:id:`IPPROTO_HOPOPTS`: :bro:type:`count`              IPv6 hop-by-hop-options header.
:bro:id:`IPPROTO_ICMP`: :bro:type:`count`                 Control message protocol.
:bro:id:`IPPROTO_ICMPV6`: :bro:type:`count`               ICMP for IPv6.
:bro:id:`IPPROTO_IGMP`: :bro:type:`count`                 Group management protocol.
:bro:id:`IPPROTO_IP`: :bro:type:`count`                   Dummy for IP.
:bro:id:`IPPROTO_IPIP`: :bro:type:`count`                 IP encapsulation in IP.
:bro:id:`IPPROTO_IPV6`: :bro:type:`count`                 IPv6 header.
:bro:id:`IPPROTO_MOBILITY`: :bro:type:`count`             IPv6 mobility header.
:bro:id:`IPPROTO_NONE`: :bro:type:`count`                 IPv6 no next header.
:bro:id:`IPPROTO_RAW`: :bro:type:`count`                  Raw IP packet.
:bro:id:`IPPROTO_ROUTING`: :bro:type:`count`              IPv6 routing header.
:bro:id:`IPPROTO_TCP`: :bro:type:`count`                  TCP.
:bro:id:`IPPROTO_UDP`: :bro:type:`count`                  User datagram protocol.
:bro:id:`LOGIN_STATE_AUTHENTICATE`: :bro:type:`count`     
:bro:id:`LOGIN_STATE_CONFUSED`: :bro:type:`count`         
:bro:id:`LOGIN_STATE_LOGGED_IN`: :bro:type:`count`        
:bro:id:`LOGIN_STATE_SKIP`: :bro:type:`count`             
:bro:id:`PEER_ID_NONE`: :bro:type:`count`                 Place-holder constant indicating "no peer".
:bro:id:`REMOTE_LOG_ERROR`: :bro:type:`count`             Deprecated.
:bro:id:`REMOTE_LOG_INFO`: :bro:type:`count`              Deprecated.
:bro:id:`REMOTE_SRC_CHILD`: :bro:type:`count`             Message from the child process.
:bro:id:`REMOTE_SRC_PARENT`: :bro:type:`count`            Message from the parent process.
:bro:id:`REMOTE_SRC_SCRIPT`: :bro:type:`count`            Message from a policy script.
:bro:id:`RPC_status`: :bro:type:`table`                   Mapping of numerical RPC status codes to readable messages.
:bro:id:`SNMP::OBJ_COUNTER32_TAG`: :bro:type:`count`      Unsigned 32-bit integer.
:bro:id:`SNMP::OBJ_COUNTER64_TAG`: :bro:type:`count`      Unsigned 64-bit integer.
:bro:id:`SNMP::OBJ_ENDOFMIBVIEW_TAG`: :bro:type:`count`   A NULL value.
:bro:id:`SNMP::OBJ_INTEGER_TAG`: :bro:type:`count`        Signed 64-bit integer.
:bro:id:`SNMP::OBJ_IPADDRESS_TAG`: :bro:type:`count`      An IP address.
:bro:id:`SNMP::OBJ_NOSUCHINSTANCE_TAG`: :bro:type:`count` A NULL value.
:bro:id:`SNMP::OBJ_NOSUCHOBJECT_TAG`: :bro:type:`count`   A NULL value.
:bro:id:`SNMP::OBJ_OCTETSTRING_TAG`: :bro:type:`count`    An octet string.
:bro:id:`SNMP::OBJ_OID_TAG`: :bro:type:`count`            An Object Identifier.
:bro:id:`SNMP::OBJ_OPAQUE_TAG`: :bro:type:`count`         An octet string.
:bro:id:`SNMP::OBJ_TIMETICKS_TAG`: :bro:type:`count`      Unsigned 32-bit integer.
:bro:id:`SNMP::OBJ_UNSIGNED32_TAG`: :bro:type:`count`     Unsigned 32-bit integer.
:bro:id:`SNMP::OBJ_UNSPECIFIED_TAG`: :bro:type:`count`    A NULL value.
:bro:id:`TCP_CLOSED`: :bro:type:`count`                   Endpoint has closed connection.
:bro:id:`TCP_ESTABLISHED`: :bro:type:`count`              Endpoint has finished initial handshake regularly.
:bro:id:`TCP_INACTIVE`: :bro:type:`count`                 Endpoint is still inactive.
:bro:id:`TCP_PARTIAL`: :bro:type:`count`                  Endpoint has sent data but no initial SYN.
:bro:id:`TCP_RESET`: :bro:type:`count`                    Endpoint has sent RST.
:bro:id:`TCP_SYN_ACK_SENT`: :bro:type:`count`             Endpoint has sent SYN/ACK.
:bro:id:`TCP_SYN_SENT`: :bro:type:`count`                 Endpoint has sent SYN.
:bro:id:`TH_ACK`: :bro:type:`count`                       ACK.
:bro:id:`TH_FIN`: :bro:type:`count`                       FIN.
:bro:id:`TH_FLAGS`: :bro:type:`count`                     Mask combining all flags.
:bro:id:`TH_PUSH`: :bro:type:`count`                      PUSH.
:bro:id:`TH_RST`: :bro:type:`count`                       RST.
:bro:id:`TH_SYN`: :bro:type:`count`                       SYN.
:bro:id:`TH_URG`: :bro:type:`count`                       URG.
:bro:id:`UDP_ACTIVE`: :bro:type:`count`                   Endpoint has sent something.
:bro:id:`UDP_INACTIVE`: :bro:type:`count`                 Endpoint is still inactive.
:bro:id:`trace_output_file`: :bro:type:`string`           Holds the filename of the trace file given with ``-w`` (empty if none).
========================================================= =======================================================================

State Variables
###############
====================================================================================================================== ============================================================================
:bro:id:`capture_filters`: :bro:type:`table` :bro:attr:`&redef`                                                        Set of BPF capture filters to use for capturing, indexed by a user-definable
                                                                                                                       ID (which must be unique).
:bro:id:`direct_login_prompts`: :bro:type:`set` :bro:attr:`&redef`                                                     TODO.
:bro:id:`discarder_maxlen`: :bro:type:`count` :bro:attr:`&redef`                                                       Maximum length of payload passed to discarder functions.
:bro:id:`dns_max_queries`: :bro:type:`count` :bro:attr:`&redef`                                                        If a DNS request includes more than this many queries, assume it's non-DNS
                                                                                                                       traffic and do not process it.
:bro:id:`dns_skip_addl`: :bro:type:`set` :bro:attr:`&redef`                                                            For DNS servers in these sets, omit processing the ADDL records they include
                                                                                                                       in their replies.
:bro:id:`dns_skip_all_addl`: :bro:type:`bool` :bro:attr:`&redef`                                                       If true, all DNS ADDL records are skipped.
:bro:id:`dns_skip_all_auth`: :bro:type:`bool` :bro:attr:`&redef`                                                       If true, all DNS AUTH records are skipped.
:bro:id:`dns_skip_auth`: :bro:type:`set` :bro:attr:`&redef`                                                            For DNS servers in these sets, omit processing the AUTH records they include
                                                                                                                       in their replies.
:bro:id:`done_with_network`: :bro:type:`bool`                                                                          
:bro:id:`generate_OS_version_event`: :bro:type:`set` :bro:attr:`&redef`                                                Defines for which subnets we should do passive fingerprinting.
:bro:id:`http_entity_data_delivery_size`: :bro:type:`count` :bro:attr:`&redef`                                         Maximum number of HTTP entity data delivered to events.
:bro:id:`interfaces`: :bro:type:`string` :bro:attr:`&add_func` = :bro:see:`add_interface` :bro:attr:`&redef`           Network interfaces to listen on.
:bro:id:`irc_servers`: :bro:type:`set` :bro:attr:`&redef`                                                              Deprecated.
:bro:id:`load_sample_freq`: :bro:type:`count` :bro:attr:`&redef`                                                       Rate at which to generate :bro:see:`load_sample` events.
:bro:id:`login_failure_msgs`: :bro:type:`set` :bro:attr:`&redef`                                                       TODO.
:bro:id:`login_non_failure_msgs`: :bro:type:`set` :bro:attr:`&redef`                                                   TODO.
:bro:id:`login_prompts`: :bro:type:`set` :bro:attr:`&redef`                                                            TODO.
:bro:id:`login_success_msgs`: :bro:type:`set` :bro:attr:`&redef`                                                       TODO.
:bro:id:`login_timeouts`: :bro:type:`set` :bro:attr:`&redef`                                                           TODO.
:bro:id:`mime_segment_length`: :bro:type:`count` :bro:attr:`&redef`                                                    The length of MIME data segments delivered to handlers of
                                                                                                                       :bro:see:`mime_segment_data`.
:bro:id:`mime_segment_overlap_length`: :bro:type:`count` :bro:attr:`&redef`                                            The number of bytes of overlap between successive segments passed to
                                                                                                                       :bro:see:`mime_segment_data`.
:bro:id:`pkt_profile_file`: :bro:type:`file` :bro:attr:`&redef`                                                        File where packet profiles are logged.
:bro:id:`profiling_file`: :bro:type:`file` :bro:attr:`&redef`                                                          Write profiling info into this file in regular intervals.
:bro:id:`restrict_filters`: :bro:type:`table` :bro:attr:`&redef`                                                       Set of BPF filters to restrict capturing, indexed by a user-definable ID
                                                                                                                       (which must be unique).
:bro:id:`secondary_filters`: :bro:type:`table` :bro:attr:`&redef`                                                      Definition of "secondary filters".
:bro:id:`signature_files`: :bro:type:`string` :bro:attr:`&add_func` = :bro:see:`add_signature_file` :bro:attr:`&redef` Signature files to read.
:bro:id:`skip_authentication`: :bro:type:`set` :bro:attr:`&redef`                                                      TODO.
:bro:id:`stp_skip_src`: :bro:type:`set` :bro:attr:`&redef`                                                             Internal to the stepping stone detector.
====================================================================================================================== ============================================================================

Types
#####
========================================================================== ==============================================================================================
:bro:type:`BrokerStats`: :bro:type:`record`                                Statistics about Broker communication.
:bro:type:`Cluster::Pool`: :bro:type:`record`                              A pool used for distributing data/work among a set of cluster nodes.
:bro:type:`ConnStats`: :bro:type:`record`                                  
:bro:type:`DHCP::Addrs`: :bro:type:`vector`                                A list of addresses offered by a DHCP server.
:bro:type:`DHCP::ClientFQDN`: :bro:type:`record`                           DHCP Client FQDN Option information (Option 81)
:bro:type:`DHCP::ClientID`: :bro:type:`record`                             DHCP Client Identifier (Option 61)
                                                                           ..
:bro:type:`DHCP::Msg`: :bro:type:`record`                                  A DHCP message.
:bro:type:`DHCP::Options`: :bro:type:`record`                              
:bro:type:`DHCP::SubOpt`: :bro:type:`record`                               DHCP Relay Agent Information Option (Option 82)
                                                                           ..
:bro:type:`DHCP::SubOpts`: :bro:type:`vector`                              
:bro:type:`DNSStats`: :bro:type:`record`                                   Statistics related to Bro's active use of DNS.
:bro:type:`EncapsulatingConnVector`: :bro:type:`vector`                    A type alias for a vector of encapsulating "connections", i.e.
:bro:type:`EventStats`: :bro:type:`record`                                 
:bro:type:`FileAnalysisStats`: :bro:type:`record`                          Statistics of file analysis.
:bro:type:`GapStats`: :bro:type:`record`                                   Statistics about number of gaps in TCP connections.
:bro:type:`IPAddrAnonymization`: :bro:type:`enum`                          Deprecated.
:bro:type:`IPAddrAnonymizationClass`: :bro:type:`enum`                     Deprecated.
:bro:type:`JSON::TimestampFormat`: :bro:type:`enum`                        
:bro:type:`KRB::AP_Options`: :bro:type:`record`                            AP Options.
:bro:type:`KRB::Error_Msg`: :bro:type:`record`                             The data from the ERROR_MSG message.
:bro:type:`KRB::Host_Address`: :bro:type:`record`                          A Kerberos host address See :rfc:`4120`.
:bro:type:`KRB::Host_Address_Vector`: :bro:type:`vector`                   
:bro:type:`KRB::KDC_Options`: :bro:type:`record`                           KDC Options.
:bro:type:`KRB::KDC_Request`: :bro:type:`record`                           The data from the AS_REQ and TGS_REQ messages.
:bro:type:`KRB::KDC_Response`: :bro:type:`record`                          The data from the AS_REQ and TGS_REQ messages.
:bro:type:`KRB::SAFE_Msg`: :bro:type:`record`                              The data from the SAFE message.
:bro:type:`KRB::Ticket`: :bro:type:`record`                                A Kerberos ticket.
:bro:type:`KRB::Ticket_Vector`: :bro:type:`vector`                         
:bro:type:`KRB::Type_Value`: :bro:type:`record`                            Used in a few places in the Kerberos analyzer for elements
                                                                           that have a type and a string value.
:bro:type:`KRB::Type_Value_Vector`: :bro:type:`vector`                     
:bro:type:`MOUNT3::dirmntargs_t`: :bro:type:`record`                       MOUNT *mnt* arguments.
:bro:type:`MOUNT3::info_t`: :bro:type:`record`                             Record summarizing the general results and status of MOUNT3
                                                                           request/reply pairs.
:bro:type:`MOUNT3::mnt_reply_t`: :bro:type:`record`                        MOUNT lookup reply.
:bro:type:`MatcherStats`: :bro:type:`record`                               Statistics of all regular expression matchers.
:bro:type:`ModbusCoils`: :bro:type:`vector`                                A vector of boolean values that indicate the setting
                                                                           for a range of modbus coils.
:bro:type:`ModbusHeaders`: :bro:type:`record`                              
:bro:type:`ModbusRegisters`: :bro:type:`vector`                            A vector of count values that represent 16bit modbus 
                                                                           register values.
:bro:type:`NFS3::delobj_reply_t`: :bro:type:`record`                       NFS reply for *remove*, *rmdir*.
:bro:type:`NFS3::direntry_t`: :bro:type:`record`                           NFS *direntry*.
:bro:type:`NFS3::direntry_vec_t`: :bro:type:`vector`                       Vector of NFS *direntry*.
:bro:type:`NFS3::diropargs_t`: :bro:type:`record`                          NFS *readdir* arguments.
:bro:type:`NFS3::fattr_t`: :bro:type:`record`                              NFS file attributes.
:bro:type:`NFS3::fsstat_t`: :bro:type:`record`                             NFS *fsstat*.
:bro:type:`NFS3::info_t`: :bro:type:`record`                               Record summarizing the general results and status of NFSv3
                                                                           request/reply pairs.
:bro:type:`NFS3::link_reply_t`: :bro:type:`record`                         NFS *link* reply.
:bro:type:`NFS3::linkargs_t`: :bro:type:`record`                           NFS *link* arguments.
:bro:type:`NFS3::lookup_reply_t`: :bro:type:`record`                       NFS lookup reply.
:bro:type:`NFS3::newobj_reply_t`: :bro:type:`record`                       NFS reply for *create*, *mkdir*, and *symlink*.
:bro:type:`NFS3::read_reply_t`: :bro:type:`record`                         NFS *read* reply.
:bro:type:`NFS3::readargs_t`: :bro:type:`record`                           NFS *read* arguments.
:bro:type:`NFS3::readdir_reply_t`: :bro:type:`record`                      NFS *readdir* reply.
:bro:type:`NFS3::readdirargs_t`: :bro:type:`record`                        NFS *readdir* arguments.
:bro:type:`NFS3::readlink_reply_t`: :bro:type:`record`                     NFS *readline* reply.
:bro:type:`NFS3::renameobj_reply_t`: :bro:type:`record`                    NFS reply for *rename*.
:bro:type:`NFS3::renameopargs_t`: :bro:type:`record`                       NFS *rename* arguments.
:bro:type:`NFS3::sattr_reply_t`: :bro:type:`record`                        NFS *sattr* reply.
:bro:type:`NFS3::sattr_t`: :bro:type:`record`                              NFS file attributes.
:bro:type:`NFS3::sattrargs_t`: :bro:type:`record`                          NFS *sattr* arguments.
:bro:type:`NFS3::symlinkargs_t`: :bro:type:`record`                        NFS *symlink* arguments.
:bro:type:`NFS3::symlinkdata_t`: :bro:type:`record`                        NFS symlinkdata attributes.
:bro:type:`NFS3::wcc_attr_t`: :bro:type:`record`                           NFS *wcc* attributes.
:bro:type:`NFS3::write_reply_t`: :bro:type:`record`                        NFS *write* reply.
:bro:type:`NFS3::writeargs_t`: :bro:type:`record`                          NFS *write* arguments.
:bro:type:`NTLM::AVs`: :bro:type:`record`                                  
:bro:type:`NTLM::Authenticate`: :bro:type:`record`                         
:bro:type:`NTLM::Challenge`: :bro:type:`record`                            
:bro:type:`NTLM::Negotiate`: :bro:type:`record`                            
:bro:type:`NTLM::NegotiateFlags`: :bro:type:`record`                       
:bro:type:`NTLM::Version`: :bro:type:`record`                              
:bro:type:`NetStats`: :bro:type:`record`                                   Packet capture statistics.
:bro:type:`OS_version`: :bro:type:`record`                                 Passive fingerprinting match.
:bro:type:`OS_version_inference`: :bro:type:`enum`                         Quality of passive fingerprinting matches.
:bro:type:`PE::DOSHeader`: :bro:type:`record`                              
:bro:type:`PE::FileHeader`: :bro:type:`record`                             
:bro:type:`PE::OptionalHeader`: :bro:type:`record`                         
:bro:type:`PE::SectionHeader`: :bro:type:`record`                          Record for Portable Executable (PE) section headers.
:bro:type:`PcapFilterID`: :bro:type:`enum`                                 Enum type identifying dynamic BPF filters.
:bro:type:`ProcStats`: :bro:type:`record`                                  Statistics about Bro's process.
:bro:type:`RADIUS::AttributeList`: :bro:type:`vector`                      
:bro:type:`RADIUS::Attributes`: :bro:type:`table`                          
:bro:type:`RADIUS::Message`: :bro:type:`record`                            
:bro:type:`RDP::ClientCoreData`: :bro:type:`record`                        
:bro:type:`RDP::EarlyCapabilityFlags`: :bro:type:`record`                  
:bro:type:`ReassemblerStats`: :bro:type:`record`                           Holds statistics for all types of reassembly.
:bro:type:`ReporterStats`: :bro:type:`record`                              Statistics about reporter messages and weirds.
:bro:type:`SMB1::Find_First2_Request_Args`: :bro:type:`record`             
:bro:type:`SMB1::Find_First2_Response_Args`: :bro:type:`record`            
:bro:type:`SMB1::Header`: :bro:type:`record`                               An SMB1 header.
:bro:type:`SMB1::NegotiateCapabilities`: :bro:type:`record`                
:bro:type:`SMB1::NegotiateRawMode`: :bro:type:`record`                     
:bro:type:`SMB1::NegotiateResponse`: :bro:type:`record`                    
:bro:type:`SMB1::NegotiateResponseCore`: :bro:type:`record`                
:bro:type:`SMB1::NegotiateResponseLANMAN`: :bro:type:`record`              
:bro:type:`SMB1::NegotiateResponseNTLM`: :bro:type:`record`                
:bro:type:`SMB1::NegotiateResponseSecurity`: :bro:type:`record`            
:bro:type:`SMB1::SessionSetupAndXCapabilities`: :bro:type:`record`         
:bro:type:`SMB1::SessionSetupAndXRequest`: :bro:type:`record`              
:bro:type:`SMB1::SessionSetupAndXResponse`: :bro:type:`record`             
:bro:type:`SMB1::Trans2_Args`: :bro:type:`record`                          
:bro:type:`SMB1::Trans2_Sec_Args`: :bro:type:`record`                      
:bro:type:`SMB1::Trans_Sec_Args`: :bro:type:`record`                       
:bro:type:`SMB2::CloseResponse`: :bro:type:`record`                        The response to an SMB2 *close* request, which is used by the client to close an instance
                                                                           of a file that was opened previously.
:bro:type:`SMB2::CreateRequest`: :bro:type:`record`                        The request sent by the client to request either creation of or access to a file.
:bro:type:`SMB2::CreateResponse`: :bro:type:`record`                       The response to an SMB2 *create_request* request, which is sent by the client to request
                                                                           either creation of or access to a file.
:bro:type:`SMB2::FileAttrs`: :bro:type:`record`                            A series of boolean flags describing basic and extended file attributes for SMB2.
:bro:type:`SMB2::GUID`: :bro:type:`record`                                 An SMB2 globally unique identifier which identifies a file.
:bro:type:`SMB2::Header`: :bro:type:`record`                               An SMB2 header.
:bro:type:`SMB2::NegotiateResponse`: :bro:type:`record`                    The response to an SMB2 *negotiate* request, which is used by tghe client to notify the server
                                                                           what dialects of the SMB2 protocol the client understands.
:bro:type:`SMB2::SessionSetupFlags`: :bro:type:`record`                    A flags field that indicates additional information about the session that's sent in the
                                                                           *session_setup* response.
:bro:type:`SMB2::SessionSetupRequest`: :bro:type:`record`                  The request sent by the client to request a new authenticated session
                                                                           within a new or existing SMB 2 Protocol transport connection to the server.
:bro:type:`SMB2::SessionSetupResponse`: :bro:type:`record`                 The response to an SMB2 *session_setup* request, which is sent by the client to request a
                                                                           new authenticated session within a new or existing SMB 2 Protocol transport connection
                                                                           to the server.
:bro:type:`SMB2::TreeConnectResponse`: :bro:type:`record`                  The response to an SMB2 *tree_connect* request, which is sent by the client to request
                                                                           access to a particular share on the server.
:bro:type:`SMB::MACTimes`: :bro:type:`record` :bro:attr:`&log`             MAC times for a file.
:bro:type:`SNMP::Binding`: :bro:type:`record`                              The ``VarBind`` data structure from either :rfc:`1157` or
                                                                           :rfc:`3416`, which maps an Object Identifier to a value.
:bro:type:`SNMP::Bindings`: :bro:type:`vector`                             A ``VarBindList`` data structure from either :rfc:`1157` or :rfc:`3416`.
:bro:type:`SNMP::BulkPDU`: :bro:type:`record`                              A ``BulkPDU`` data structure from :rfc:`3416`.
:bro:type:`SNMP::Header`: :bro:type:`record`                               A generic SNMP header data structure that may include data from
                                                                           any version of SNMP.
:bro:type:`SNMP::HeaderV1`: :bro:type:`record`                             The top-level message data structure of an SNMPv1 datagram, not
                                                                           including the PDU data.
:bro:type:`SNMP::HeaderV2`: :bro:type:`record`                             The top-level message data structure of an SNMPv2 datagram, not
                                                                           including the PDU data.
:bro:type:`SNMP::HeaderV3`: :bro:type:`record`                             The top-level message data structure of an SNMPv3 datagram, not
                                                                           including the PDU data.
:bro:type:`SNMP::ObjectValue`: :bro:type:`record`                          A generic SNMP object value, that may include any of the
                                                                           valid ``ObjectSyntax`` values from :rfc:`1155` or :rfc:`3416`.
:bro:type:`SNMP::PDU`: :bro:type:`record`                                  A ``PDU`` data structure from either :rfc:`1157` or :rfc:`3416`.
:bro:type:`SNMP::ScopedPDU_Context`: :bro:type:`record`                    The ``ScopedPduData`` data structure of an SNMPv3 datagram, not
                                                                           including the PDU data (i.e.
:bro:type:`SNMP::TrapPDU`: :bro:type:`record`                              A ``Trap-PDU`` data structure from :rfc:`1157`.
:bro:type:`SOCKS::Address`: :bro:type:`record` :bro:attr:`&log`            This record is for a SOCKS client or server to provide either a
                                                                           name or an address to represent a desired or established connection.
:bro:type:`SSH::Algorithm_Prefs`: :bro:type:`record`                       The client and server each have some preferences for the algorithms used
                                                                           in each direction.
:bro:type:`SSH::Capabilities`: :bro:type:`record`                          This record lists the preferences of an SSH endpoint for
                                                                           algorithm selection.
:bro:type:`SSL::SignatureAndHashAlgorithm`: :bro:type:`record`             
:bro:type:`SYN_packet`: :bro:type:`record`                                 Fields of a SYN packet.
:bro:type:`ThreadStats`: :bro:type:`record`                                Statistics about threads.
:bro:type:`TimerStats`: :bro:type:`record`                                 Statistics of timers.
:bro:type:`Tunnel::EncapsulatingConn`: :bro:type:`record` :bro:attr:`&log` Records the identity of an encapsulating parent of a tunneled connection.
:bro:type:`Unified2::IDSEvent`: :bro:type:`record`                         
:bro:type:`Unified2::Packet`: :bro:type:`record`                           
:bro:type:`X509::BasicConstraints`: :bro:type:`record` :bro:attr:`&log`    
:bro:type:`X509::Certificate`: :bro:type:`record`                          
:bro:type:`X509::Extension`: :bro:type:`record`                            
:bro:type:`X509::Result`: :bro:type:`record`                               Result of an X509 certificate chain verification
:bro:type:`X509::SubjectAlternativeName`: :bro:type:`record`               
:bro:type:`addr_set`: :bro:type:`set`                                      A set of addresses.
:bro:type:`addr_vec`: :bro:type:`vector`                                   A vector of addresses.
:bro:type:`any_vec`: :bro:type:`vector`                                    A vector of any, used by some builtin functions to store a list of varying
                                                                           types.
:bro:type:`backdoor_endp_stats`: :bro:type:`record`                        Deprecated.
:bro:type:`bittorrent_benc_dir`: :bro:type:`table`                         A table of BitTorrent "benc" values.
:bro:type:`bittorrent_benc_value`: :bro:type:`record`                      BitTorrent "benc" value.
:bro:type:`bittorrent_peer`: :bro:type:`record`                            A BitTorrent peer.
:bro:type:`bittorrent_peer_set`: :bro:type:`set`                           A set of BitTorrent peers.
:bro:type:`bt_tracker_headers`: :bro:type:`table`                          Header table type used by BitTorrent analyzer.
:bro:type:`call_argument`: :bro:type:`record`                              Meta-information about a parameter to a function/event.
:bro:type:`call_argument_vector`: :bro:type:`vector`                       Vector type used to capture parameters of a function/event call.
:bro:type:`conn_id`: :bro:type:`record` :bro:attr:`&log`                   A connection's identifying 4-tuple of endpoints and ports.
:bro:type:`connection`: :bro:type:`record`                                 A connection.
:bro:type:`count_set`: :bro:type:`set`                                     A set of counts.
:bro:type:`dns_answer`: :bro:type:`record`                                 The general part of a DNS reply.
:bro:type:`dns_dnskey_rr`: :bro:type:`record`                              A DNSSEC DNSKEY record.
:bro:type:`dns_ds_rr`: :bro:type:`record`                                  A DNSSEC DS record.
:bro:type:`dns_edns_additional`: :bro:type:`record`                        An additional DNS EDNS record.
:bro:type:`dns_mapping`: :bro:type:`record`                                
:bro:type:`dns_msg`: :bro:type:`record`                                    A DNS message.
:bro:type:`dns_nsec3_rr`: :bro:type:`record`                               A DNSSEC NSEC3 record.
:bro:type:`dns_rrsig_rr`: :bro:type:`record`                               A DNSSEC RRSIG record.
:bro:type:`dns_soa`: :bro:type:`record`                                    A DNS SOA record.
:bro:type:`dns_tsig_additional`: :bro:type:`record`                        An additional DNS TSIG record.
:bro:type:`endpoint`: :bro:type:`record`                                   Statistics about a :bro:type:`connection` endpoint.
:bro:type:`endpoint_stats`: :bro:type:`record`                             Statistics about what a TCP endpoint sent.
:bro:type:`entropy_test_result`: :bro:type:`record`                        Computed entropy values.
:bro:type:`event_peer`: :bro:type:`record`                                 A communication peer.
:bro:type:`fa_file`: :bro:type:`record` :bro:attr:`&redef`                 A file that Bro is analyzing.
:bro:type:`fa_metadata`: :bro:type:`record`                                Metadata that's been inferred about a particular file.
:bro:type:`files_tag_set`: :bro:type:`set`                                 A set of file analyzer tags.
:bro:type:`flow_id`: :bro:type:`record` :bro:attr:`&log`                   The identifying 4-tuple of a uni-directional flow.
:bro:type:`ftp_port`: :bro:type:`record`                                   A parsed host/port combination describing server endpoint for an upcoming
                                                                           data transfer.
:bro:type:`geo_location`: :bro:type:`record` :bro:attr:`&log`              GeoIP location information.
:bro:type:`gtp_access_point_name`: :bro:type:`string`                      
:bro:type:`gtp_cause`: :bro:type:`count`                                   
:bro:type:`gtp_charging_characteristics`: :bro:type:`count`                
:bro:type:`gtp_charging_gateway_addr`: :bro:type:`addr`                    
:bro:type:`gtp_charging_id`: :bro:type:`count`                             
:bro:type:`gtp_create_pdp_ctx_request_elements`: :bro:type:`record`        
:bro:type:`gtp_create_pdp_ctx_response_elements`: :bro:type:`record`       
:bro:type:`gtp_delete_pdp_ctx_request_elements`: :bro:type:`record`        
:bro:type:`gtp_delete_pdp_ctx_response_elements`: :bro:type:`record`       
:bro:type:`gtp_end_user_addr`: :bro:type:`record`                          
:bro:type:`gtp_gsn_addr`: :bro:type:`record`                               
:bro:type:`gtp_imsi`: :bro:type:`count`                                    
:bro:type:`gtp_msisdn`: :bro:type:`string`                                 
:bro:type:`gtp_nsapi`: :bro:type:`count`                                   
:bro:type:`gtp_omc_id`: :bro:type:`string`                                 
:bro:type:`gtp_private_extension`: :bro:type:`record`                      
:bro:type:`gtp_proto_config_options`: :bro:type:`string`                   
:bro:type:`gtp_qos_profile`: :bro:type:`record`                            
:bro:type:`gtp_rai`: :bro:type:`record`                                    
:bro:type:`gtp_recovery`: :bro:type:`count`                                
:bro:type:`gtp_reordering_required`: :bro:type:`bool`                      
:bro:type:`gtp_selection_mode`: :bro:type:`count`                          
:bro:type:`gtp_teardown_ind`: :bro:type:`bool`                             
:bro:type:`gtp_teid1`: :bro:type:`count`                                   
:bro:type:`gtp_teid_control_plane`: :bro:type:`count`                      
:bro:type:`gtp_tft`: :bro:type:`string`                                    
:bro:type:`gtp_trace_reference`: :bro:type:`count`                         
:bro:type:`gtp_trace_type`: :bro:type:`count`                              
:bro:type:`gtp_trigger_id`: :bro:type:`string`                             
:bro:type:`gtp_update_pdp_ctx_request_elements`: :bro:type:`record`        
:bro:type:`gtp_update_pdp_ctx_response_elements`: :bro:type:`record`       
:bro:type:`gtpv1_hdr`: :bro:type:`record`                                  A GTPv1 (GPRS Tunneling Protocol) header.
:bro:type:`http_message_stat`: :bro:type:`record`                          HTTP message statistics.
:bro:type:`http_stats_rec`: :bro:type:`record`                             HTTP session statistics.
:bro:type:`icmp6_nd_option`: :bro:type:`record`                            Options extracted from ICMPv6 neighbor discovery messages as specified
                                                                           by :rfc:`4861`.
:bro:type:`icmp6_nd_options`: :bro:type:`vector`                           A type alias for a vector of ICMPv6 neighbor discovery message options.
:bro:type:`icmp6_nd_prefix_info`: :bro:type:`record`                       Values extracted from a Prefix Information option in an ICMPv6 neighbor
                                                                           discovery message as specified by :rfc:`4861`.
:bro:type:`icmp_conn`: :bro:type:`record`                                  Specifics about an ICMP conversation.
:bro:type:`icmp_context`: :bro:type:`record`                               Packet context part of an ICMP message.
:bro:type:`icmp_hdr`: :bro:type:`record`                                   Values extracted from an ICMP header.
:bro:type:`id_table`: :bro:type:`table`                                    Table type used to map script-level identifiers to meta-information
                                                                           describing them.
:bro:type:`index_vec`: :bro:type:`vector`                                  A vector of counts, used by some builtin functions to store a list of indices.
:bro:type:`interconn_endp_stats`: :bro:type:`record`                       Deprecated.
:bro:type:`ip4_hdr`: :bro:type:`record`                                    Values extracted from an IPv4 header.
:bro:type:`ip6_ah`: :bro:type:`record`                                     Values extracted from an IPv6 Authentication extension header.
:bro:type:`ip6_dstopts`: :bro:type:`record`                                Values extracted from an IPv6 Destination options extension header.
:bro:type:`ip6_esp`: :bro:type:`record`                                    Values extracted from an IPv6 ESP extension header.
:bro:type:`ip6_ext_hdr`: :bro:type:`record`                                A general container for a more specific IPv6 extension header.
:bro:type:`ip6_ext_hdr_chain`: :bro:type:`vector`                          A type alias for a vector of IPv6 extension headers.
:bro:type:`ip6_fragment`: :bro:type:`record`                               Values extracted from an IPv6 Fragment extension header.
:bro:type:`ip6_hdr`: :bro:type:`record`                                    Values extracted from an IPv6 header.
:bro:type:`ip6_hopopts`: :bro:type:`record`                                Values extracted from an IPv6 Hop-by-Hop options extension header.
:bro:type:`ip6_mobility_back`: :bro:type:`record`                          Values extracted from an IPv6 Mobility Binding Acknowledgement message.
:bro:type:`ip6_mobility_be`: :bro:type:`record`                            Values extracted from an IPv6 Mobility Binding Error message.
:bro:type:`ip6_mobility_brr`: :bro:type:`record`                           Values extracted from an IPv6 Mobility Binding Refresh Request message.
:bro:type:`ip6_mobility_bu`: :bro:type:`record`                            Values extracted from an IPv6 Mobility Binding Update message.
:bro:type:`ip6_mobility_cot`: :bro:type:`record`                           Values extracted from an IPv6 Mobility Care-of Test message.
:bro:type:`ip6_mobility_coti`: :bro:type:`record`                          Values extracted from an IPv6 Mobility Care-of Test Init message.
:bro:type:`ip6_mobility_hdr`: :bro:type:`record`                           Values extracted from an IPv6 Mobility header.
:bro:type:`ip6_mobility_hot`: :bro:type:`record`                           Values extracted from an IPv6 Mobility Home Test message.
:bro:type:`ip6_mobility_hoti`: :bro:type:`record`                          Values extracted from an IPv6 Mobility Home Test Init message.
:bro:type:`ip6_mobility_msg`: :bro:type:`record`                           Values extracted from an IPv6 Mobility header's message data.
:bro:type:`ip6_option`: :bro:type:`record`                                 Values extracted from an IPv6 extension header's (e.g.
:bro:type:`ip6_options`: :bro:type:`vector`                                A type alias for a vector of IPv6 options.
:bro:type:`ip6_routing`: :bro:type:`record`                                Values extracted from an IPv6 Routing extension header.
:bro:type:`irc_join_info`: :bro:type:`record`                              IRC join information.
:bro:type:`irc_join_list`: :bro:type:`set`                                 Set of IRC join information.
:bro:type:`l2_hdr`: :bro:type:`record`                                     Values extracted from the layer 2 header.
:bro:type:`load_sample_info`: :bro:type:`set`                              
:bro:type:`mime_header_list`: :bro:type:`table`                            A list of MIME headers.
:bro:type:`mime_header_rec`: :bro:type:`record`                            A MIME header key/value pair.
:bro:type:`mime_match`: :bro:type:`record`                                 A structure indicating a MIME type and strength of a match against
                                                                           file magic signatures.
:bro:type:`mime_matches`: :bro:type:`vector`                               A vector of file magic signature matches, ordered by strength of
                                                                           the signature, strongest first.
:bro:type:`ntp_msg`: :bro:type:`record`                                    An NTP message.
:bro:type:`packet`: :bro:type:`record`                                     Deprecated.
:bro:type:`pcap_packet`: :bro:type:`record`                                Policy-level representation of a packet passed on by libpcap.
:bro:type:`peer_id`: :bro:type:`count`                                     A locally unique ID identifying a communication peer.
:bro:type:`pkt_hdr`: :bro:type:`record`                                    A packet header, consisting of an IP header and transport-layer header.
:bro:type:`pkt_profile_modes`: :bro:type:`enum`                            Output modes for packet profiling information.
:bro:type:`pm_callit_request`: :bro:type:`record`                          An RPC portmapper *callit* request.
:bro:type:`pm_mapping`: :bro:type:`record`                                 An RPC portmapper mapping.
:bro:type:`pm_mappings`: :bro:type:`table`                                 Table of RPC portmapper mappings.
:bro:type:`pm_port_request`: :bro:type:`record`                            An RPC portmapper request.
:bro:type:`raw_pkt_hdr`: :bro:type:`record`                                A raw packet header, consisting of L2 header and everything in
                                                                           :bro:see:`pkt_hdr`.
:bro:type:`record_field`: :bro:type:`record`                               Meta-information about a record field.
:bro:type:`record_field_table`: :bro:type:`table`                          Table type used to map record field declarations to meta-information
                                                                           describing them.
:bro:type:`rotate_info`: :bro:type:`record`                                Deprecated.
:bro:type:`script_id`: :bro:type:`record`                                  Meta-information about a script-level identifier.
:bro:type:`signature_and_hashalgorithm_vec`: :bro:type:`vector`            A vector of Signature and Hash Algorithms.
:bro:type:`signature_state`: :bro:type:`record`                            Description of a signature match.
:bro:type:`software`: :bro:type:`record`                                   
:bro:type:`software_version`: :bro:type:`record`                           
:bro:type:`string_array`: :bro:type:`table`                                An ordered array of strings.
:bro:type:`string_set`: :bro:type:`set`                                    A set of strings.
:bro:type:`string_vec`: :bro:type:`vector`                                 A vector of strings.
:bro:type:`subnet_vec`: :bro:type:`vector`                                 A vector of subnets.
:bro:type:`sw_align`: :bro:type:`record`                                   Helper type for return value of Smith-Waterman algorithm.
:bro:type:`sw_align_vec`: :bro:type:`vector`                               Helper type for return value of Smith-Waterman algorithm.
:bro:type:`sw_params`: :bro:type:`record`                                  Parameters for the Smith-Waterman algorithm.
:bro:type:`sw_substring`: :bro:type:`record`                               Helper type for return value of Smith-Waterman algorithm.
:bro:type:`sw_substring_vec`: :bro:type:`vector`                           Return type for Smith-Waterman algorithm.
:bro:type:`table_string_of_count`: :bro:type:`table`                       A table of counts indexed by strings.
:bro:type:`table_string_of_string`: :bro:type:`table`                      A table of strings indexed by strings.
:bro:type:`tcp_hdr`: :bro:type:`record`                                    Values extracted from a TCP header.
:bro:type:`teredo_auth`: :bro:type:`record`                                A Teredo origin indication header.
:bro:type:`teredo_hdr`: :bro:type:`record`                                 A Teredo packet header.
:bro:type:`teredo_origin`: :bro:type:`record`                              A Teredo authentication header.
:bro:type:`transport_proto`: :bro:type:`enum`                              A connection's transport-layer protocol.
:bro:type:`udp_hdr`: :bro:type:`record`                                    Values extracted from a UDP header.
:bro:type:`var_sizes`: :bro:type:`table`                                   Table type used to map variable names to their memory allocation.
:bro:type:`x509_opaque_vector`: :bro:type:`vector`                         A vector of x509 opaques.
========================================================================== ==============================================================================================

Functions
#########
================================================================ =========================================================
:bro:id:`add_interface`: :bro:type:`function`                    Internal function.
:bro:id:`add_signature_file`: :bro:type:`function`               Internal function.
:bro:id:`discarder_check_icmp`: :bro:type:`function`             Function for skipping packets based on their ICMP header.
:bro:id:`discarder_check_ip`: :bro:type:`function`               Function for skipping packets based on their IP header.
:bro:id:`discarder_check_tcp`: :bro:type:`function`              Function for skipping packets based on their TCP header.
:bro:id:`discarder_check_udp`: :bro:type:`function`              Function for skipping packets based on their UDP header.
:bro:id:`log_file_name`: :bro:type:`function` :bro:attr:`&redef` Deprecated.
:bro:id:`max_count`: :bro:type:`function`                        Returns maximum of two ``count`` values.
:bro:id:`max_double`: :bro:type:`function`                       Returns maximum of two ``double`` values.
:bro:id:`max_interval`: :bro:type:`function`                     Returns maximum of two ``interval`` values.
:bro:id:`min_count`: :bro:type:`function`                        Returns minimum of two ``count`` values.
:bro:id:`min_double`: :bro:type:`function`                       Returns minimum of two ``double`` values.
:bro:id:`min_interval`: :bro:type:`function`                     Returns minimum of two ``interval`` values.
:bro:id:`open_log_file`: :bro:type:`function` :bro:attr:`&redef` Deprecated.
================================================================ =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Weird::sampling_duration

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 mins``

   How long a weird of a given type is allowed to keep state/counters in
   memory. For "net" weirds an expiration timer starts per weird name when
   first initializing its counter. For "flow" weirds an expiration timer
   starts once per src/dst IP pair for the first weird of any name. For
   "conn" weirds, counters and expiration timers are kept for the duration
   of the connection for each named weird and reset when necessary. E.g.
   if a "conn" weird by the name of "foo" is seen more than
   :bro:see:`Weird::sampling_threshold` times, then an expiration timer
   begins for "foo" and upon triggering will reset the counter for "foo"
   and unthrottle its rate-limiting until it once again exceeds the
   threshold.

.. bro:id:: Weird::sampling_rate

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1000``

   The rate-limiting sampling rate. One out of every of this number of
   rate-limited weirds of a given type will be allowed to raise events
   for further script-layer handling. Setting the sampling rate to 0
   will disable all output of rate-limited weirds.

.. bro:id:: Weird::sampling_threshold

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``25``

   How many weirds of a given type to tolerate before sampling begins.
   I.e. this many consecutive weirds of a given type will be allowed to
   raise events for script-layer handling before being rate-limited.

.. bro:id:: Weird::sampling_whitelist

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Prevents rate-limiting sampling of any weirds named in the table.

.. bro:id:: default_file_bof_buffer_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``4096``

   Default amount of bytes that file analysis will buffer in order to use
   for mime type matching.  File analyzers attached at the time of mime type
   matching or later, will receive a copy of this buffer.

.. bro:id:: default_file_timeout_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``2.0 mins``

   Default amount of time a file can be inactive before the file analysis
   gives up and discards any internal state related to the file.

Redefinable Options
###################
.. bro:id:: DCE_RPC::max_cmd_reassembly

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``20``

   The maximum number of simultaneous fragmented commands that
   the DCE_RPC analyzer will tolerate before the it will generate
   a weird and skip further input.

.. bro:id:: DCE_RPC::max_frag_data

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30000``

   The maximum number of fragmented bytes that the DCE_RPC analyzer
   will tolerate on a command before the analyzer will generate a weird
   and skip further input.

.. bro:id:: KRB::keytab

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Kerberos keytab file name. Used to decrypt tickets encountered on the wire.

.. bro:id:: NCP::max_frame_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``65536``

   The maximum number of bytes to allocate when parsing NCP frames.

.. bro:id:: NFS3::return_data

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, :bro:see:`nfs_proc_read` and :bro:see:`nfs_proc_write`
   events return the file data that has been read/written.
   
   .. bro:see:: NFS3::return_data_max NFS3::return_data_first_only

.. bro:id:: NFS3::return_data_first_only

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If :bro:id:`NFS3::return_data` is true, whether to *only* return data
   if the read or write offset is 0, i.e., only return data for the
   beginning of the file.

.. bro:id:: NFS3::return_data_max

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``512``

   If :bro:id:`NFS3::return_data` is true, how much data should be
   returned at most.

.. bro:id:: Pcap::bufsize

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``128``

   Number of Mbytes to provide as buffer space when capturing from live
   interfaces.

.. bro:id:: Pcap::snaplen

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``9216``

   Number of bytes per packet to capture from live interfaces.

.. bro:id:: Reporter::errors_to_stderr

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Tunable for sending reporter error messages to STDERR.  The option to
   turn it off is presented here in case Bro is being run by some
   external harness and shouldn't output anything to the console.

.. bro:id:: Reporter::info_to_stderr

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Tunable for sending reporter info messages to STDERR.  The option to
   turn it off is presented here in case Bro is being run by some
   external harness and shouldn't output anything to the console.

.. bro:id:: Reporter::warnings_to_stderr

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Tunable for sending reporter warning messages to STDERR.  The option
   to turn it off is presented here in case Bro is being run by some
   external harness and shouldn't output anything to the console.

.. bro:id:: SMB::pipe_filenames

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "srvsvc",
         "winreg",
         "netdfs",
         "MsFteWds",
         "samr",
         "spoolss",
         "wkssvc",
         "lsarpc"
      }

   A set of file names used as named pipes over SMB. This
   only comes into play as a heuristic to identify named
   pipes when the drive mapping wasn't seen by Bro.
   
   .. bro:see:: smb_pipe_connect_heuristic

.. bro:id:: Threading::heartbeat_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 sec``

   The heartbeat interval used by the threading framework.
   Changing this should usually not be necessary and will break
   several tests.

.. bro:id:: Tunnel::delay_gtp_confirmation

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   With this set, the GTP analyzer waits until the most-recent upflow
   and downflow packets are a valid GTPv1 encapsulation before
   issuing :bro:see:`protocol_confirmation`.  If it's false, the
   first occurrence of a packet with valid GTPv1 encapsulation causes
   confirmation.  Since the same inner connection can be carried
   differing outer upflow/downflow connections, setting to false
   may work better.

.. bro:id:: Tunnel::delay_teredo_confirmation

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   With this set, the Teredo analyzer waits until it sees both sides
   of a connection using a valid Teredo encapsulation before issuing
   a :bro:see:`protocol_confirmation`.  If it's false, the first
   occurrence of a packet with valid Teredo encapsulation causes a
   confirmation.

.. bro:id:: Tunnel::enable_ayiya

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Toggle whether to do IPv{4,6}-in-AYIYA decapsulation.

.. bro:id:: Tunnel::enable_gre

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Toggle whether to do GRE decapsulation.

.. bro:id:: Tunnel::enable_gtpv1

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Toggle whether to do GTPv1 decapsulation.

.. bro:id:: Tunnel::enable_ip

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Toggle whether to do IPv{4,6}-in-IPv{4,6} decapsulation.

.. bro:id:: Tunnel::enable_teredo

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Toggle whether to do IPv6-in-Teredo decapsulation.

.. bro:id:: Tunnel::ip_tunnel_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 day``

   How often to cleanup internal state for inactive IP tunnels
   (includes GRE tunnels).

.. bro:id:: Tunnel::max_depth

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``2``

   The maximum depth of a tunnel to decapsulate until giving up.
   Setting this to zero will disable all types of tunnel decapsulation.

.. bro:id:: backdoor_stat_backoff

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`

   Deprecated.

.. bro:id:: backdoor_stat_period

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`

   Deprecated.

.. bro:id:: bits_per_uid

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``96``

   Number of bits in UIDs that are generated to identify connections and
   files.  The larger the value, the more confidence in UID uniqueness.
   The maximum is currently 128 bits.

.. bro:id:: check_for_unused_event_handlers

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, warns about unused event handlers at startup.

.. bro:id:: chunked_io_buffer_soft_cap

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``800000``

   The number of IO chunks allowed to be buffered between the child
   and parent process of remote communication before Bro starts dropping
   connections to remote peers in an attempt to catch up.

.. bro:id:: cmd_line_bpf_filter

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   BPF filter the user has set via the -f command line options. Empty if none.

.. bro:id:: detect_filtered_trace

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Whether to attempt to automatically detect SYN/FIN/RST-filtered trace
   and not report missing segments for such connections.
   If this is enabled, then missing data at the end of connections may not
   be reported via :bro:see:`content_gap`.

.. bro:id:: dns_resolver

   :Type: :bro:type:`addr`
   :Attributes: :bro:attr:`&redef`
   :Default: ``::``

   The address of the DNS resolver to use.  If not changed from the
   unspecified address, ``[::]``, the first nameserver from /etc/resolv.conf
   gets used (IPv6 is currently only supported if set via this option, not
   when parsed from the file).

.. bro:id:: dns_session_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 secs``

   Time to wait before timing out a DNS request.

.. bro:id:: dpd_buffer_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1024``

   Size of per-connection buffer used for dynamic protocol detection. For each
   connection, Bro buffers this initial amount of payload in memory so that
   complete protocol analysis can start even after the initial packets have
   already passed through (i.e., when a DPD signature matches only later).
   However, once the buffer is full, data is deleted and lost to analyzers that
   are activated afterwards. Then only analyzers that can deal with partial
   connections will be able to analyze the session.
   
   .. bro:see:: dpd_reassemble_first_packets dpd_match_only_beginning
      dpd_ignore_ports

.. bro:id:: dpd_ignore_ports

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, don't consider any ports for deciding which protocol analyzer to
   use.
   
   .. bro:see:: dpd_reassemble_first_packets dpd_buffer_size
      dpd_match_only_beginning

.. bro:id:: dpd_match_only_beginning

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, stops signature matching if :bro:see:`dpd_buffer_size` has been
   reached.
   
   .. bro:see:: dpd_reassemble_first_packets dpd_buffer_size
      dpd_ignore_ports
   
   .. note:: Despite the name, this option affects *all* signature matching, not
      only signatures used for dynamic protocol detection.

.. bro:id:: dpd_reassemble_first_packets

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Reassemble the beginning of all TCP connections before doing
   signature matching. Enabling this provides more accurate matching at the
   expense of CPU cycles.
   
   .. bro:see:: dpd_buffer_size
      dpd_match_only_beginning dpd_ignore_ports
   
   .. note:: Despite the name, this option affects *all* signature matching, not
      only signatures used for dynamic protocol detection.

.. bro:id:: enable_syslog

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Deprecated. No longer functional.

.. bro:id:: encap_hdr_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   If positive, indicates the encapsulation header size that should
   be skipped. This applies to all packets.

.. bro:id:: exit_only_after_terminate

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Flag to prevent Bro from exiting automatically when input is exhausted.
   Normally Bro terminates when all packet sources have gone dry
   and communication isn't enabled. If this flag is set, Bro's main loop will
   instead keep idling until :bro:see:`terminate` is explicitly called.
   
   This is mainly for testing purposes when termination behaviour needs to be
   controlled for reproducing results.

.. bro:id:: expensive_profiling_multiple

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``20``

   Multiples of :bro:see:`profiling_interval` at which (more expensive) memory
   profiling is done (0 disables).
   
   .. bro:see:: profiling_interval profiling_file segment_profiling

.. bro:id:: forward_remote_events

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, broadcast events received from one peer to all other peers.
   
   .. bro:see:: forward_remote_state_changes
   
   .. note:: This option is only temporary and will disappear once we get a
      more sophisticated script-level communication framework.

.. bro:id:: forward_remote_state_changes

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, broadcast state updates received from one peer to all other peers.
   
   .. bro:see:: forward_remote_events
   
   .. note:: This option is only temporary and will disappear once we get a
      more sophisticated script-level communication framework.

.. bro:id:: frag_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 mins``

   How long to hold onto fragments for possible reassembly.  A value of 0.0
   means "forever", which resists evasion, but can lead to state accrual.

.. bro:id:: global_hash_seed

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Seed for hashes computed internally for probabilistic data structures. Using
   the same value here will make the hashes compatible between independent Bro
   instances. If left unset, Bro will use a temporary local seed.

.. bro:id:: icmp_inactivity_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 min``

   If an ICMP flow is inactive, time it out after this interval. If 0 secs, then
   don't time it out.
   
   .. bro:see:: tcp_inactivity_timeout udp_inactivity_timeout set_inactivity_timeout

.. bro:id:: ignore_checksums

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, don't verify checksums.  Useful for running on altered trace
   files, and for saving a few cycles, but at the risk of analyzing invalid
   data. Note that the ``-C`` command-line option overrides the setting of this
   variable.

.. bro:id:: ignore_keep_alive_rexmit

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Ignore certain TCP retransmissions for :bro:see:`conn_stats`.  Some
   connections (e.g., SSH) retransmit the acknowledged last byte to keep the
   connection alive. If *ignore_keep_alive_rexmit* is set to true, such
   retransmissions will be excluded in the rexmit counter in
   :bro:see:`conn_stats`.
   
   .. bro:see:: conn_stats

.. bro:id:: interconn_default_pkt_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`

   Deprecated.

.. bro:id:: interconn_max_interarrival

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`

   Deprecated.

.. bro:id:: interconn_max_keystroke_pkt_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`

   Deprecated.

.. bro:id:: interconn_min_interarrival

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`

   Deprecated.

.. bro:id:: interconn_stat_backoff

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`

   Deprecated.

.. bro:id:: interconn_stat_period

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`

   Deprecated.

.. bro:id:: likely_server_ports

   :Type: :bro:type:`set` [:bro:type:`port`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         443/tcp,
         995/tcp,
         6668/tcp,
         5222/tcp,
         631/tcp,
         8000/tcp,
         161/udp,
         6666/tcp,
         502/tcp,
         1080/tcp,
         443/udp,
         162/udp,
         993/tcp,
         139/tcp,
         5072/udp,
         2811/tcp,
         81/tcp,
         6667/tcp,
         990/tcp,
         563/tcp,
         20000/tcp,
         5223/tcp,
         143/tcp,
         137/udp,
         636/tcp,
         587/tcp,
         25/tcp,
         135/tcp,
         20000/udp,
         53/udp,
         5355/udp,
         585/tcp,
         80/tcp,
         88/udp,
         3389/tcp,
         6669/tcp,
         5269/tcp,
         8080/tcp,
         614/tcp,
         53/tcp,
         67/udp,
         445/tcp,
         8888/tcp,
         2152/udp,
         3544/udp,
         22/tcp,
         514/udp,
         21/tcp,
         989/tcp,
         88/tcp,
         3128/tcp,
         1812/udp,
         992/tcp,
         2123/udp,
         5353/udp,
         5060/udp
      }

   Ports which the core considers being likely used by servers. For ports in
   this set, it may heuristically decide to flip the direction of the
   connection if it misses the initial handshake.

.. bro:id:: log_encryption_key

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"<undefined>"``

   Deprecated.

.. bro:id:: log_max_size

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0.0``

   Deprecated.

.. bro:id:: log_rotate_base_time

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"0:00"``

   Deprecated.

.. bro:id:: log_rotate_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0 secs``

   Deprecated.

.. bro:id:: max_files_in_cache

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   The maximum number of open files to keep cached at a given time.
   If set to zero, this is automatically determined by inspecting
   the current/maximum limit on open files for the process.

.. bro:id:: max_remote_events_processed

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10``

   With a similar trade-off, this gives the number of remote events
   to process in a batch before interleaving other activity.

.. bro:id:: max_timer_expires

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``300``

   The maximum number of timers to expire after processing each new
   packet.  The value trades off spreading out the timer expiration load
   with possibly having to hold state longer.  A value of 0 means
   "process all expired timers with each new packet".

.. bro:id:: mmdb_dir

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   The directory containing MaxMind DB (.mmdb) files to use for GeoIP support.

.. bro:id:: non_analyzed_lifetime

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0 secs``

   If a connection belongs to an application that we don't analyze,
   time it out after this interval.  If 0 secs, then don't time it out (but
   :bro:see:`tcp_inactivity_timeout`, :bro:see:`udp_inactivity_timeout`, and
   :bro:see:`icmp_inactivity_timeout` still apply).

.. bro:id:: ntp_session_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 mins``

   Time to wait before timing out an NTP request.

.. bro:id:: old_comm_usage_is_ok

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Whether usage of the old communication system is considered an error or
   not.  The default Bro configuration no longer works with the non-Broker
   communication system unless you have manually taken action to initialize
   and set up the old comm. system.  Deprecation warnings are still emitted
   when setting this flag, but they will not result in a fatal error.

.. bro:id:: packet_filter_default

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Default mode for Bro's user-space dynamic packet filter. If true, packets
   that aren't explicitly allowed through, are dropped from any further
   processing.
   
   .. note:: This is not the BPF packet filter but an additional dynamic filter
      that Bro optionally applies just before normal processing starts.
   
   .. bro:see:: install_dst_addr_filter install_dst_net_filter
      install_src_addr_filter install_src_net_filter  uninstall_dst_addr_filter
      uninstall_dst_net_filter uninstall_src_addr_filter uninstall_src_net_filter

.. bro:id:: partial_connection_ok

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, instantiate connection state when a partial connection
   (one missing its initial establishment negotiation) is seen.

.. bro:id:: passive_fingerprint_file

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"base/misc/p0f.fp"``

   ``p0f`` fingerprint file to use. Will be searched relative to ``BROPATH``.

.. bro:id:: peer_description

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro"``

   Description transmitted to remote communication peers for identification.

.. bro:id:: pkt_profile_freq

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0.0``

   Frequency associated with packet profiling.
   
   .. bro:see:: pkt_profile_modes pkt_profile_mode pkt_profile_file

.. bro:id:: pkt_profile_mode

   :Type: :bro:type:`pkt_profile_modes`
   :Attributes: :bro:attr:`&redef`
   :Default: ``PKT_PROFILE_MODE_NONE``

   Output mode for packet profiling information.
   
   .. bro:see:: pkt_profile_modes pkt_profile_freq pkt_profile_file

.. bro:id:: profiling_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0 secs``

   Update interval for profiling (0 disables).  The easiest way to activate
   profiling is loading  :doc:`/scripts/policy/misc/profiling.bro`.
   
   .. bro:see:: profiling_file expensive_profiling_multiple segment_profiling

.. bro:id:: record_all_packets

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If a trace file is given with ``-w``, dump *all* packets seen by Bro into it.
   By default, Bro applies (very few) heuristics to reduce the volume. A side
   effect of setting this to true is that we can write the packets out before we
   actually process them, which can be helpful for debugging in case the
   analysis triggers a crash.
   
   .. bro:see:: trace_output_file

.. bro:id:: remote_check_sync_consistency

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Whether for :bro:attr:`&synchronized` state to send the old value as a
   consistency check.

.. bro:id:: remote_trace_sync_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0 secs``

   Synchronize trace processing at a regular basis in pseudo-realtime mode.
   
   .. bro:see:: remote_trace_sync_peers

.. bro:id:: remote_trace_sync_peers

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   Number of peers across which to synchronize trace processing in
   pseudo-realtime mode.
   
   .. bro:see:: remote_trace_sync_interval

.. bro:id:: report_gaps_for_partial

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Whether we want :bro:see:`content_gap` for partial
   connections. A connection is partial if it is missing a full handshake. Note
   that gap reports for partial connections might not be reliable.
   
   .. bro:see:: content_gap partial_connection

.. bro:id:: rpc_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``24.0 secs``

   Time to wait before timing out an RPC request.

.. bro:id:: segment_profiling

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, then write segment profiling information (very high volume!)
   in addition to profiling statistics.
   
   .. bro:see:: profiling_interval expensive_profiling_multiple profiling_file

.. bro:id:: sig_max_group_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``50``

   Maximum size of regular expression groups for signature matching.

.. bro:id:: skip_http_data

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Skip HTTP data for performance considerations. The skipped
   portion will not go through TCP reassembly.
   
   .. bro:see:: http_entity_data skip_http_entity_data http_entity_data_delivery_size

.. bro:id:: ssl_ca_certificate

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"<undefined>"``

   The CA certificate file to authorize remote Bros/Broccolis.
   
   .. bro:see:: ssl_private_key ssl_passphrase

.. bro:id:: ssl_passphrase

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"<undefined>"``

   The passphrase for our private key. Keeping this undefined
   causes Bro to prompt for the passphrase.
   
   .. bro:see:: ssl_private_key ssl_ca_certificate

.. bro:id:: ssl_private_key

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"<undefined>"``

   File containing our private key and our certificate.
   
   .. bro:see:: ssl_ca_certificate ssl_passphrase

.. bro:id:: state_dir

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``".state"``

   Specifies a directory for Bro to store its persistent state. All globals can
   be declared persistent via the :bro:attr:`&persistent` attribute.

.. bro:id:: state_write_delay

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 msecs``

   Length of the delays inserted when storing state incrementally. To avoid
   dropping packets when serializing larger volumes of persistent state to
   disk, Bro interleaves the operation with continued packet processing.

.. bro:id:: stp_delta

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`

   Internal to the stepping stone detector.

.. bro:id:: stp_idle_min

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`

   Internal to the stepping stone detector.

.. bro:id:: suppress_local_output

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Deprecated.

.. bro:id:: table_expire_delay

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 msecs``

   When expiring table entries, wait this amount of time before checking the
   next chunk of entries.
   
   .. bro:see:: table_expire_interval table_incremental_step

.. bro:id:: table_expire_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 secs``

   Check for expired table entries after this amount of time.
   
   .. bro:see:: table_incremental_step table_expire_delay

.. bro:id:: table_incremental_step

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5000``

   When expiring/serializing table entries, don't work on more than this many
   table entries at a time.
   
   .. bro:see:: table_expire_interval table_expire_delay

.. bro:id:: tcp_SYN_ack_ok

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, instantiate connection state when a SYN/ACK is seen but not the
   initial SYN (even if :bro:see:`partial_connection_ok` is false).

.. bro:id:: tcp_SYN_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 secs``

   Check up on the result of an initial SYN after this much time.

.. bro:id:: tcp_attempt_delay

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 secs``

   Wait this long upon seeing an initial SYN before timing out the
   connection attempt.

.. bro:id:: tcp_close_delay

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 secs``

   Upon seeing a normal connection close, flush state after this much time.

.. bro:id:: tcp_connection_linger

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 secs``

   When checking a closed connection for further activity, consider it
   inactive if there hasn't been any for this long.  Complain if the
   connection is reused before this much time has elapsed.

.. bro:id:: tcp_content_deliver_all_orig

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, all TCP originator-side traffic is reported via
   :bro:see:`tcp_contents`.
   
   .. bro:see:: tcp_content_delivery_ports_orig tcp_content_delivery_ports_resp
      tcp_content_deliver_all_resp udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp tcp_contents

.. bro:id:: tcp_content_deliver_all_resp

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, all TCP responder-side traffic is reported via
   :bro:see:`tcp_contents`.
   
   .. bro:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp
      tcp_content_deliver_all_orig udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp tcp_contents

.. bro:id:: tcp_content_delivery_ports_orig

   :Type: :bro:type:`table` [:bro:type:`port`] of :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Defines destination TCP ports for which the contents of the originator stream
   should be delivered via :bro:see:`tcp_contents`.
   
   .. bro:see:: tcp_content_delivery_ports_resp tcp_content_deliver_all_orig
      tcp_content_deliver_all_resp udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp  tcp_contents

.. bro:id:: tcp_content_delivery_ports_resp

   :Type: :bro:type:`table` [:bro:type:`port`] of :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Defines destination TCP ports for which the contents of the responder stream
   should be delivered via :bro:see:`tcp_contents`.
   
   .. bro:see:: tcp_content_delivery_ports_orig tcp_content_deliver_all_orig
      tcp_content_deliver_all_resp udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp tcp_contents

.. bro:id:: tcp_excessive_data_without_further_acks

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10485760``

   If we've seen this much data without any of it being acked, we give up
   on that connection to avoid memory exhaustion due to buffering all that
   stuff.  If set to zero, then we don't ever give up.  Ideally, Bro would
   track the current window on a connection and use it to infer that data
   has in fact gone too far, but for now we just make this quite beefy.
   
   .. bro:see:: tcp_max_initial_window tcp_max_above_hole_without_any_acks

.. bro:id:: tcp_inactivity_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 mins``

   If a TCP connection is inactive, time it out after this interval. If 0 secs,
   then don't time it out.
   
   .. bro:see:: udp_inactivity_timeout icmp_inactivity_timeout set_inactivity_timeout

.. bro:id:: tcp_match_undelivered

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, pass any undelivered to the signature engine before flushing the state.
   If a connection state is removed, there may still be some data waiting in the
   reassembler.

.. bro:id:: tcp_max_above_hole_without_any_acks

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``16384``

   If we're not seeing our peer's ACKs, the maximum volume of data above a
   sequence hole that we'll tolerate before assuming that there's been a packet
   drop and we should give up on tracking a connection. If set to zero, then we
   don't ever give up.
   
   .. bro:see:: tcp_max_initial_window tcp_excessive_data_without_further_acks

.. bro:id:: tcp_max_initial_window

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``16384``

   Maximum amount of data that might plausibly be sent in an initial flight
   (prior to receiving any acks).  Used to determine whether we must not be
   seeing our peer's ACKs.  Set to zero to turn off this determination.
   
   .. bro:see:: tcp_max_above_hole_without_any_acks tcp_excessive_data_without_further_acks

.. bro:id:: tcp_max_old_segments

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   Number of TCP segments to buffer beyond what's been acknowledged already
   to detect retransmission inconsistencies. Zero disables any additonal
   buffering.

.. bro:id:: tcp_partial_close_delay

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``3.0 secs``

   Generate a :bro:id:`connection_partial_close` event this much time after one
   half of a partial connection closes, assuming there has been no subsequent
   activity.

.. bro:id:: tcp_reassembler_ports_orig

   :Type: :bro:type:`set` [:bro:type:`port`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   For services without a handler, these sets define originator-side ports
   that still trigger reassembly.
   
   .. bro:see:: tcp_reassembler_ports_resp

.. bro:id:: tcp_reassembler_ports_resp

   :Type: :bro:type:`set` [:bro:type:`port`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   For services without a handler, these sets define responder-side ports
   that still trigger reassembly.
   
   .. bro:see:: tcp_reassembler_ports_orig

.. bro:id:: tcp_reset_delay

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 secs``

   Upon seeing a RST, flush state after this much time.

.. bro:id:: tcp_session_timer

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``6.0 secs``

   After a connection has closed, wait this long for further activity
   before checking whether to time out its state.

.. bro:id:: tcp_storm_interarrival_thresh

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 sec``

   FINs/RSTs must come with this much time or less between them to be
   considered a "storm".
   
   .. bro:see:: tcp_storm_thresh

.. bro:id:: tcp_storm_thresh

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1000``

   Number of FINs/RSTs in a row that constitute a "storm". Storms are reported
   as ``weird`` via the notice framework, and they must also come within
   intervals of at most :bro:see:`tcp_storm_interarrival_thresh`.
   
   .. bro:see:: tcp_storm_interarrival_thresh

.. bro:id:: time_machine_profiling

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, output profiling for Time-Machine queries.

.. bro:id:: timer_mgr_inactivity_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 min``

   Per-incident timer managers are drained after this amount of inactivity.

.. bro:id:: truncate_http_URI

   :Type: :bro:type:`int`
   :Attributes: :bro:attr:`&redef`
   :Default: ``-1``

   Maximum length of HTTP URIs passed to events. Longer ones will be truncated
   to prevent over-long URIs (usually sent by worms) from slowing down event
   processing.  A value of -1 means "do not truncate".
   
   .. bro:see:: http_request

.. bro:id:: udp_content_deliver_all_orig

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, all UDP originator-side traffic is reported via
   :bro:see:`udp_contents`.
   
   .. bro:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp tcp_content_deliver_all_resp
      tcp_content_delivery_ports_orig udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_resp
      udp_contents

.. bro:id:: udp_content_deliver_all_resp

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, all UDP responder-side traffic is reported via
   :bro:see:`udp_contents`.
   
   .. bro:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp tcp_content_deliver_all_resp
      tcp_content_delivery_ports_orig udp_content_delivery_ports_orig
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_contents

.. bro:id:: udp_content_delivery_ports_orig

   :Type: :bro:type:`table` [:bro:type:`port`] of :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Defines UDP destination ports for which the contents of the originator stream
   should be delivered via :bro:see:`udp_contents`.
   
   .. bro:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp
      tcp_content_deliver_all_orig tcp_content_deliver_all_resp
      udp_content_delivery_ports_resp  udp_content_deliver_all_orig
      udp_content_deliver_all_resp  udp_contents

.. bro:id:: udp_content_delivery_ports_resp

   :Type: :bro:type:`table` [:bro:type:`port`] of :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Defines UDP destination ports for which the contents of the responder stream
   should be delivered via :bro:see:`udp_contents`.
   
   .. bro:see:: tcp_content_delivery_ports_orig
      tcp_content_delivery_ports_resp tcp_content_deliver_all_orig
      tcp_content_deliver_all_resp udp_content_delivery_ports_orig
      udp_content_deliver_all_orig udp_content_deliver_all_resp udp_contents

.. bro:id:: udp_inactivity_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 min``

   If a UDP flow is inactive, time it out after this interval. If 0 secs, then
   don't time it out.
   
   .. bro:see:: tcp_inactivity_timeout icmp_inactivity_timeout set_inactivity_timeout

.. bro:id:: use_conn_size_analyzer

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Whether to use the ``ConnSize`` analyzer to count the number of packets and
   IP-level bytes transferred by each endpoint. If true, these values are
   returned in the connection's :bro:see:`endpoint` record value.

.. bro:id:: watchdog_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 secs``

   Bro's watchdog interval.

Constants
#########
.. bro:id:: CONTENTS_BOTH

   :Type: :bro:type:`count`
   :Default: ``3``

   Record both originator and responder contents.

.. bro:id:: CONTENTS_NONE

   :Type: :bro:type:`count`
   :Default: ``0``

   Turn off recording of contents.

.. bro:id:: CONTENTS_ORIG

   :Type: :bro:type:`count`
   :Default: ``1``

   Record originator contents.

.. bro:id:: CONTENTS_RESP

   :Type: :bro:type:`count`
   :Default: ``2``

   Record responder contents.

.. bro:id:: DNS_ADDL

   :Type: :bro:type:`count`
   :Default: ``3``

   An additional record.

.. bro:id:: DNS_ANS

   :Type: :bro:type:`count`
   :Default: ``1``

   An answer record.

.. bro:id:: DNS_AUTH

   :Type: :bro:type:`count`
   :Default: ``2``

   An authoritative record.

.. bro:id:: DNS_QUERY

   :Type: :bro:type:`count`
   :Default: ``0``

   A query. This shouldn't occur, just for completeness.

.. bro:id:: ENDIAN_BIG

   :Type: :bro:type:`count`
   :Default: ``2``

   Big endian.

.. bro:id:: ENDIAN_CONFUSED

   :Type: :bro:type:`count`
   :Default: ``3``

   Tried to determine endian, but failed.

.. bro:id:: ENDIAN_LITTLE

   :Type: :bro:type:`count`
   :Default: ``1``

   Little endian.

.. bro:id:: ENDIAN_UNKNOWN

   :Type: :bro:type:`count`
   :Default: ``0``

   Endian not yet determined.

.. bro:id:: ICMP_UNREACH_ADMIN_PROHIB

   :Type: :bro:type:`count`
   :Default: ``13``

   Administratively prohibited.

.. bro:id:: ICMP_UNREACH_HOST

   :Type: :bro:type:`count`
   :Default: ``1``

   Host unreachable.

.. bro:id:: ICMP_UNREACH_NEEDFRAG

   :Type: :bro:type:`count`
   :Default: ``4``

   Fragment needed.

.. bro:id:: ICMP_UNREACH_NET

   :Type: :bro:type:`count`
   :Default: ``0``

   Network unreachable.

.. bro:id:: ICMP_UNREACH_PORT

   :Type: :bro:type:`count`
   :Default: ``3``

   Port unreachable.

.. bro:id:: ICMP_UNREACH_PROTOCOL

   :Type: :bro:type:`count`
   :Default: ``2``

   Protocol unreachable.

.. bro:id:: IPPROTO_AH

   :Type: :bro:type:`count`
   :Default: ``51``

   IPv6 authentication header.

.. bro:id:: IPPROTO_DSTOPTS

   :Type: :bro:type:`count`
   :Default: ``60``

   IPv6 destination options header.

.. bro:id:: IPPROTO_ESP

   :Type: :bro:type:`count`
   :Default: ``50``

   IPv6 encapsulating security payload header.

.. bro:id:: IPPROTO_FRAGMENT

   :Type: :bro:type:`count`
   :Default: ``44``

   IPv6 fragment header.

.. bro:id:: IPPROTO_HOPOPTS

   :Type: :bro:type:`count`
   :Default: ``0``

   IPv6 hop-by-hop-options header.

.. bro:id:: IPPROTO_ICMP

   :Type: :bro:type:`count`
   :Default: ``1``

   Control message protocol.

.. bro:id:: IPPROTO_ICMPV6

   :Type: :bro:type:`count`
   :Default: ``58``

   ICMP for IPv6.

.. bro:id:: IPPROTO_IGMP

   :Type: :bro:type:`count`
   :Default: ``2``

   Group management protocol.

.. bro:id:: IPPROTO_IP

   :Type: :bro:type:`count`
   :Default: ``0``

   Dummy for IP.

.. bro:id:: IPPROTO_IPIP

   :Type: :bro:type:`count`
   :Default: ``4``

   IP encapsulation in IP.

.. bro:id:: IPPROTO_IPV6

   :Type: :bro:type:`count`
   :Default: ``41``

   IPv6 header.

.. bro:id:: IPPROTO_MOBILITY

   :Type: :bro:type:`count`
   :Default: ``135``

   IPv6 mobility header.

.. bro:id:: IPPROTO_NONE

   :Type: :bro:type:`count`
   :Default: ``59``

   IPv6 no next header.

.. bro:id:: IPPROTO_RAW

   :Type: :bro:type:`count`
   :Default: ``255``

   Raw IP packet.

.. bro:id:: IPPROTO_ROUTING

   :Type: :bro:type:`count`
   :Default: ``43``

   IPv6 routing header.

.. bro:id:: IPPROTO_TCP

   :Type: :bro:type:`count`
   :Default: ``6``

   TCP.

.. bro:id:: IPPROTO_UDP

   :Type: :bro:type:`count`
   :Default: ``17``

   User datagram protocol.

.. bro:id:: LOGIN_STATE_AUTHENTICATE

   :Type: :bro:type:`count`
   :Default: ``0``


.. bro:id:: LOGIN_STATE_CONFUSED

   :Type: :bro:type:`count`
   :Default: ``3``


.. bro:id:: LOGIN_STATE_LOGGED_IN

   :Type: :bro:type:`count`
   :Default: ``1``


.. bro:id:: LOGIN_STATE_SKIP

   :Type: :bro:type:`count`
   :Default: ``2``


.. bro:id:: PEER_ID_NONE

   :Type: :bro:type:`count`
   :Default: ``0``

   Place-holder constant indicating "no peer".

.. bro:id:: REMOTE_LOG_ERROR

   :Type: :bro:type:`count`
   :Default: ``2``

   Deprecated.

.. bro:id:: REMOTE_LOG_INFO

   :Type: :bro:type:`count`
   :Default: ``1``

   Deprecated.

.. bro:id:: REMOTE_SRC_CHILD

   :Type: :bro:type:`count`
   :Default: ``1``

   Message from the child process.

.. bro:id:: REMOTE_SRC_PARENT

   :Type: :bro:type:`count`
   :Default: ``2``

   Message from the parent process.

.. bro:id:: REMOTE_SRC_SCRIPT

   :Type: :bro:type:`count`
   :Default: ``3``

   Message from a policy script.

.. bro:id:: RPC_status

   :Type: :bro:type:`table` [:bro:type:`rpc_status`] of :bro:type:`string`
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
   
   .. bro:see:: pm_attempt_callit pm_attempt_dump pm_attempt_getport
      pm_attempt_null pm_attempt_set pm_attempt_unset rpc_dialogue rpc_reply

.. bro:id:: SNMP::OBJ_COUNTER32_TAG

   :Type: :bro:type:`count`
   :Default: ``65``

   Unsigned 32-bit integer.

.. bro:id:: SNMP::OBJ_COUNTER64_TAG

   :Type: :bro:type:`count`
   :Default: ``70``

   Unsigned 64-bit integer.

.. bro:id:: SNMP::OBJ_ENDOFMIBVIEW_TAG

   :Type: :bro:type:`count`
   :Default: ``130``

   A NULL value.

.. bro:id:: SNMP::OBJ_INTEGER_TAG

   :Type: :bro:type:`count`
   :Default: ``2``

   Signed 64-bit integer.

.. bro:id:: SNMP::OBJ_IPADDRESS_TAG

   :Type: :bro:type:`count`
   :Default: ``64``

   An IP address.

.. bro:id:: SNMP::OBJ_NOSUCHINSTANCE_TAG

   :Type: :bro:type:`count`
   :Default: ``129``

   A NULL value.

.. bro:id:: SNMP::OBJ_NOSUCHOBJECT_TAG

   :Type: :bro:type:`count`
   :Default: ``128``

   A NULL value.

.. bro:id:: SNMP::OBJ_OCTETSTRING_TAG

   :Type: :bro:type:`count`
   :Default: ``4``

   An octet string.

.. bro:id:: SNMP::OBJ_OID_TAG

   :Type: :bro:type:`count`
   :Default: ``6``

   An Object Identifier.

.. bro:id:: SNMP::OBJ_OPAQUE_TAG

   :Type: :bro:type:`count`
   :Default: ``68``

   An octet string.

.. bro:id:: SNMP::OBJ_TIMETICKS_TAG

   :Type: :bro:type:`count`
   :Default: ``67``

   Unsigned 32-bit integer.

.. bro:id:: SNMP::OBJ_UNSIGNED32_TAG

   :Type: :bro:type:`count`
   :Default: ``66``

   Unsigned 32-bit integer.

.. bro:id:: SNMP::OBJ_UNSPECIFIED_TAG

   :Type: :bro:type:`count`
   :Default: ``5``

   A NULL value.

.. bro:id:: TCP_CLOSED

   :Type: :bro:type:`count`
   :Default: ``5``

   Endpoint has closed connection.

.. bro:id:: TCP_ESTABLISHED

   :Type: :bro:type:`count`
   :Default: ``4``

   Endpoint has finished initial handshake regularly.

.. bro:id:: TCP_INACTIVE

   :Type: :bro:type:`count`
   :Default: ``0``

   Endpoint is still inactive.

.. bro:id:: TCP_PARTIAL

   :Type: :bro:type:`count`
   :Default: ``3``

   Endpoint has sent data but no initial SYN.

.. bro:id:: TCP_RESET

   :Type: :bro:type:`count`
   :Default: ``6``

   Endpoint has sent RST.

.. bro:id:: TCP_SYN_ACK_SENT

   :Type: :bro:type:`count`
   :Default: ``2``

   Endpoint has sent SYN/ACK.

.. bro:id:: TCP_SYN_SENT

   :Type: :bro:type:`count`
   :Default: ``1``

   Endpoint has sent SYN.

.. bro:id:: TH_ACK

   :Type: :bro:type:`count`
   :Default: ``16``

   ACK.

.. bro:id:: TH_FIN

   :Type: :bro:type:`count`
   :Default: ``1``

   FIN.

.. bro:id:: TH_FLAGS

   :Type: :bro:type:`count`
   :Default: ``63``

   Mask combining all flags.

.. bro:id:: TH_PUSH

   :Type: :bro:type:`count`
   :Default: ``8``

   PUSH.

.. bro:id:: TH_RST

   :Type: :bro:type:`count`
   :Default: ``4``

   RST.

.. bro:id:: TH_SYN

   :Type: :bro:type:`count`
   :Default: ``2``

   SYN.

.. bro:id:: TH_URG

   :Type: :bro:type:`count`
   :Default: ``32``

   URG.

.. bro:id:: UDP_ACTIVE

   :Type: :bro:type:`count`
   :Default: ``1``

   Endpoint has sent something.

.. bro:id:: UDP_INACTIVE

   :Type: :bro:type:`count`
   :Default: ``0``

   Endpoint is still inactive.

.. bro:id:: trace_output_file

   :Type: :bro:type:`string`
   :Default: ``""``

   Holds the filename of the trace file given with ``-w`` (empty if none).
   
   .. bro:see:: record_all_packets

State Variables
###############
.. bro:id:: capture_filters

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Set of BPF capture filters to use for capturing, indexed by a user-definable
   ID (which must be unique). If Bro is *not* configured with
   :bro:id:`PacketFilter::enable_auto_protocol_capture_filters`,
   all packets matching at least one of the filters in this table (and all in
   :bro:id:`restrict_filters`) will be analyzed.
   
   .. bro:see:: PacketFilter PacketFilter::enable_auto_protocol_capture_filters
      PacketFilter::unrestricted_filter restrict_filters

.. bro:id:: direct_login_prompts

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   TODO.

.. bro:id:: discarder_maxlen

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``128``

   Maximum length of payload passed to discarder functions.
   
   .. bro:see:: discarder_check_tcp discarder_check_udp discarder_check_icmp
      discarder_check_ip

.. bro:id:: dns_max_queries

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``25``

   If a DNS request includes more than this many queries, assume it's non-DNS
   traffic and do not process it.  Set to 0 to turn off this functionality.

.. bro:id:: dns_skip_addl

   :Type: :bro:type:`set` [:bro:type:`addr`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   For DNS servers in these sets, omit processing the ADDL records they include
   in their replies.
   
   .. bro:see:: dns_skip_all_addl dns_skip_auth

.. bro:id:: dns_skip_all_addl

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, all DNS ADDL records are skipped.
   
   .. bro:see:: dns_skip_all_auth dns_skip_addl

.. bro:id:: dns_skip_all_auth

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, all DNS AUTH records are skipped.
   
   .. bro:see:: dns_skip_all_addl dns_skip_auth

.. bro:id:: dns_skip_auth

   :Type: :bro:type:`set` [:bro:type:`addr`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   For DNS servers in these sets, omit processing the AUTH records they include
   in their replies.
   
   .. bro:see:: dns_skip_all_auth dns_skip_addl

.. bro:id:: done_with_network

   :Type: :bro:type:`bool`
   :Default: ``F``


.. bro:id:: generate_OS_version_event

   :Type: :bro:type:`set` [:bro:type:`subnet`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Defines for which subnets we should do passive fingerprinting.
   
   .. bro:see:: OS_version_found

.. bro:id:: http_entity_data_delivery_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1500``

   Maximum number of HTTP entity data delivered to events.
   
   .. bro:see:: http_entity_data skip_http_entity_data skip_http_data

.. bro:id:: interfaces

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&add_func` = :bro:see:`add_interface` :bro:attr:`&redef`
   :Default: ``""``

   Network interfaces to listen on. Use ``redef interfaces += "eth0"`` to
   extend.

.. bro:id:: irc_servers

   :Type: :bro:type:`set` [:bro:type:`addr`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Deprecated.
   
   .. todo:: Remove. It's still declared internally but doesn't seem  used anywhere
      else.

.. bro:id:: load_sample_freq

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``20``

   Rate at which to generate :bro:see:`load_sample` events. As all
   events, the event is only generated if you've also defined a
   :bro:see:`load_sample` handler.  Units are inverse number of packets; e.g.,
   a value of 20 means "roughly one in every 20 packets".
   
   .. bro:see:: load_sample

.. bro:id:: login_failure_msgs

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   TODO.

.. bro:id:: login_non_failure_msgs

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   TODO.

.. bro:id:: login_prompts

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   TODO.

.. bro:id:: login_success_msgs

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   TODO.

.. bro:id:: login_timeouts

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   TODO.

.. bro:id:: mime_segment_length

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1024``

   The length of MIME data segments delivered to handlers of
   :bro:see:`mime_segment_data`.
   
   .. bro:see:: mime_segment_data mime_segment_overlap_length

.. bro:id:: mime_segment_overlap_length

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   The number of bytes of overlap between successive segments passed to
   :bro:see:`mime_segment_data`.

.. bro:id:: pkt_profile_file

   :Type: :bro:type:`file`
   :Attributes: :bro:attr:`&redef`

   File where packet profiles are logged.
   
   .. bro:see:: pkt_profile_modes pkt_profile_freq pkt_profile_mode

.. bro:id:: profiling_file

   :Type: :bro:type:`file`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      file "prof.log" of string

   Write profiling info into this file in regular intervals. The easiest way to
   activate profiling is loading :doc:`/scripts/policy/misc/profiling.bro`.
   
   .. bro:see:: profiling_interval expensive_profiling_multiple segment_profiling

.. bro:id:: restrict_filters

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Set of BPF filters to restrict capturing, indexed by a user-definable ID
   (which must be unique).
   
   .. bro:see:: PacketFilter PacketFilter::enable_auto_protocol_capture_filters
      PacketFilter::unrestricted_filter capture_filters

.. bro:id:: secondary_filters

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`event` (filter: :bro:type:`string`, pkt: :bro:type:`pkt_hdr`)
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Definition of "secondary filters". A secondary filter is a BPF filter given
   as index in this table. For each such filter, the corresponding event is
   raised for all matching packets.

.. bro:id:: signature_files

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&add_func` = :bro:see:`add_signature_file` :bro:attr:`&redef`
   :Default: ``""``

   Signature files to read. Use ``redef signature_files  += "foo.sig"`` to
   extend. Signature files added this way will be searched relative to
   ``BROPATH``.  Using the ``@load-sigs`` directive instead is preferred
   since that can search paths relative to the current script.

.. bro:id:: skip_authentication

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   TODO.

.. bro:id:: stp_skip_src

   :Type: :bro:type:`set` [:bro:type:`addr`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Internal to the stepping stone detector.

Types
#####
.. bro:type:: BrokerStats

   :Type: :bro:type:`record`

      num_peers: :bro:type:`count`

      num_stores: :bro:type:`count`
         Number of active data stores.

      num_pending_queries: :bro:type:`count`
         Number of pending data store queries.

      num_events_incoming: :bro:type:`count`
         Number of total log messages received.

      num_events_outgoing: :bro:type:`count`
         Number of total log messages sent.

      num_logs_incoming: :bro:type:`count`
         Number of total log records received.

      num_logs_outgoing: :bro:type:`count`
         Number of total log records sent.

      num_ids_incoming: :bro:type:`count`
         Number of total identifiers received.

      num_ids_outgoing: :bro:type:`count`
         Number of total identifiers sent.

   Statistics about Broker communication.
   
   .. bro:see:: get_broker_stats

.. bro:type:: Cluster::Pool

   :Type: :bro:type:`record`

      spec: :bro:type:`Cluster::PoolSpec` :bro:attr:`&default` = ``[topic=, node_type=Cluster::PROXY, max_nodes=<uninitialized>, exclusive=F]`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.bro` is loaded)

         The specification of the pool that was used when registering it.

      nodes: :bro:type:`Cluster::PoolNodeTable` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.bro` is loaded)

         Nodes in the pool, indexed by their name (e.g. "manager").

      node_list: :bro:type:`vector` of :bro:type:`Cluster::PoolNode` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.bro` is loaded)

         A list of nodes in the pool in a deterministic order.

      hrw_pool: :bro:type:`HashHRW::Pool` :bro:attr:`&default` = ``[sites={  }]`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.bro` is loaded)

         The Rendezvous hashing structure.

      rr_key_seq: :bro:type:`Cluster::RoundRobinTable` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.bro` is loaded)

         Round-Robin table indexed by arbitrary key and storing the next
         index of *node_list* that will be eligible to receive work (if it's
         alive at the time of next request).

      alive_count: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/cluster/pools.bro` is loaded)

         Number of pool nodes that are currently alive.

   A pool used for distributing data/work among a set of cluster nodes.

.. bro:type:: ConnStats

   :Type: :bro:type:`record`

      total_conns: :bro:type:`count`
         

      current_conns: :bro:type:`count`
         

      current_conns_extern: :bro:type:`count`
         

      sess_current_conns: :bro:type:`count`
         

      num_packets: :bro:type:`count`

      num_fragments: :bro:type:`count`

      max_fragments: :bro:type:`count`

      num_tcp_conns: :bro:type:`count`
         Current number of TCP connections in memory.

      max_tcp_conns: :bro:type:`count`
         Maximum number of concurrent TCP connections so far.

      cumulative_tcp_conns: :bro:type:`count`
         Total number of TCP connections so far.

      num_udp_conns: :bro:type:`count`
         Current number of UDP flows in memory.

      max_udp_conns: :bro:type:`count`
         Maximum number of concurrent UDP flows so far.

      cumulative_udp_conns: :bro:type:`count`
         Total number of UDP flows so far.

      num_icmp_conns: :bro:type:`count`
         Current number of ICMP flows in memory.

      max_icmp_conns: :bro:type:`count`
         Maximum number of concurrent ICMP flows so far.

      cumulative_icmp_conns: :bro:type:`count`
         Total number of ICMP flows so far.

      killed_by_inactivity: :bro:type:`count`


.. bro:type:: DHCP::Addrs

   :Type: :bro:type:`vector` of :bro:type:`addr`

   A list of addresses offered by a DHCP server.  Could be routers,
   DNS servers, or other.
   
   .. bro:see:: dhcp_message

.. bro:type:: DHCP::ClientFQDN

   :Type: :bro:type:`record`

      flags: :bro:type:`count`
         An unparsed bitfield of flags (refer to RFC 4702).

      rcode1: :bro:type:`count`
         This field is deprecated in the standard.

      rcode2: :bro:type:`count`
         This field is deprecated in the standard.

      domain_name: :bro:type:`string`
         The Domain Name part of the option carries all or part of the FQDN
         of a DHCP client.

   DHCP Client FQDN Option information (Option 81)

.. bro:type:: DHCP::ClientID

   :Type: :bro:type:`record`

      hwtype: :bro:type:`count`

      hwaddr: :bro:type:`string`

   DHCP Client Identifier (Option 61)
   .. bro:see:: dhcp_message

.. bro:type:: DHCP::Msg

   :Type: :bro:type:`record`

      op: :bro:type:`count`
         Message OP code. 1 = BOOTREQUEST, 2 = BOOTREPLY

      m_type: :bro:type:`count`
         The type of DHCP message.

      xid: :bro:type:`count`
         Transaction ID of a DHCP session.

      secs: :bro:type:`interval`
         Number of seconds since client began address acquisition
         or renewal process

      flags: :bro:type:`count`

      ciaddr: :bro:type:`addr`
         Original IP address of the client.

      yiaddr: :bro:type:`addr`
         IP address assigned to the client.

      siaddr: :bro:type:`addr`
         IP address of the server.

      giaddr: :bro:type:`addr`
         IP address of the relaying gateway.

      chaddr: :bro:type:`string`
         Client hardware address.

      sname: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         Server host name.

      file_n: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         Boot file name.

   A DHCP message.
   .. bro:see:: dhcp_message

.. bro:type:: DHCP::Options

   :Type: :bro:type:`record`

      options: :bro:type:`index_vec` :bro:attr:`&optional`
         The ordered list of all DHCP option numbers.

      subnet_mask: :bro:type:`addr` :bro:attr:`&optional`
         Subnet Mask Value (option 1)

      routers: :bro:type:`DHCP::Addrs` :bro:attr:`&optional`
         Router addresses (option 3)

      dns_servers: :bro:type:`DHCP::Addrs` :bro:attr:`&optional`
         DNS Server addresses (option 6)

      host_name: :bro:type:`string` :bro:attr:`&optional`
         The Hostname of the client (option 12)

      domain_name: :bro:type:`string` :bro:attr:`&optional`
         The DNS domain name of the client (option 15)

      forwarding: :bro:type:`bool` :bro:attr:`&optional`
         Enable/Disable IP Forwarding (option 19)

      broadcast: :bro:type:`addr` :bro:attr:`&optional`
         Broadcast Address (option 28)

      vendor: :bro:type:`string` :bro:attr:`&optional`
         Vendor specific data. This can frequently
         be unparsed binary data. (option 43)

      nbns: :bro:type:`DHCP::Addrs` :bro:attr:`&optional`
         NETBIOS name server list (option 44)

      addr_request: :bro:type:`addr` :bro:attr:`&optional`
         Address requested by the client (option 50)

      lease: :bro:type:`interval` :bro:attr:`&optional`
         Lease time offered by the server. (option 51)

      serv_addr: :bro:type:`addr` :bro:attr:`&optional`
         Server address to allow clients to distinguish
         between lease offers. (option 54)

      param_list: :bro:type:`index_vec` :bro:attr:`&optional`
         DHCP Parameter Request list (option 55)

      message: :bro:type:`string` :bro:attr:`&optional`
         Textual error message (option 56)

      max_msg_size: :bro:type:`count` :bro:attr:`&optional`
         Maximum Message Size (option 57)

      renewal_time: :bro:type:`interval` :bro:attr:`&optional`
         This option specifies the time interval from address
         assignment until the client transitions to the
         RENEWING state. (option 58)

      rebinding_time: :bro:type:`interval` :bro:attr:`&optional`
         This option specifies the time interval from address
         assignment until the client transitions to the
         REBINDING state. (option 59)

      vendor_class: :bro:type:`string` :bro:attr:`&optional`
         This option is used by DHCP clients to optionally
         identify the vendor type and configuration of a DHCP
         client. (option 60)

      client_id: :bro:type:`DHCP::ClientID` :bro:attr:`&optional`
         DHCP Client Identifier (Option 61)

      user_class: :bro:type:`string` :bro:attr:`&optional`
         User Class opaque value (Option 77)

      client_fqdn: :bro:type:`DHCP::ClientFQDN` :bro:attr:`&optional`
         DHCP Client FQDN (Option 81)

      sub_opt: :bro:type:`DHCP::SubOpts` :bro:attr:`&optional`
         DHCP Relay Agent Information Option (Option 82)

      auto_config: :bro:type:`bool` :bro:attr:`&optional`
         Auto Config option to let host know if it's allowed to
         auto assign an IP address. (Option 116)

      auto_proxy_config: :bro:type:`string` :bro:attr:`&optional`
         URL to find a proxy.pac for auto proxy config (Option 252)


.. bro:type:: DHCP::SubOpt

   :Type: :bro:type:`record`

      code: :bro:type:`count`

      value: :bro:type:`string`

   DHCP Relay Agent Information Option (Option 82)
   .. bro:see:: dhcp_message

.. bro:type:: DHCP::SubOpts

   :Type: :bro:type:`vector` of :bro:type:`DHCP::SubOpt`


.. bro:type:: DNSStats

   :Type: :bro:type:`record`

      requests: :bro:type:`count`
         Number of DNS requests made

      successful: :bro:type:`count`
         Number of successful DNS replies.

      failed: :bro:type:`count`
         Number of DNS reply failures.

      pending: :bro:type:`count`
         Current pending queries.

      cached_hosts: :bro:type:`count`
         Number of cached hosts.

      cached_addresses: :bro:type:`count`
         Number of cached addresses.

   Statistics related to Bro's active use of DNS.  These numbers are
   about Bro performing DNS queries on it's own, not traffic
   being seen.
   
   .. bro:see:: get_dns_stats

.. bro:type:: EncapsulatingConnVector

   :Type: :bro:type:`vector` of :bro:type:`Tunnel::EncapsulatingConn`

   A type alias for a vector of encapsulating "connections", i.e. for when
   there are tunnels within tunnels.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: EventStats

   :Type: :bro:type:`record`

      queued: :bro:type:`count`
         Total number of events queued so far.

      dispatched: :bro:type:`count`
         Total number of events dispatched so far.


.. bro:type:: FileAnalysisStats

   :Type: :bro:type:`record`

      current: :bro:type:`count`
         Current number of files being analyzed.

      max: :bro:type:`count`
         Maximum number of concurrent files so far.

      cumulative: :bro:type:`count`
         Cumulative number of files analyzed.

   Statistics of file analysis.
   
   .. bro:see:: get_file_analysis_stats

.. bro:type:: GapStats

   :Type: :bro:type:`record`

      ack_events: :bro:type:`count`
         How many ack events *could* have had gaps.

      ack_bytes: :bro:type:`count`
         How many bytes those covered.

      gap_events: :bro:type:`count`
         How many *did* have gaps.

      gap_bytes: :bro:type:`count`
         How many bytes were missing in the gaps.

   Statistics about number of gaps in TCP connections.
   
   .. bro:see:: get_gap_stats

.. bro:type:: IPAddrAnonymization

   :Type: :bro:type:`enum`

      .. bro:enum:: KEEP_ORIG_ADDR IPAddrAnonymization

      .. bro:enum:: SEQUENTIALLY_NUMBERED IPAddrAnonymization

      .. bro:enum:: RANDOM_MD5 IPAddrAnonymization

      .. bro:enum:: PREFIX_PRESERVING_A50 IPAddrAnonymization

      .. bro:enum:: PREFIX_PRESERVING_MD5 IPAddrAnonymization

   Deprecated.
   
   .. bro:see:: anonymize_addr

.. bro:type:: IPAddrAnonymizationClass

   :Type: :bro:type:`enum`

      .. bro:enum:: ORIG_ADDR IPAddrAnonymizationClass

      .. bro:enum:: RESP_ADDR IPAddrAnonymizationClass

      .. bro:enum:: OTHER_ADDR IPAddrAnonymizationClass

   Deprecated.
   
   .. bro:see:: anonymize_addr

.. bro:type:: JSON::TimestampFormat

   :Type: :bro:type:`enum`

      .. bro:enum:: JSON::TS_EPOCH JSON::TimestampFormat

         Timestamps will be formatted as UNIX epoch doubles.  This is
         the format that Bro typically writes out timestamps.

      .. bro:enum:: JSON::TS_MILLIS JSON::TimestampFormat

         Timestamps will be formatted as unsigned integers that
         represent the number of milliseconds since the UNIX
         epoch.

      .. bro:enum:: JSON::TS_ISO8601 JSON::TimestampFormat

         Timestamps will be formatted in the ISO8601 DateTime format.
         Subseconds are also included which isn't actually part of the
         standard but most consumers that parse ISO8601 seem to be able
         to cope with that.


.. bro:type:: KRB::AP_Options

   :Type: :bro:type:`record`

      use_session_key: :bro:type:`bool`
         Indicates that user-to-user-authentication is in use

      mutual_required: :bro:type:`bool`
         Mutual authentication is required

   AP Options. See :rfc:`4120`

.. bro:type:: KRB::Error_Msg

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :bro:type:`count`
         The message type (30 for ERROR_MSG)

      client_time: :bro:type:`time` :bro:attr:`&optional`
         Current time on the client

      server_time: :bro:type:`time`
         Current time on the server

      error_code: :bro:type:`count`
         The specific error code

      client_realm: :bro:type:`string` :bro:attr:`&optional`
         Realm of the ticket

      client_name: :bro:type:`string` :bro:attr:`&optional`
         Name on the ticket

      service_realm: :bro:type:`string`
         Realm of the service

      service_name: :bro:type:`string`
         Name of the service

      error_text: :bro:type:`string` :bro:attr:`&optional`
         Additional text to explain the error

      pa_data: :bro:type:`vector` of :bro:type:`KRB::Type_Value` :bro:attr:`&optional`
         Optional pre-authentication data

   The data from the ERROR_MSG message. See :rfc:`4120`.

.. bro:type:: KRB::Host_Address

   :Type: :bro:type:`record`

      ip: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         IPv4 or IPv6 address

      netbios: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         NetBIOS address

      unknown: :bro:type:`KRB::Type_Value` :bro:attr:`&optional`
         Some other type that we don't support yet

   A Kerberos host address See :rfc:`4120`.

.. bro:type:: KRB::Host_Address_Vector

   :Type: :bro:type:`vector` of :bro:type:`KRB::Host_Address`


.. bro:type:: KRB::KDC_Options

   :Type: :bro:type:`record`

      forwardable: :bro:type:`bool`
         The ticket to be issued should have its forwardable flag set.

      forwarded: :bro:type:`bool`
         A (TGT) request for forwarding.

      proxiable: :bro:type:`bool`
         The ticket to be issued should have its proxiable flag set.

      proxy: :bro:type:`bool`
         A request for a proxy.

      allow_postdate: :bro:type:`bool`
         The ticket to be issued should have its may-postdate flag set.

      postdated: :bro:type:`bool`
         A request for a postdated ticket.

      renewable: :bro:type:`bool`
         The ticket to be issued should have its renewable  flag set.

      opt_hardware_auth: :bro:type:`bool`
         Reserved for opt_hardware_auth

      disable_transited_check: :bro:type:`bool`
         Request that the KDC not check the transited field of a TGT against
         the policy of the local realm before it will issue derivative tickets
         based on the TGT.

      renewable_ok: :bro:type:`bool`
         If a ticket with the requested lifetime cannot be issued, a renewable
         ticket is acceptable

      enc_tkt_in_skey: :bro:type:`bool`
         The ticket for the end server is to be encrypted in the session key
         from the additional TGT provided

      renew: :bro:type:`bool`
         The request is for a renewal

      validate: :bro:type:`bool`
         The request is to validate a postdated ticket.

   KDC Options. See :rfc:`4120`

.. bro:type:: KRB::KDC_Request

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :bro:type:`count`
         The message type (10 for AS_REQ, 12 for TGS_REQ)

      pa_data: :bro:type:`vector` of :bro:type:`KRB::Type_Value` :bro:attr:`&optional`
         Optional pre-authentication data

      kdc_options: :bro:type:`KRB::KDC_Options`
         Options specified in the request

      client_name: :bro:type:`string` :bro:attr:`&optional`
         Name on the ticket

      service_realm: :bro:type:`string`
         Realm of the service

      service_name: :bro:type:`string` :bro:attr:`&optional`
         Name of the service

      from: :bro:type:`time` :bro:attr:`&optional`
         Time the ticket is good from

      till: :bro:type:`time`
         Time the ticket is good till

      rtime: :bro:type:`time` :bro:attr:`&optional`
         The requested renew-till time

      nonce: :bro:type:`count`
         A random nonce generated by the client

      encryption_types: :bro:type:`vector` of :bro:type:`count`
         The desired encryption algorithms, in order of preference

      host_addrs: :bro:type:`vector` of :bro:type:`KRB::Host_Address` :bro:attr:`&optional`
         Any additional addresses the ticket should be valid for

      additional_tickets: :bro:type:`vector` of :bro:type:`KRB::Ticket` :bro:attr:`&optional`
         Additional tickets may be included for certain transactions

   The data from the AS_REQ and TGS_REQ messages. See :rfc:`4120`.

.. bro:type:: KRB::KDC_Response

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :bro:type:`count`
         The message type (11 for AS_REP, 13 for TGS_REP)

      pa_data: :bro:type:`vector` of :bro:type:`KRB::Type_Value` :bro:attr:`&optional`
         Optional pre-authentication data

      client_realm: :bro:type:`string` :bro:attr:`&optional`
         Realm on the ticket

      client_name: :bro:type:`string`
         Name on the service

      ticket: :bro:type:`KRB::Ticket`
         The ticket that was issued

   The data from the AS_REQ and TGS_REQ messages. See :rfc:`4120`.

.. bro:type:: KRB::SAFE_Msg

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :bro:type:`count`
         The message type (20 for SAFE_MSG)

      data: :bro:type:`string`
         The application-specific data that is being passed
         from the sender to the reciever

      timestamp: :bro:type:`time` :bro:attr:`&optional`
         Current time from the sender of the message

      seq: :bro:type:`count` :bro:attr:`&optional`
         Sequence number used to detect replays

      sender: :bro:type:`KRB::Host_Address` :bro:attr:`&optional`
         Sender address

      recipient: :bro:type:`KRB::Host_Address` :bro:attr:`&optional`
         Recipient address

   The data from the SAFE message. See :rfc:`4120`.

.. bro:type:: KRB::Ticket

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      realm: :bro:type:`string`
         Realm

      service_name: :bro:type:`string`
         Name of the service

      cipher: :bro:type:`count`
         Cipher the ticket was encrypted with

      ciphertext: :bro:type:`string` :bro:attr:`&optional`
         Cipher text of the ticket

      authenticationinfo: :bro:type:`string` :bro:attr:`&optional`
         Authentication info

   A Kerberos ticket. See :rfc:`4120`.

.. bro:type:: KRB::Ticket_Vector

   :Type: :bro:type:`vector` of :bro:type:`KRB::Ticket`


.. bro:type:: KRB::Type_Value

   :Type: :bro:type:`record`

      data_type: :bro:type:`count`
         The data type

      val: :bro:type:`string`
         The data value

   Used in a few places in the Kerberos analyzer for elements
   that have a type and a string value.

.. bro:type:: KRB::Type_Value_Vector

   :Type: :bro:type:`vector` of :bro:type:`KRB::Type_Value`


.. bro:type:: MOUNT3::dirmntargs_t

   :Type: :bro:type:`record`

      dirname: :bro:type:`string`
         Name of directory to mount

   MOUNT *mnt* arguments.
   
   .. bro:see:: mount_proc_mnt

.. bro:type:: MOUNT3::info_t

   :Type: :bro:type:`record`

      rpc_stat: :bro:type:`rpc_status`
         The RPC status.

      mnt_stat: :bro:type:`MOUNT3::status_t`
         The MOUNT status.

      req_start: :bro:type:`time`
         The start time of the request.

      req_dur: :bro:type:`interval`
         The duration of the request.

      req_len: :bro:type:`count`
         The length in bytes of the request.

      rep_start: :bro:type:`time`
         The start time of the reply.

      rep_dur: :bro:type:`interval`
         The duration of the reply.

      rep_len: :bro:type:`count`
         The length in bytes of the reply.

      rpc_uid: :bro:type:`count`
         The user id of the reply.

      rpc_gid: :bro:type:`count`
         The group id of the reply.

      rpc_stamp: :bro:type:`count`
         The stamp of the reply.

      rpc_machine_name: :bro:type:`string`
         The machine name of the reply.

      rpc_auxgids: :bro:type:`index_vec`
         The auxiliary ids of the reply.

   Record summarizing the general results and status of MOUNT3
   request/reply pairs.
   
   Note that when *rpc_stat* or *mount_stat* indicates not successful,
   the reply record passed to the corresponding event will be empty and
   contain uninitialized fields, so don't use it. Also note that time

.. bro:type:: MOUNT3::mnt_reply_t

   :Type: :bro:type:`record`

      dirfh: :bro:type:`string` :bro:attr:`&optional`
         Dir handle

      auth_flavors: :bro:type:`vector` of :bro:type:`MOUNT3::auth_flavor_t` :bro:attr:`&optional`
         Returned authentication flavors

   MOUNT lookup reply. If the mount failed, *dir_attr* may be set. If the
   mount succeeded, *fh* is always set.
   
   .. bro:see:: mount_proc_mnt

.. bro:type:: MatcherStats

   :Type: :bro:type:`record`

      matchers: :bro:type:`count`
         Number of distinct RE matchers.

      nfa_states: :bro:type:`count`
         Number of NFA states across all matchers.

      dfa_states: :bro:type:`count`
         Number of DFA states across all matchers.

      computed: :bro:type:`count`
         Number of computed DFA state transitions.

      mem: :bro:type:`count`
         Number of bytes used by DFA states.

      hits: :bro:type:`count`
         Number of cache hits.

      misses: :bro:type:`count`
         Number of cache misses.

   Statistics of all regular expression matchers.
   
   .. bro:see:: get_matcher_stats

.. bro:type:: ModbusCoils

   :Type: :bro:type:`vector` of :bro:type:`bool`

   A vector of boolean values that indicate the setting
   for a range of modbus coils.

.. bro:type:: ModbusHeaders

   :Type: :bro:type:`record`

      tid: :bro:type:`count`
         Transaction identifier

      pid: :bro:type:`count`
         Protocol identifier

      uid: :bro:type:`count`
         Unit identifier (previously 'slave address')

      function_code: :bro:type:`count`
         MODBUS function code


.. bro:type:: ModbusRegisters

   :Type: :bro:type:`vector` of :bro:type:`count`

   A vector of count values that represent 16bit modbus 
   register values.

.. bro:type:: NFS3::delobj_reply_t

   :Type: :bro:type:`record`

      dir_pre_attr: :bro:type:`NFS3::wcc_attr_t` :bro:attr:`&optional`
         Optional attributes associated w/ dir.

      dir_post_attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Optional attributes associated w/ dir.

   NFS reply for *remove*, *rmdir*. Corresponds to *wcc_data* in the spec.
   
   .. bro:see:: nfs_proc_remove nfs_proc_rmdir

.. bro:type:: NFS3::direntry_t

   :Type: :bro:type:`record`

      fileid: :bro:type:`count`
         E.g., inode number.

      fname: :bro:type:`string`
         Filename.

      cookie: :bro:type:`count`
         Cookie value.

      attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         *readdirplus*: the *fh* attributes for the entry.

      fh: :bro:type:`string` :bro:attr:`&optional`
         *readdirplus*: the *fh* for the entry

   NFS *direntry*.  *fh* and *attr* are used for *readdirplus*. However,
   even for *readdirplus* they may not be filled out.
   
   .. bro:see:: NFS3::direntry_vec_t NFS3::readdir_reply_t

.. bro:type:: NFS3::direntry_vec_t

   :Type: :bro:type:`vector` of :bro:type:`NFS3::direntry_t`

   Vector of NFS *direntry*.
   
   .. bro:see:: NFS3::readdir_reply_t

.. bro:type:: NFS3::diropargs_t

   :Type: :bro:type:`record`

      dirfh: :bro:type:`string`
         The file handle of the directory.

      fname: :bro:type:`string`
         The name of the file we are interested in.

   NFS *readdir* arguments.
   
   .. bro:see:: nfs_proc_readdir

.. bro:type:: NFS3::fattr_t

   :Type: :bro:type:`record`

      ftype: :bro:type:`NFS3::file_type_t`
         File type.

      mode: :bro:type:`count`
         Mode

      nlink: :bro:type:`count`
         Number of links.

      uid: :bro:type:`count`
         User ID.

      gid: :bro:type:`count`
         Group ID.

      size: :bro:type:`count`
         Size.

      used: :bro:type:`count`
         TODO.

      rdev1: :bro:type:`count`
         TODO.

      rdev2: :bro:type:`count`
         TODO.

      fsid: :bro:type:`count`
         TODO.

      fileid: :bro:type:`count`
         TODO.

      atime: :bro:type:`time`
         Time of last access.

      mtime: :bro:type:`time`
         Time of last modification.

      ctime: :bro:type:`time`
         Time of creation.

   NFS file attributes. Field names are based on RFC 1813.
   
   .. bro:see:: nfs_proc_getattr

.. bro:type:: NFS3::fsstat_t

   :Type: :bro:type:`record`

      attrs: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Attributes.

      tbytes: :bro:type:`double`
         TODO.

      fbytes: :bro:type:`double`
         TODO.

      abytes: :bro:type:`double`
         TODO.

      tfiles: :bro:type:`double`
         TODO.

      ffiles: :bro:type:`double`
         TODO.

      afiles: :bro:type:`double`
         TODO.

      invarsec: :bro:type:`interval`
         TODO.

   NFS *fsstat*.

.. bro:type:: NFS3::info_t

   :Type: :bro:type:`record`

      rpc_stat: :bro:type:`rpc_status`
         The RPC status.

      nfs_stat: :bro:type:`NFS3::status_t`
         The NFS status.

      req_start: :bro:type:`time`
         The start time of the request.

      req_dur: :bro:type:`interval`
         The duration of the request.

      req_len: :bro:type:`count`
         The length in bytes of the request.

      rep_start: :bro:type:`time`
         The start time of the reply.

      rep_dur: :bro:type:`interval`
         The duration of the reply.

      rep_len: :bro:type:`count`
         The length in bytes of the reply.

      rpc_uid: :bro:type:`count`
         The user id of the reply.

      rpc_gid: :bro:type:`count`
         The group id of the reply.

      rpc_stamp: :bro:type:`count`
         The stamp of the reply.

      rpc_machine_name: :bro:type:`string`
         The machine name of the reply.

      rpc_auxgids: :bro:type:`index_vec`
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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup
      nfs_proc_mkdir nfs_proc_not_implemented nfs_proc_null
      nfs_proc_read nfs_proc_readdir nfs_proc_readlink nfs_proc_remove
      nfs_proc_rmdir nfs_proc_write nfs_reply_status

.. bro:type:: NFS3::link_reply_t

   :Type: :bro:type:`record`

      post_attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Optional post-operation attributes of the file system object identified by file

      preattr: :bro:type:`NFS3::wcc_attr_t` :bro:attr:`&optional`
         Optional attributes associated w/ file.

      postattr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Optional attributes associated w/ file.

   NFS *link* reply.
   
   .. bro:see:: nfs_proc_link

.. bro:type:: NFS3::linkargs_t

   :Type: :bro:type:`record`

      fh: :bro:type:`string`
         The file handle for the existing file system object.

      link: :bro:type:`NFS3::diropargs_t`
         The location of the link to be created.

   NFS *link* arguments.
   
   .. bro:see:: nfs_proc_link

.. bro:type:: NFS3::lookup_reply_t

   :Type: :bro:type:`record`

      fh: :bro:type:`string` :bro:attr:`&optional`
         File handle of object looked up.

      obj_attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Optional attributes associated w/ file

      dir_attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Optional attributes associated w/ dir.

   NFS lookup reply. If the lookup failed, *dir_attr* may be set. If the
   lookup succeeded, *fh* is always set and *obj_attr* and *dir_attr*
   may be set.
   
   .. bro:see:: nfs_proc_lookup

.. bro:type:: NFS3::newobj_reply_t

   :Type: :bro:type:`record`

      fh: :bro:type:`string` :bro:attr:`&optional`
         File handle of object created.

      obj_attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Optional attributes associated w/ new object.

      dir_pre_attr: :bro:type:`NFS3::wcc_attr_t` :bro:attr:`&optional`
         Optional attributes associated w/ dir.

      dir_post_attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Optional attributes associated w/ dir.

   NFS reply for *create*, *mkdir*, and *symlink*. If the proc
   failed, *dir_\*_attr* may be set. If the proc succeeded, *fh* and the
   *attr*'s may be set. Note: no guarantee that *fh* is set after
   success.
   
   .. bro:see:: nfs_proc_create nfs_proc_mkdir

.. bro:type:: NFS3::read_reply_t

   :Type: :bro:type:`record`

      attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Attributes.

      size: :bro:type:`count` :bro:attr:`&optional`
         Number of bytes read.

      eof: :bro:type:`bool` :bro:attr:`&optional`
         Sid the read end at EOF.

      data: :bro:type:`string` :bro:attr:`&optional`
         The actual data; not yet implemented.

   NFS *read* reply. If the lookup fails, *attr* may be set. If the
   lookup succeeds, *attr* may be set and all other fields are set.

.. bro:type:: NFS3::readargs_t

   :Type: :bro:type:`record`

      fh: :bro:type:`string`
         File handle to read from.

      offset: :bro:type:`count`
         Offset in file.

      size: :bro:type:`count`
         Number of bytes to read.

   NFS *read* arguments.
   
   .. bro:see:: nfs_proc_read

.. bro:type:: NFS3::readdir_reply_t

   :Type: :bro:type:`record`

      isplus: :bro:type:`bool`
         True if the reply for a *readdirplus* request.

      dir_attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Directory attributes.

      cookieverf: :bro:type:`count` :bro:attr:`&optional`
         TODO.

      entries: :bro:type:`NFS3::direntry_vec_t` :bro:attr:`&optional`
         Returned directory entries.

      eof: :bro:type:`bool`
         If true, no more entries in directory.

   NFS *readdir* reply. Used for *readdir* and *readdirplus*. If an is
   returned, *dir_attr* might be set. On success, *dir_attr* may be set,
   all others must be set.

.. bro:type:: NFS3::readdirargs_t

   :Type: :bro:type:`record`

      isplus: :bro:type:`bool`
         Is this a readdirplus request?

      dirfh: :bro:type:`string`
         The directory filehandle.

      cookie: :bro:type:`count`
         Cookie / pos in dir; 0 for first call.

      cookieverf: :bro:type:`count`
         The cookie verifier.

      dircount: :bro:type:`count`
         "count" field for readdir; maxcount otherwise (in bytes).

      maxcount: :bro:type:`count` :bro:attr:`&optional`
         Only used for readdirplus. in bytes.

   NFS *readdir* arguments. Used for both *readdir* and *readdirplus*.
   
   .. bro:see:: nfs_proc_readdir

.. bro:type:: NFS3::readlink_reply_t

   :Type: :bro:type:`record`

      attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Attributes.

      nfspath: :bro:type:`string` :bro:attr:`&optional`
         Contents of the symlink; in general a pathname as text.

   NFS *readline* reply. If the request fails, *attr* may be set. If the
   request succeeds, *attr* may be set and all other fields are set.
   
   .. bro:see:: nfs_proc_readlink

.. bro:type:: NFS3::renameobj_reply_t

   :Type: :bro:type:`record`

      src_dir_pre_attr: :bro:type:`NFS3::wcc_attr_t`

      src_dir_post_attr: :bro:type:`NFS3::fattr_t`

      dst_dir_pre_attr: :bro:type:`NFS3::wcc_attr_t`

      dst_dir_post_attr: :bro:type:`NFS3::fattr_t`

   NFS reply for *rename*. Corresponds to *wcc_data* in the spec.
   
   .. bro:see:: nfs_proc_rename

.. bro:type:: NFS3::renameopargs_t

   :Type: :bro:type:`record`

      src_dirfh: :bro:type:`string`

      src_fname: :bro:type:`string`

      dst_dirfh: :bro:type:`string`

      dst_fname: :bro:type:`string`

   NFS *rename* arguments.
   
   .. bro:see:: nfs_proc_rename

.. bro:type:: NFS3::sattr_reply_t

   :Type: :bro:type:`record`

      dir_pre_attr: :bro:type:`NFS3::wcc_attr_t` :bro:attr:`&optional`
         Optional attributes associated w/ dir.

      dir_post_attr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Optional attributes associated w/ dir.

   NFS *sattr* reply. If the request fails, *pre|post* attr may be set.
   If the request succeeds, *pre|post* attr are set.
   

.. bro:type:: NFS3::sattr_t

   :Type: :bro:type:`record`

      mode: :bro:type:`count` :bro:attr:`&optional`
         Mode

      uid: :bro:type:`count` :bro:attr:`&optional`
         User ID.

      gid: :bro:type:`count` :bro:attr:`&optional`
         Group ID.

      size: :bro:type:`count` :bro:attr:`&optional`
         Size.

      atime: :bro:type:`NFS3::time_how_t` :bro:attr:`&optional`
         Time of last access.

      mtime: :bro:type:`NFS3::time_how_t` :bro:attr:`&optional`
         Time of last modification.

   NFS file attributes. Field names are based on RFC 1813.
   
   .. bro:see:: nfs_proc_sattr

.. bro:type:: NFS3::sattrargs_t

   :Type: :bro:type:`record`

      fh: :bro:type:`string`
         The file handle for the existing file system object.

      new_attributes: :bro:type:`NFS3::sattr_t`
         The new attributes for the file.

   NFS *sattr* arguments.
   
   .. bro:see:: nfs_proc_sattr

.. bro:type:: NFS3::symlinkargs_t

   :Type: :bro:type:`record`

      link: :bro:type:`NFS3::diropargs_t`
         The location of the link to be created.

      symlinkdata: :bro:type:`NFS3::symlinkdata_t`
         The symbolic link to be created.

   NFS *symlink* arguments.
   
   .. bro:see:: nfs_proc_symlink

.. bro:type:: NFS3::symlinkdata_t

   :Type: :bro:type:`record`

      symlink_attributes: :bro:type:`NFS3::sattr_t`
         The initial attributes for the symbolic link

      nfspath: :bro:type:`string` :bro:attr:`&optional`
         The string containing the symbolic link data.

   NFS symlinkdata attributes. Field names are based on RFC 1813
   
   .. bro:see:: nfs_proc_symlink

.. bro:type:: NFS3::wcc_attr_t

   :Type: :bro:type:`record`

      size: :bro:type:`count`
         The size.

      atime: :bro:type:`time`
         Access time.

      mtime: :bro:type:`time`
         Modification time.

   NFS *wcc* attributes.
   
   .. bro:see:: NFS3::write_reply_t

.. bro:type:: NFS3::write_reply_t

   :Type: :bro:type:`record`

      preattr: :bro:type:`NFS3::wcc_attr_t` :bro:attr:`&optional`
         Pre operation attributes.

      postattr: :bro:type:`NFS3::fattr_t` :bro:attr:`&optional`
         Post operation attributes.

      size: :bro:type:`count` :bro:attr:`&optional`
         Size.

      commited: :bro:type:`NFS3::stable_how_t` :bro:attr:`&optional`
         TODO.

      verf: :bro:type:`count` :bro:attr:`&optional`
         Write verifier cookie.

   NFS *write* reply. If the request fails, *pre|post* attr may be set.
   If the request succeeds, *pre|post* attr may be set and all other
   fields are set.
   
   .. bro:see:: nfs_proc_write

.. bro:type:: NFS3::writeargs_t

   :Type: :bro:type:`record`

      fh: :bro:type:`string`
         File handle to write to.

      offset: :bro:type:`count`
         Offset in file.

      size: :bro:type:`count`
         Number of bytes to write.

      stable: :bro:type:`NFS3::stable_how_t`
         How and when data is commited.

      data: :bro:type:`string` :bro:attr:`&optional`
         The actual data; not implemented yet.

   NFS *write* arguments.
   
   .. bro:see:: nfs_proc_write

.. bro:type:: NTLM::AVs

   :Type: :bro:type:`record`

      nb_computer_name: :bro:type:`string`
         The server's NetBIOS computer name

      nb_domain_name: :bro:type:`string`
         The server's NetBIOS domain name

      dns_computer_name: :bro:type:`string` :bro:attr:`&optional`
         The FQDN of the computer

      dns_domain_name: :bro:type:`string` :bro:attr:`&optional`
         The FQDN of the domain

      dns_tree_name: :bro:type:`string` :bro:attr:`&optional`
         The FQDN of the forest

      constrained_auth: :bro:type:`bool` :bro:attr:`&optional`
         Indicates to the client that the account
         authentication is constrained

      timestamp: :bro:type:`time` :bro:attr:`&optional`
         The associated timestamp, if present

      single_host_id: :bro:type:`count` :bro:attr:`&optional`
         Indicates that the client is providing
         a machine ID created at computer startup to
         identify the calling machine

      target_name: :bro:type:`string` :bro:attr:`&optional`
         The SPN of the target server


.. bro:type:: NTLM::Authenticate

   :Type: :bro:type:`record`

      flags: :bro:type:`NTLM::NegotiateFlags`
         The negotiate flags

      domain_name: :bro:type:`string` :bro:attr:`&optional`
         The domain or computer name hosting the account

      user_name: :bro:type:`string` :bro:attr:`&optional`
         The name of the user to be authenticated.

      workstation: :bro:type:`string` :bro:attr:`&optional`
         The name of the computer to which the user was logged on.

      session_key: :bro:type:`string` :bro:attr:`&optional`
         The session key

      version: :bro:type:`NTLM::Version` :bro:attr:`&optional`
         The Windows version information, if supplied


.. bro:type:: NTLM::Challenge

   :Type: :bro:type:`record`

      flags: :bro:type:`NTLM::NegotiateFlags`
         The negotiate flags

      target_name: :bro:type:`string` :bro:attr:`&optional`
         The server authentication realm. If the server is
         domain-joined, the name of the domain. Otherwise
         the server name. See flags.target_type_domain
         and flags.target_type_server

      version: :bro:type:`NTLM::Version` :bro:attr:`&optional`
         The Windows version information, if supplied

      target_info: :bro:type:`NTLM::AVs` :bro:attr:`&optional`
         Attribute-value pairs specified by the server


.. bro:type:: NTLM::Negotiate

   :Type: :bro:type:`record`

      flags: :bro:type:`NTLM::NegotiateFlags`
         The negotiate flags

      domain_name: :bro:type:`string` :bro:attr:`&optional`
         The domain name of the client, if known

      workstation: :bro:type:`string` :bro:attr:`&optional`
         The machine name of the client, if known

      version: :bro:type:`NTLM::Version` :bro:attr:`&optional`
         The Windows version information, if supplied


.. bro:type:: NTLM::NegotiateFlags

   :Type: :bro:type:`record`

      negotiate_56: :bro:type:`bool`
         If set, requires 56-bit encryption

      negotiate_key_exch: :bro:type:`bool`
         If set, requests an explicit key exchange

      negotiate_128: :bro:type:`bool`
         If set, requests 128-bit session key negotiation

      negotiate_version: :bro:type:`bool`
         If set, requests the protocol version number

      negotiate_target_info: :bro:type:`bool`
         If set, indicates that the TargetInfo fields in the
         CHALLENGE_MESSAGE are populated

      request_non_nt_session_key: :bro:type:`bool`
         If set, requests the usage of the LMOWF function

      negotiate_identify: :bro:type:`bool`
         If set, requests and identify level token

      negotiate_extended_sessionsecurity: :bro:type:`bool`
         If set, requests usage of NTLM v2 session security
         Note: NTML v2 session security is actually NTLM v1

      target_type_server: :bro:type:`bool`
         If set, TargetName must be a server name

      target_type_domain: :bro:type:`bool`
         If set, TargetName must be a domain name

      negotiate_always_sign: :bro:type:`bool`
         If set, requests the presence of a signature block
         on all messages

      negotiate_oem_workstation_supplied: :bro:type:`bool`
         If set, the workstation name is provided

      negotiate_oem_domain_supplied: :bro:type:`bool`
         If set, the domain name is provided

      negotiate_anonymous_connection: :bro:type:`bool`
         If set, the connection should be anonymous

      negotiate_ntlm: :bro:type:`bool`
         If set, requests usage of NTLM v1

      negotiate_lm_key: :bro:type:`bool`
         If set, requests LAN Manager session key computation

      negotiate_datagram: :bro:type:`bool`
         If set, requests connectionless authentication

      negotiate_seal: :bro:type:`bool`
         If set, requests session key negotiation for message 
         confidentiality

      negotiate_sign: :bro:type:`bool`
         If set, requests session key negotiation for message
         signatures

      request_target: :bro:type:`bool`
         If set, the TargetName field is present

      negotiate_oem: :bro:type:`bool`
         If set, requests OEM character set encoding

      negotiate_unicode: :bro:type:`bool`
         If set, requests Unicode character set encoding


.. bro:type:: NTLM::Version

   :Type: :bro:type:`record`

      major: :bro:type:`count`
         The major version of the Windows operating system in use

      minor: :bro:type:`count`
         The minor version of the Windows operating system in use

      build: :bro:type:`count`
         The build number of the Windows operating system in use

      ntlmssp: :bro:type:`count`
         The current revision of NTLMSSP in use


.. bro:type:: NetStats

   :Type: :bro:type:`record`

      pkts_recvd: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Packets received by Bro.

      pkts_dropped: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Packets reported dropped by the system.

      pkts_link: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Packets seen on the link. Note that this may differ
         from *pkts_recvd* because of a potential capture_filter. See
         :doc:`/scripts/base/frameworks/packet-filter/main.bro`. Depending on the
         packet capture system, this value may not be available and will then
         be always set to zero.

      bytes_recvd: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Bytes received by Bro.

   Packet capture statistics.  All counts are cumulative.
   
   .. bro:see:: get_net_stats

.. bro:type:: OS_version

   :Type: :bro:type:`record`

      genre: :bro:type:`string`
         Linux, Windows, AIX, ...

      detail: :bro:type:`string`
         Kernel version or such.

      dist: :bro:type:`count`
         How far is the host away from the sensor (TTL)?.

      match_type: :bro:type:`OS_version_inference`
         Quality of the match.

   Passive fingerprinting match.
   
   .. bro:see:: OS_version_found

.. bro:type:: OS_version_inference

   :Type: :bro:type:`enum`

      .. bro:enum:: direct_inference OS_version_inference

         TODO.

      .. bro:enum:: generic_inference OS_version_inference

         TODO.

      .. bro:enum:: fuzzy_inference OS_version_inference

         TODO.

   Quality of passive fingerprinting matches.
   
   .. bro:see:: OS_version

.. bro:type:: PE::DOSHeader

   :Type: :bro:type:`record`

      signature: :bro:type:`string`
         The magic number of a portable executable file ("MZ").

      used_bytes_in_last_page: :bro:type:`count`
         The number of bytes in the last page that are used.

      file_in_pages: :bro:type:`count`
         The number of pages in the file that are part of the PE file itself.

      num_reloc_items: :bro:type:`count`
         Number of relocation entries stored after the header.

      header_in_paragraphs: :bro:type:`count`
         Number of paragraphs in the header.

      min_extra_paragraphs: :bro:type:`count`
         Number of paragraps of additional memory that the program will need.

      max_extra_paragraphs: :bro:type:`count`
         Maximum number of paragraphs of additional memory.

      init_relative_ss: :bro:type:`count`
         Relative value of the stack segment.

      init_sp: :bro:type:`count`
         Initial value of the SP register.

      checksum: :bro:type:`count`
         Checksum. The 16-bit sum of all words in the file should be 0. Normally not set.

      init_ip: :bro:type:`count`
         Initial value of the IP register.

      init_relative_cs: :bro:type:`count`
         Initial value of the CS register (relative to the initial segment).

      addr_of_reloc_table: :bro:type:`count`
         Offset of the first relocation table.

      overlay_num: :bro:type:`count`
         Overlays allow you to append data to the end of the file. If this is the main program,
         this will be 0.

      oem_id: :bro:type:`count`
         OEM identifier.

      oem_info: :bro:type:`count`
         Additional OEM info, specific to oem_id.

      addr_of_new_exe_header: :bro:type:`count`
         Address of the new EXE header.


.. bro:type:: PE::FileHeader

   :Type: :bro:type:`record`

      machine: :bro:type:`count`
         The target machine that the file was compiled for.

      ts: :bro:type:`time`
         The time that the file was created at.

      sym_table_ptr: :bro:type:`count`
         Pointer to the symbol table.

      num_syms: :bro:type:`count`
         Number of symbols.

      optional_header_size: :bro:type:`count`
         The size of the optional header.

      characteristics: :bro:type:`set` [:bro:type:`count`]
         Bit flags that determine if this file is executable, non-relocatable, and/or a DLL.


.. bro:type:: PE::OptionalHeader

   :Type: :bro:type:`record`

      magic: :bro:type:`count`
         PE32 or PE32+ indicator.

      major_linker_version: :bro:type:`count`
         The major version of the linker used to create the PE.

      minor_linker_version: :bro:type:`count`
         The minor version of the linker used to create the PE.

      size_of_code: :bro:type:`count`
         Size of the .text section.

      size_of_init_data: :bro:type:`count`
         Size of the .data section.

      size_of_uninit_data: :bro:type:`count`
         Size of the .bss section.

      addr_of_entry_point: :bro:type:`count`
         The relative virtual address (RVA) of the entry point.

      base_of_code: :bro:type:`count`
         The relative virtual address (RVA) of the .text section.

      base_of_data: :bro:type:`count` :bro:attr:`&optional`
         The relative virtual address (RVA) of the .data section.

      image_base: :bro:type:`count`
         Preferred memory location for the image to be based at.

      section_alignment: :bro:type:`count`
         The alignment (in bytes) of sections when they're loaded in memory.

      file_alignment: :bro:type:`count`
         The alignment (in bytes) of the raw data of sections.

      os_version_major: :bro:type:`count`
         The major version of the required OS.

      os_version_minor: :bro:type:`count`
         The minor version of the required OS.

      major_image_version: :bro:type:`count`
         The major version of this image.

      minor_image_version: :bro:type:`count`
         The minor version of this image.

      major_subsys_version: :bro:type:`count`
         The major version of the subsystem required to run this file.

      minor_subsys_version: :bro:type:`count`
         The minor version of the subsystem required to run this file.

      size_of_image: :bro:type:`count`
         The size (in bytes) of the iamge as the image is loaded in memory.

      size_of_headers: :bro:type:`count`
         The size (in bytes) of the headers, rounded up to file_alignment.

      checksum: :bro:type:`count`
         The image file checksum.

      subsystem: :bro:type:`count`
         The subsystem that's required to run this image.

      dll_characteristics: :bro:type:`set` [:bro:type:`count`]
         Bit flags that determine how to execute or load this file.

      table_sizes: :bro:type:`vector` of :bro:type:`count`
         A vector with the sizes of various tables and strings that are
         defined in the optional header data directories. Examples include
         the import table, the resource table, and debug information.


.. bro:type:: PE::SectionHeader

   :Type: :bro:type:`record`

      name: :bro:type:`string`
         The name of the section

      virtual_size: :bro:type:`count`
         The total size of the section when loaded into memory.

      virtual_addr: :bro:type:`count`
         The relative virtual address (RVA) of the section.

      size_of_raw_data: :bro:type:`count`
         The size of the initialized data for the section, as it is
         in the file on disk.

      ptr_to_raw_data: :bro:type:`count`
         The virtual address of the initialized dat for the section,
         as it is in the file on disk.

      ptr_to_relocs: :bro:type:`count`
         The file pointer to the beginning of relocation entries for
         the section.

      ptr_to_line_nums: :bro:type:`count`
         The file pointer to the beginning of line-number entries for
         the section.

      num_of_relocs: :bro:type:`count`
         The number of relocation entries for the section.

      num_of_line_nums: :bro:type:`count`
         The number of line-number entrie for the section.

      characteristics: :bro:type:`set` [:bro:type:`count`]
         Bit-flags that describe the characteristics of the section.

   Record for Portable Executable (PE) section headers.

.. bro:type:: PcapFilterID

   :Type: :bro:type:`enum`

      .. bro:enum:: None PcapFilterID

      .. bro:enum:: PacketFilter::DefaultPcapFilter PcapFilterID

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.bro` is loaded)


      .. bro:enum:: PacketFilter::FilterTester PcapFilterID

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.bro` is loaded)


   Enum type identifying dynamic BPF filters. These are used by
   :bro:see:`Pcap::precompile_pcap_filter` and :bro:see:`Pcap::precompile_pcap_filter`.

.. bro:type:: ProcStats

   :Type: :bro:type:`record`

      debug: :bro:type:`bool`
         True if compiled with --enable-debug.

      start_time: :bro:type:`time`
         Start time of process.

      real_time: :bro:type:`interval`
         Elapsed real time since Bro started running.

      user_time: :bro:type:`interval`
         User CPU seconds.

      system_time: :bro:type:`interval`
         System CPU seconds.

      mem: :bro:type:`count`
         Maximum memory consumed, in KB.

      minor_faults: :bro:type:`count`
         Page faults not requiring actual I/O.

      major_faults: :bro:type:`count`
         Page faults requiring actual I/O.

      num_swap: :bro:type:`count`
         Times swapped out.

      blocking_input: :bro:type:`count`
         Blocking input operations.

      blocking_output: :bro:type:`count`
         Blocking output operations.

      num_context: :bro:type:`count`
         Number of involuntary context switches.

   Statistics about Bro's process.
   
   .. bro:see:: get_proc_stats
   
   .. note:: All process-level values refer to Bro's main process only, not to
      the child process it spawns for doing communication.

.. bro:type:: RADIUS::AttributeList

   :Type: :bro:type:`vector` of :bro:type:`string`


.. bro:type:: RADIUS::Attributes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`RADIUS::AttributeList`


.. bro:type:: RADIUS::Message

   :Type: :bro:type:`record`

      code: :bro:type:`count`
         The type of message (Access-Request, Access-Accept, etc.).

      trans_id: :bro:type:`count`
         The transaction ID.

      authenticator: :bro:type:`string`
         The "authenticator" string.

      attributes: :bro:type:`RADIUS::Attributes` :bro:attr:`&optional`
         Any attributes.


.. bro:type:: RDP::ClientCoreData

   :Type: :bro:type:`record`

      version_major: :bro:type:`count`

      version_minor: :bro:type:`count`

      desktop_width: :bro:type:`count`

      desktop_height: :bro:type:`count`

      color_depth: :bro:type:`count`

      sas_sequence: :bro:type:`count`

      keyboard_layout: :bro:type:`count`

      client_build: :bro:type:`count`

      client_name: :bro:type:`string`

      keyboard_type: :bro:type:`count`

      keyboard_sub: :bro:type:`count`

      keyboard_function_key: :bro:type:`count`

      ime_file_name: :bro:type:`string`

      post_beta2_color_depth: :bro:type:`count` :bro:attr:`&optional`

      client_product_id: :bro:type:`string` :bro:attr:`&optional`

      serial_number: :bro:type:`count` :bro:attr:`&optional`

      high_color_depth: :bro:type:`count` :bro:attr:`&optional`

      supported_color_depths: :bro:type:`count` :bro:attr:`&optional`

      ec_flags: :bro:type:`RDP::EarlyCapabilityFlags` :bro:attr:`&optional`

      dig_product_id: :bro:type:`string` :bro:attr:`&optional`


.. bro:type:: RDP::EarlyCapabilityFlags

   :Type: :bro:type:`record`

      support_err_info_pdu: :bro:type:`bool`

      want_32bpp_session: :bro:type:`bool`

      support_statusinfo_pdu: :bro:type:`bool`

      strong_asymmetric_keys: :bro:type:`bool`

      support_monitor_layout_pdu: :bro:type:`bool`

      support_netchar_autodetect: :bro:type:`bool`

      support_dynvc_gfx_protocol: :bro:type:`bool`

      support_dynamic_time_zone: :bro:type:`bool`

      support_heartbeat_pdu: :bro:type:`bool`


.. bro:type:: ReassemblerStats

   :Type: :bro:type:`record`

      file_size: :bro:type:`count`
         Byte size of File reassembly tracking.

      frag_size: :bro:type:`count`
         Byte size of Fragment reassembly tracking.

      tcp_size: :bro:type:`count`
         Byte size of TCP reassembly tracking.

      unknown_size: :bro:type:`count`
         Byte size of reassembly tracking for unknown purposes.

   Holds statistics for all types of reassembly.
   
   .. bro:see:: get_reassembler_stats

.. bro:type:: ReporterStats

   :Type: :bro:type:`record`

      weirds: :bro:type:`count`
         Number of total weirds encountered, before any rate-limiting.

      weirds_by_type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`count`
         Number of times each individual weird is encountered, before any
         rate-limiting is applied.

   Statistics about reporter messages and weirds.
   
   .. bro:see:: get_reporter_stats

.. bro:type:: SMB1::Find_First2_Request_Args

   :Type: :bro:type:`record`

      search_attrs: :bro:type:`count`
         File attributes to apply as a constraint to the search

      search_count: :bro:type:`count`
         Max search results

      flags: :bro:type:`count`
         Misc. flags for how the server should manage the transaction
         once results are returned

      info_level: :bro:type:`count`
         How detailed the information returned in the results should be

      search_storage_type: :bro:type:`count`
         Specify whether to search for directories or files

      file_name: :bro:type:`string`
         The string to serch for (note: may contain wildcards)


.. bro:type:: SMB1::Find_First2_Response_Args

   :Type: :bro:type:`record`

      sid: :bro:type:`count`
         The server generated search identifier

      search_count: :bro:type:`count`
         Number of results returned by the search

      end_of_search: :bro:type:`bool`
         Whether or not the search can be continued using
         the TRANS2_FIND_NEXT2 transaction

      ext_attr_error: :bro:type:`string` :bro:attr:`&optional`
         An extended attribute name that couldn't be retrieved


.. bro:type:: SMB1::Header

   :Type: :bro:type:`record`

      command: :bro:type:`count`
         The command number

      status: :bro:type:`count`
         The status code

      flags: :bro:type:`count`
         Flag set 1

      flags2: :bro:type:`count`
         Flag set 2

      tid: :bro:type:`count`
         Tree ID

      pid: :bro:type:`count`
         Process ID

      uid: :bro:type:`count`
         User ID

      mid: :bro:type:`count`
         Multiplex ID

   An SMB1 header.
   
   .. bro:see:: smb1_message smb1_empty_response smb1_error
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

.. bro:type:: SMB1::NegotiateCapabilities

   :Type: :bro:type:`record`

      raw_mode: :bro:type:`bool`
         The server supports SMB_COM_READ_RAW and SMB_COM_WRITE_RAW

      mpx_mode: :bro:type:`bool`
         The server supports SMB_COM_READ_MPX and SMB_COM_WRITE_MPX

      unicode: :bro:type:`bool`
         The server supports unicode strings

      large_files: :bro:type:`bool`
         The server supports large files with 64 bit offsets

      nt_smbs: :bro:type:`bool`
         The server supports the SMBs particilar to the NT LM 0.12 dialect. Implies nt_find.

      rpc_remote_apis: :bro:type:`bool`
         The server supports remote admin API requests via DCE-RPC

      status32: :bro:type:`bool`
         The server can respond with 32 bit status codes in Status.Status

      level_2_oplocks: :bro:type:`bool`
         The server supports level 2 oplocks

      lock_and_read: :bro:type:`bool`
         The server supports SMB_COM_LOCK_AND_READ

      nt_find: :bro:type:`bool`
         Reserved

      dfs: :bro:type:`bool`
         The server is DFS aware

      infolevel_passthru: :bro:type:`bool`
         The server supports NT information level requests passing through

      large_readx: :bro:type:`bool`
         The server supports large SMB_COM_READ_ANDX (up to 64k)

      large_writex: :bro:type:`bool`
         The server supports large SMB_COM_WRITE_ANDX (up to 64k)

      unix: :bro:type:`bool`
         The server supports CIFS Extensions for UNIX

      bulk_transfer: :bro:type:`bool`
         The server supports SMB_BULK_READ, SMB_BULK_WRITE
         Note: No known implementations support this

      compressed_data: :bro:type:`bool`
         The server supports compressed data transfer. Requires bulk_transfer.
         Note: No known implementations support this

      extended_security: :bro:type:`bool`
         The server supports extended security exchanges	


.. bro:type:: SMB1::NegotiateRawMode

   :Type: :bro:type:`record`

      read_raw: :bro:type:`bool`
         Read raw supported

      write_raw: :bro:type:`bool`
         Write raw supported


.. bro:type:: SMB1::NegotiateResponse

   :Type: :bro:type:`record`

      core: :bro:type:`SMB1::NegotiateResponseCore` :bro:attr:`&optional`
         If the server does not understand any of the dialect strings, or if 
         PC NETWORK PROGRAM 1.0 is the chosen dialect.

      lanman: :bro:type:`SMB1::NegotiateResponseLANMAN` :bro:attr:`&optional`
         If the chosen dialect is greater than core up to and including
         LANMAN 2.1.

      ntlm: :bro:type:`SMB1::NegotiateResponseNTLM` :bro:attr:`&optional`
         If the chosen dialect is NT LM 0.12.


.. bro:type:: SMB1::NegotiateResponseCore

   :Type: :bro:type:`record`

      dialect_index: :bro:type:`count`
         Index of selected dialect


.. bro:type:: SMB1::NegotiateResponseLANMAN

   :Type: :bro:type:`record`

      word_count: :bro:type:`count`
         Count of parameter words (should be 13)

      dialect_index: :bro:type:`count`
         Index of selected dialect

      security_mode: :bro:type:`SMB1::NegotiateResponseSecurity`
         Security mode

      max_buffer_size: :bro:type:`count`
         Max transmit buffer size (>= 1024)

      max_mpx_count: :bro:type:`count`
         Max pending multiplexed requests

      max_number_vcs: :bro:type:`count`
         Max number of virtual circuits (VCs - transport-layer connections)
         between client and server

      raw_mode: :bro:type:`SMB1::NegotiateRawMode`
         Raw mode

      session_key: :bro:type:`count`
         Unique token identifying this session

      server_time: :bro:type:`time`
         Current date and time at server

      encryption_key: :bro:type:`string`
         The challenge encryption key

      primary_domain: :bro:type:`string`
         The server's primary domain


.. bro:type:: SMB1::NegotiateResponseNTLM

   :Type: :bro:type:`record`

      word_count: :bro:type:`count`
         Count of parameter words (should be 17)

      dialect_index: :bro:type:`count`
         Index of selected dialect

      security_mode: :bro:type:`SMB1::NegotiateResponseSecurity`
         Security mode

      max_buffer_size: :bro:type:`count`
         Max transmit buffer size

      max_mpx_count: :bro:type:`count`
         Max pending multiplexed requests

      max_number_vcs: :bro:type:`count`
         Max number of virtual circuits (VCs - transport-layer connections)
         between client and server

      max_raw_size: :bro:type:`count`
         Max raw buffer size

      session_key: :bro:type:`count`
         Unique token identifying this session

      capabilities: :bro:type:`SMB1::NegotiateCapabilities`
         Server capabilities

      server_time: :bro:type:`time`
         Current date and time at server

      encryption_key: :bro:type:`string` :bro:attr:`&optional`
         The challenge encryption key.
         Present only for non-extended security (i.e. capabilities$extended_security = F)

      domain_name: :bro:type:`string` :bro:attr:`&optional`
         The name of the domain.
         Present only for non-extended security (i.e. capabilities$extended_security = F)

      guid: :bro:type:`string` :bro:attr:`&optional`
         A globally unique identifier assigned to the server.
         Present only for extended security (i.e. capabilities$extended_security = T)

      security_blob: :bro:type:`string`
         Opaque security blob associated with the security package if capabilities$extended_security = T
         Otherwise, the challenge for challenge/response authentication.


.. bro:type:: SMB1::NegotiateResponseSecurity

   :Type: :bro:type:`record`

      user_level: :bro:type:`bool`
         This indicates whether the server, as a whole, is operating under
         Share Level or User Level security.

      challenge_response: :bro:type:`bool`
         This indicates whether or not the server supports Challenge/Response
         authentication. If the bit is false, then plaintext passwords must
         be used.

      signatures_enabled: :bro:type:`bool` :bro:attr:`&optional`
         This indicates if the server is capable of performing MAC message
         signing. Note: Requires NT LM 0.12 or later.

      signatures_required: :bro:type:`bool` :bro:attr:`&optional`
         This indicates if the server is requiring the use of a MAC in each
         packet. If false, message signing is optional. Note: Requires NT LM 0.12
         or later.


.. bro:type:: SMB1::SessionSetupAndXCapabilities

   :Type: :bro:type:`record`

      unicode: :bro:type:`bool`
         The client can use unicode strings

      large_files: :bro:type:`bool`
         The client can deal with files having 64 bit offsets

      nt_smbs: :bro:type:`bool`
         The client understands the SMBs introduced with NT LM 0.12
         Implies nt_find

      status32: :bro:type:`bool`
         The client can receive 32 bit errors encoded in Status.Status

      level_2_oplocks: :bro:type:`bool`
         The client understands Level II oplocks

      nt_find: :bro:type:`bool`
         Reserved. Implied by nt_smbs.


.. bro:type:: SMB1::SessionSetupAndXRequest

   :Type: :bro:type:`record`

      word_count: :bro:type:`count`
         Count of parameter words
            - 10 for pre NT LM 0.12
            - 12 for NT LM 0.12 with extended security
            - 13 for NT LM 0.12 without extended security

      max_buffer_size: :bro:type:`count`
         Client maximum buffer size

      max_mpx_count: :bro:type:`count`
         Actual maximum multiplexed pending request

      vc_number: :bro:type:`count`
         Virtual circuit number. First VC == 0

      session_key: :bro:type:`count`
         Session key (valid iff vc_number > 0)

      native_os: :bro:type:`string`
         Client's native operating system

      native_lanman: :bro:type:`string`
         Client's native LAN Manager type

      account_name: :bro:type:`string` :bro:attr:`&optional`
         Account name
         Note: not set for NT LM 0.12 with extended security

      account_password: :bro:type:`string` :bro:attr:`&optional`
         If challenge/response auth is not being used, this is the password.
         Otherwise, it's the response to the server's challenge.
         Note: Only set for pre NT LM 0.12

      primary_domain: :bro:type:`string` :bro:attr:`&optional`
         Client's primary domain, if known
         Note: not set for NT LM 0.12 with extended security

      case_insensitive_password: :bro:type:`string` :bro:attr:`&optional`
         Case insensitive password
         Note: only set for NT LM 0.12 without extended security

      case_sensitive_password: :bro:type:`string` :bro:attr:`&optional`
         Case sensitive password
         Note: only set for NT LM 0.12 without extended security

      security_blob: :bro:type:`string` :bro:attr:`&optional`
         Security blob
         Note: only set for NT LM 0.12 with extended security

      capabilities: :bro:type:`SMB1::SessionSetupAndXCapabilities` :bro:attr:`&optional`
         Client capabilities
         Note: only set for NT LM 0.12


.. bro:type:: SMB1::SessionSetupAndXResponse

   :Type: :bro:type:`record`

      word_count: :bro:type:`count`
         Count of parameter words (should be 3 for pre NT LM 0.12 and 4 for NT LM 0.12)

      is_guest: :bro:type:`bool` :bro:attr:`&optional`
         Were we logged in as a guest user?

      native_os: :bro:type:`string` :bro:attr:`&optional`
         Server's native operating system

      native_lanman: :bro:type:`string` :bro:attr:`&optional`
         Server's native LAN Manager type

      primary_domain: :bro:type:`string` :bro:attr:`&optional`
         Server's primary domain

      security_blob: :bro:type:`string` :bro:attr:`&optional`
         Security blob if NTLM


.. bro:type:: SMB1::Trans2_Args

   :Type: :bro:type:`record`

      total_param_count: :bro:type:`count`
         Total parameter count

      total_data_count: :bro:type:`count`
         Total data count

      max_param_count: :bro:type:`count`
         Max parameter count

      max_data_count: :bro:type:`count`
         Max data count

      max_setup_count: :bro:type:`count`
         Max setup count

      flags: :bro:type:`count`
         Flags

      trans_timeout: :bro:type:`count`
         Timeout

      param_count: :bro:type:`count`
         Parameter count

      param_offset: :bro:type:`count`
         Parameter offset

      data_count: :bro:type:`count`
         Data count

      data_offset: :bro:type:`count`
         Data offset

      setup_count: :bro:type:`count`
         Setup count


.. bro:type:: SMB1::Trans2_Sec_Args

   :Type: :bro:type:`record`

      total_param_count: :bro:type:`count`
         Total parameter count

      total_data_count: :bro:type:`count`
         Total data count

      param_count: :bro:type:`count`
         Parameter count

      param_offset: :bro:type:`count`
         Parameter offset

      param_displacement: :bro:type:`count`
         Parameter displacement

      data_count: :bro:type:`count`
         Data count

      data_offset: :bro:type:`count`
         Data offset

      data_displacement: :bro:type:`count`
         Data displacement

      FID: :bro:type:`count`
         File ID


.. bro:type:: SMB1::Trans_Sec_Args

   :Type: :bro:type:`record`

      total_param_count: :bro:type:`count`
         Total parameter count

      total_data_count: :bro:type:`count`
         Total data count

      param_count: :bro:type:`count`
         Parameter count

      param_offset: :bro:type:`count`
         Parameter offset

      param_displacement: :bro:type:`count`
         Parameter displacement

      data_count: :bro:type:`count`
         Data count

      data_offset: :bro:type:`count`
         Data offset

      data_displacement: :bro:type:`count`
         Data displacement


.. bro:type:: SMB2::CloseResponse

   :Type: :bro:type:`record`

      alloc_size: :bro:type:`count`
         The size, in bytes of the data that is allocated to the file.

      eof: :bro:type:`count`
         The size, in bytes, of the file.

      times: :bro:type:`SMB::MACTimes`
         The creation, last access, last write, and change times.

      attrs: :bro:type:`SMB2::FileAttrs`
         The attributes of the file.

   The response to an SMB2 *close* request, which is used by the client to close an instance
   of a file that was opened previously.
   
   For more information, see MS-SMB2:2.2.16
   
   .. bro:see:: smb2_close_response

.. bro:type:: SMB2::CreateRequest

   :Type: :bro:type:`record`

      filename: :bro:type:`string`
         Name of the file

      disposition: :bro:type:`count`
         Defines the action the server MUST take if the file that is specified already exists.

      create_options: :bro:type:`count`
         Specifies the options to be applied when creating or opening the file.

   The request sent by the client to request either creation of or access to a file.
   
   For more information, see MS-SMB2:2.2.13
   
   .. bro:see:: smb2_create_request

.. bro:type:: SMB2::CreateResponse

   :Type: :bro:type:`record`

      file_id: :bro:type:`SMB2::GUID`
         The SMB2 GUID for the file.

      size: :bro:type:`count`
         Size of the file.

      times: :bro:type:`SMB::MACTimes`
         Timestamps associated with the file in question.

      attrs: :bro:type:`SMB2::FileAttrs`
         File attributes.

      create_action: :bro:type:`count`
         The action taken in establishing the open.

   The response to an SMB2 *create_request* request, which is sent by the client to request
   either creation of or access to a file.
   
   For more information, see MS-SMB2:2.2.14
   
   .. bro:see:: smb2_create_response

.. bro:type:: SMB2::FileAttrs

   :Type: :bro:type:`record`

      read_only: :bro:type:`bool`
         The file is read only. Applications can read the file but cannot
         write to it or delete it.

      hidden: :bro:type:`bool`
         The file is hidden. It is not to be included in an ordinary directory listing.

      system: :bro:type:`bool`
         The file is part of or is used exclusively by the operating system.

      directory: :bro:type:`bool`
         The file is a directory.

      archive: :bro:type:`bool`
         The file has not been archived since it was last modified. Applications use
         this attribute to mark files for backup or removal.

      normal: :bro:type:`bool`
         The file has no other attributes set. This attribute is valid only if used alone.

      temporary: :bro:type:`bool`
         The file is temporary. This is a hint to the cache manager that it does not need
         to flush the file to backing storage.

      sparse_file: :bro:type:`bool`
         A file that is a sparse file.

      reparse_point: :bro:type:`bool`
         A file or directory that has an associated reparse point.

      compressed: :bro:type:`bool`
         The file or directory is compressed. For a file, this means that all of the data
         in the file is compressed. For a directory, this means that compression is the
         default for newly created files and subdirectories.

      offline: :bro:type:`bool`
         The data in this file is not available immediately. This attribute indicates that
         the file data is physically moved to offline storage. This attribute is used by
         Remote Storage, which is hierarchical storage management software.

      not_content_indexed: :bro:type:`bool`
         A file or directory that is not indexed by the content indexing service.

      encrypted: :bro:type:`bool`
         A file or directory that is encrypted. For a file, all data streams in the file
         are encrypted. For a directory, encryption is the default for newly created files
         and subdirectories.

      integrity_stream: :bro:type:`bool`
         A file or directory that is configured with integrity support. For a file, all
         data streams in the file have integrity support. For a directory, integrity support
         is the default for newly created files and subdirectories, unless the caller
         specifies otherwise.

      no_scrub_data: :bro:type:`bool`
         A file or directory that is configured to be excluded from the data integrity scan.

   A series of boolean flags describing basic and extended file attributes for SMB2.
   
   For more information, see MS-CIFS:2.2.1.2.3 and MS-FSCC:2.6
   
   .. bro:see:: smb2_create_response

.. bro:type:: SMB2::GUID

   :Type: :bro:type:`record`

      persistent: :bro:type:`count`
         A file handle that remains persistent when reconnected after a disconnect

      volatile: :bro:type:`count`
         A file handle that can be changed when reconnected after a disconnect

   An SMB2 globally unique identifier which identifies a file.
   
   For more information, see MS-SMB2:2.2.14.1
   
   .. bro:see:: smb2_close_request smb2_create_response smb2_read_request
      smb2_file_rename smb2_file_delete smb2_write_request

.. bro:type:: SMB2::Header

   :Type: :bro:type:`record`

      credit_charge: :bro:type:`count`
         The number of credits that this request consumes

      status: :bro:type:`count`
         In a request, this is an indication to the server about the client's channel
         change. In a response, this is the status field

      command: :bro:type:`count`
         The command code of the packet

      credits: :bro:type:`count`
         The number of credits the client is requesting, or the number of credits
         granted to the client in a response.

      flags: :bro:type:`count`
         A flags field, which indicates how to process the operation (e.g. asynchronously)

      message_id: :bro:type:`count`
         A value that uniquely identifies the message request/response pair across all
         messages that are sent on the same transport protocol connection

      process_id: :bro:type:`count`
         A value that uniquely identifies the process that generated the event.

      tree_id: :bro:type:`count`
         A value that uniquely identifies the tree connect for the command.

      session_id: :bro:type:`count`
         A value that uniquely identifies the established session for the command.

      signature: :bro:type:`string`
         The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the ``flags``
         field.

   An SMB2 header.
   
   For more information, see MS-SMB2:2.2.1.1 and MS-SMB2:2.2.1.2
   
   .. bro:see:: smb2_message smb2_close_request smb2_close_response
      smb2_create_request smb2_create_response smb2_negotiate_request
      smb2_negotiate_response smb2_read_request
      smb2_session_setup_request smb2_session_setup_response
      smb2_file_rename smb2_file_delete
      smb2_tree_connect_request smb2_tree_connect_response
      smb2_write_request

.. bro:type:: SMB2::NegotiateResponse

   :Type: :bro:type:`record`

      dialect_revision: :bro:type:`count`
         The preferred common SMB2 Protocol dialect number from the array that was sent in the SMB2
         NEGOTIATE Request.

      security_mode: :bro:type:`count`
         The security mode field specifies whether SMB signing is enabled, required at the server, or both.

      server_guid: :bro:type:`string`
         A globally unique identifier that is generate by the server to uniquely identify the server.

      system_time: :bro:type:`time`
         The system time of the SMB2 server when the SMB2 NEGOTIATE Request was processed.

      server_start_time: :bro:type:`time`
         The SMB2 server start time.

   The response to an SMB2 *negotiate* request, which is used by tghe client to notify the server
   what dialects of the SMB2 protocol the client understands.
   
   For more information, see MS-SMB2:2.2.4
   
   .. bro:see:: smb2_negotiate_response

.. bro:type:: SMB2::SessionSetupFlags

   :Type: :bro:type:`record`

      guest: :bro:type:`bool`
         If set, the client has been authenticated as a guest user.

      anonymous: :bro:type:`bool`
         If set, the client has been authenticated as an anonymous user.

      encrypt: :bro:type:`bool`
         If set, the server requires encryption of messages on this session.

   A flags field that indicates additional information about the session that's sent in the
   *session_setup* response.
   
   For more information, see MS-SMB2:2.2.6
   
   .. bro:see:: smb2_session_setup_response

.. bro:type:: SMB2::SessionSetupRequest

   :Type: :bro:type:`record`

      security_mode: :bro:type:`count`
         The security mode field specifies whether SMB signing is enabled or required at the client.

   The request sent by the client to request a new authenticated session
   within a new or existing SMB 2 Protocol transport connection to the server.
   
   For more information, see MS-SMB2:2.2.5
   
   .. bro:see:: smb2_session_setup_request

.. bro:type:: SMB2::SessionSetupResponse

   :Type: :bro:type:`record`

      flags: :bro:type:`SMB2::SessionSetupFlags`
         Additional information about the session

   The response to an SMB2 *session_setup* request, which is sent by the client to request a
   new authenticated session within a new or existing SMB 2 Protocol transport connection
   to the server.
   
   For more information, see MS-SMB2:2.2.6
   
   .. bro:see:: smb2_session_setup_response

.. bro:type:: SMB2::TreeConnectResponse

   :Type: :bro:type:`record`

      share_type: :bro:type:`count`
         The type of share being accessed. Physical disk, named pipe, or printer.

   The response to an SMB2 *tree_connect* request, which is sent by the client to request
   access to a particular share on the server.
   
   For more information, see MS-SMB2:2.2.9
   
   .. bro:see:: smb2_tree_connect_response

.. bro:type:: SMB::MACTimes

   :Type: :bro:type:`record`

      modified: :bro:type:`time` :bro:attr:`&log`
         The time when data was last written to the file.

      accessed: :bro:type:`time` :bro:attr:`&log`
         The time when the file was last accessed.

      created: :bro:type:`time` :bro:attr:`&log`
         The time the file was created.

      changed: :bro:type:`time` :bro:attr:`&log`
         The time when the file was last modified.
   :Attributes: :bro:attr:`&log`

   MAC times for a file.
   
   For more information, see MS-SMB2:2.2.16
   
   .. bro:see:: smb1_nt_create_andx_response smb2_create_response

.. bro:type:: SNMP::Binding

   :Type: :bro:type:`record`

      oid: :bro:type:`string`

      value: :bro:type:`SNMP::ObjectValue`

   The ``VarBind`` data structure from either :rfc:`1157` or
   :rfc:`3416`, which maps an Object Identifier to a value.

.. bro:type:: SNMP::Bindings

   :Type: :bro:type:`vector` of :bro:type:`SNMP::Binding`

   A ``VarBindList`` data structure from either :rfc:`1157` or :rfc:`3416`.
   A sequences of :bro:see:`SNMP::Binding`, which maps an OIDs to values.

.. bro:type:: SNMP::BulkPDU

   :Type: :bro:type:`record`

      request_id: :bro:type:`int`

      non_repeaters: :bro:type:`count`

      max_repititions: :bro:type:`count`

      bindings: :bro:type:`SNMP::Bindings`

   A ``BulkPDU`` data structure from :rfc:`3416`.

.. bro:type:: SNMP::Header

   :Type: :bro:type:`record`

      version: :bro:type:`count`

      v1: :bro:type:`SNMP::HeaderV1` :bro:attr:`&optional`
         Set when ``version`` is 0.

      v2: :bro:type:`SNMP::HeaderV2` :bro:attr:`&optional`
         Set when ``version`` is 1.

      v3: :bro:type:`SNMP::HeaderV3` :bro:attr:`&optional`
         Set when ``version`` is 3.

   A generic SNMP header data structure that may include data from
   any version of SNMP.  The value of the ``version`` field
   determines what header field is initialized.

.. bro:type:: SNMP::HeaderV1

   :Type: :bro:type:`record`

      community: :bro:type:`string`

   The top-level message data structure of an SNMPv1 datagram, not
   including the PDU data.  See :rfc:`1157`.

.. bro:type:: SNMP::HeaderV2

   :Type: :bro:type:`record`

      community: :bro:type:`string`

   The top-level message data structure of an SNMPv2 datagram, not
   including the PDU data.  See :rfc:`1901`.

.. bro:type:: SNMP::HeaderV3

   :Type: :bro:type:`record`

      id: :bro:type:`count`

      max_size: :bro:type:`count`

      flags: :bro:type:`count`

      auth_flag: :bro:type:`bool`

      priv_flag: :bro:type:`bool`

      reportable_flag: :bro:type:`bool`

      security_model: :bro:type:`count`

      security_params: :bro:type:`string`

      pdu_context: :bro:type:`SNMP::ScopedPDU_Context` :bro:attr:`&optional`

   The top-level message data structure of an SNMPv3 datagram, not
   including the PDU data.  See :rfc:`3412`.

.. bro:type:: SNMP::ObjectValue

   :Type: :bro:type:`record`

      tag: :bro:type:`count`

      oid: :bro:type:`string` :bro:attr:`&optional`

      signed: :bro:type:`int` :bro:attr:`&optional`

      unsigned: :bro:type:`count` :bro:attr:`&optional`

      address: :bro:type:`addr` :bro:attr:`&optional`

      octets: :bro:type:`string` :bro:attr:`&optional`

   A generic SNMP object value, that may include any of the
   valid ``ObjectSyntax`` values from :rfc:`1155` or :rfc:`3416`.
   The value is decoded whenever possible and assigned to
   the appropriate field, which can be determined from the value
   of the ``tag`` field.  For tags that can't be mapped to an
   appropriate type, the ``octets`` field holds the BER encoded
   ASN.1 content if there is any (though, ``octets`` is may also
   be used for other tags such as OCTET STRINGS or Opaque).  Null
   values will only have their corresponding tag value set.

.. bro:type:: SNMP::PDU

   :Type: :bro:type:`record`

      request_id: :bro:type:`int`

      error_status: :bro:type:`int`

      error_index: :bro:type:`int`

      bindings: :bro:type:`SNMP::Bindings`

   A ``PDU`` data structure from either :rfc:`1157` or :rfc:`3416`.

.. bro:type:: SNMP::ScopedPDU_Context

   :Type: :bro:type:`record`

      engine_id: :bro:type:`string`

      name: :bro:type:`string`

   The ``ScopedPduData`` data structure of an SNMPv3 datagram, not
   including the PDU data (i.e. just the "context" fields).
   See :rfc:`3412`.

.. bro:type:: SNMP::TrapPDU

   :Type: :bro:type:`record`

      enterprise: :bro:type:`string`

      agent: :bro:type:`addr`

      generic_trap: :bro:type:`int`

      specific_trap: :bro:type:`int`

      time_stamp: :bro:type:`count`

      bindings: :bro:type:`SNMP::Bindings`

   A ``Trap-PDU`` data structure from :rfc:`1157`.

.. bro:type:: SOCKS::Address

   :Type: :bro:type:`record`

      host: :bro:type:`addr` :bro:attr:`&optional` :bro:attr:`&log`

      name: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
   :Attributes: :bro:attr:`&log`

   This record is for a SOCKS client or server to provide either a
   name or an address to represent a desired or established connection.

.. bro:type:: SSH::Algorithm_Prefs

   :Type: :bro:type:`record`

      client_to_server: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional`
         The algorithm preferences for client to server communication

      server_to_client: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional`
         The algorithm preferences for server to client communication

   The client and server each have some preferences for the algorithms used
   in each direction.

.. bro:type:: SSH::Capabilities

   :Type: :bro:type:`record`

      kex_algorithms: :bro:type:`string_vec`
         Key exchange algorithms

      server_host_key_algorithms: :bro:type:`string_vec`
         The algorithms supported for the server host key

      encryption_algorithms: :bro:type:`SSH::Algorithm_Prefs`
         Symmetric encryption algorithm preferences

      mac_algorithms: :bro:type:`SSH::Algorithm_Prefs`
         Symmetric MAC algorithm preferences

      compression_algorithms: :bro:type:`SSH::Algorithm_Prefs`
         Compression algorithm preferences

      languages: :bro:type:`SSH::Algorithm_Prefs` :bro:attr:`&optional`
         Language preferences

      is_server: :bro:type:`bool`
         Are these the capabilities of the server?

   This record lists the preferences of an SSH endpoint for
   algorithm selection. During the initial :abbr:`SSH (Secure Shell)`
   key exchange, each endpoint lists the algorithms
   that it supports, in order of preference. See
   :rfc:`4253#section-7.1` for details.

.. bro:type:: SSL::SignatureAndHashAlgorithm

   :Type: :bro:type:`record`

      HashAlgorithm: :bro:type:`count`
         Hash algorithm number

      SignatureAlgorithm: :bro:type:`count`
         Signature algorithm number


.. bro:type:: SYN_packet

   :Type: :bro:type:`record`

      is_orig: :bro:type:`bool`
         True if the packet was sent the connection's originator.

      DF: :bro:type:`bool`
         True if the *don't fragment* is set in the IP header.

      ttl: :bro:type:`count`
         The IP header's time-to-live.

      size: :bro:type:`count`
         The size of the packet's payload as specified in the IP header.

      win_size: :bro:type:`count`
         The window size from the TCP header.

      win_scale: :bro:type:`int`
         The window scale option if present, or -1 if not.

      MSS: :bro:type:`count`
         The maximum segment size if present, or 0 if not.

      SACK_OK: :bro:type:`bool`
         True if the *SACK* option is present.

   Fields of a SYN packet.
   
   .. bro:see:: connection_SYN_packet

.. bro:type:: ThreadStats

   :Type: :bro:type:`record`

      num_threads: :bro:type:`count`

   Statistics about threads.
   
   .. bro:see:: get_thread_stats

.. bro:type:: TimerStats

   :Type: :bro:type:`record`

      current: :bro:type:`count`
         Current number of pending timers.

      max: :bro:type:`count`
         Maximum number of concurrent timers pending so far.

      cumulative: :bro:type:`count`
         Cumulative number of timers scheduled.

   Statistics of timers.
   
   .. bro:see:: get_timer_stats

.. bro:type:: Tunnel::EncapsulatingConn

   :Type: :bro:type:`record`

      cid: :bro:type:`conn_id` :bro:attr:`&log`
         The 4-tuple of the encapsulating "connection". In case of an
         IP-in-IP tunnel the ports will be set to 0. The direction
         (i.e., orig and resp) are set according to the first tunneled
         packet seen and not according to the side that established
         the tunnel.

      tunnel_type: :bro:type:`Tunnel::Type` :bro:attr:`&log`
         The type of tunnel.

      uid: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         A globally unique identifier that, for non-IP-in-IP tunnels,
         cross-references the *uid* field of :bro:type:`connection`.
   :Attributes: :bro:attr:`&log`

   Records the identity of an encapsulating parent of a tunneled connection.

.. bro:type:: Unified2::IDSEvent

   :Type: :bro:type:`record`

      sensor_id: :bro:type:`count`

      event_id: :bro:type:`count`

      ts: :bro:type:`time`

      signature_id: :bro:type:`count`

      generator_id: :bro:type:`count`

      signature_revision: :bro:type:`count`

      classification_id: :bro:type:`count`

      priority_id: :bro:type:`count`

      src_ip: :bro:type:`addr`

      dst_ip: :bro:type:`addr`

      src_p: :bro:type:`port`

      dst_p: :bro:type:`port`

      impact_flag: :bro:type:`count`

      impact: :bro:type:`count`

      blocked: :bro:type:`count`

      mpls_label: :bro:type:`count` :bro:attr:`&optional`
         Not available in "legacy" IDS events.

      vlan_id: :bro:type:`count` :bro:attr:`&optional`
         Not available in "legacy" IDS events.

      packet_action: :bro:type:`count` :bro:attr:`&optional`
         Only available in "legacy" IDS events.


.. bro:type:: Unified2::Packet

   :Type: :bro:type:`record`

      sensor_id: :bro:type:`count`

      event_id: :bro:type:`count`

      event_second: :bro:type:`count`

      packet_ts: :bro:type:`time`

      link_type: :bro:type:`count`

      data: :bro:type:`string`


.. bro:type:: X509::BasicConstraints

   :Type: :bro:type:`record`

      ca: :bro:type:`bool` :bro:attr:`&log`
         CA flag set?

      path_len: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Maximum path length
   :Attributes: :bro:attr:`&log`


.. bro:type:: X509::Certificate

   :Type: :bro:type:`record`

      version: :bro:type:`count` :bro:attr:`&log`
         Version number.

      serial: :bro:type:`string` :bro:attr:`&log`
         Serial number.

      subject: :bro:type:`string` :bro:attr:`&log`
         Subject.

      issuer: :bro:type:`string` :bro:attr:`&log`
         Issuer.

      cn: :bro:type:`string` :bro:attr:`&optional`
         Last (most specific) common name.

      not_valid_before: :bro:type:`time` :bro:attr:`&log`
         Timestamp before when certificate is not valid.

      not_valid_after: :bro:type:`time` :bro:attr:`&log`
         Timestamp after when certificate is not valid.

      key_alg: :bro:type:`string` :bro:attr:`&log`
         Name of the key algorithm

      sig_alg: :bro:type:`string` :bro:attr:`&log`
         Name of the signature algorithm

      key_type: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Key type, if key parseable by openssl (either rsa, dsa or ec)

      key_length: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Key length in bits

      exponent: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Exponent, if RSA-certificate

      curve: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Curve, if EC-certificate


.. bro:type:: X509::Extension

   :Type: :bro:type:`record`

      name: :bro:type:`string`
         Long name of extension. oid if name not known

      short_name: :bro:type:`string` :bro:attr:`&optional`
         Short name of extension if known

      oid: :bro:type:`string`
         Oid of extension

      critical: :bro:type:`bool`
         True if extension is critical

      value: :bro:type:`string`
         Extension content parsed to string for known extensions. Raw data otherwise.


.. bro:type:: X509::Result

   :Type: :bro:type:`record`

      result: :bro:type:`int`
         OpenSSL result code

      result_string: :bro:type:`string`
         Result as string

      chain_certs: :bro:type:`vector` of :bro:type:`opaque` of x509 :bro:attr:`&optional`
         References to the final certificate chain, if verification successful. End-host certificate is first.

   Result of an X509 certificate chain verification

.. bro:type:: X509::SubjectAlternativeName

   :Type: :bro:type:`record`

      dns: :bro:type:`string_vec` :bro:attr:`&optional` :bro:attr:`&log`
         List of DNS entries in SAN

      uri: :bro:type:`string_vec` :bro:attr:`&optional` :bro:attr:`&log`
         List of URI entries in SAN

      email: :bro:type:`string_vec` :bro:attr:`&optional` :bro:attr:`&log`
         List of email entries in SAN

      ip: :bro:type:`addr_vec` :bro:attr:`&optional` :bro:attr:`&log`
         List of IP entries in SAN

      other_fields: :bro:type:`bool`
         True if the certificate contained other, not recognized or parsed name fields


.. bro:type:: addr_set

   :Type: :bro:type:`set` [:bro:type:`addr`]

   A set of addresses.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: addr_vec

   :Type: :bro:type:`vector` of :bro:type:`addr`

   A vector of addresses.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: any_vec

   :Type: :bro:type:`vector` of :bro:type:`any`

   A vector of any, used by some builtin functions to store a list of varying
   types.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: backdoor_endp_stats

   :Type: :bro:type:`record`

      is_partial: :bro:type:`bool`

      num_pkts: :bro:type:`count`

      num_8k0_pkts: :bro:type:`count`

      num_8k4_pkts: :bro:type:`count`

      num_lines: :bro:type:`count`

      num_normal_lines: :bro:type:`count`

      num_bytes: :bro:type:`count`

      num_7bit_ascii: :bro:type:`count`

   Deprecated.

.. bro:type:: bittorrent_benc_dir

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`bittorrent_benc_value`

   A table of BitTorrent "benc" values.
   
   .. bro:see:: bt_tracker_response

.. bro:type:: bittorrent_benc_value

   :Type: :bro:type:`record`

      i: :bro:type:`int` :bro:attr:`&optional`
         TODO.

      s: :bro:type:`string` :bro:attr:`&optional`
         TODO.

      d: :bro:type:`string` :bro:attr:`&optional`
         TODO.

      l: :bro:type:`string` :bro:attr:`&optional`
         TODO.

   BitTorrent "benc" value. Note that "benc" = Bencode ("Bee-Encode"), per
   http://en.wikipedia.org/wiki/Bencode.
   
   .. bro:see:: bittorrent_benc_dir

.. bro:type:: bittorrent_peer

   :Type: :bro:type:`record`

      h: :bro:type:`addr`
         The peer's address.

      p: :bro:type:`port`
         The peer's port.

   A BitTorrent peer.
   
   .. bro:see:: bittorrent_peer_set

.. bro:type:: bittorrent_peer_set

   :Type: :bro:type:`set` [:bro:type:`bittorrent_peer`]

   A set of BitTorrent peers.
   
   .. bro:see:: bt_tracker_response

.. bro:type:: bt_tracker_headers

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string`

   Header table type used by BitTorrent analyzer.
   
   .. bro:see:: bt_tracker_request bt_tracker_response
      bt_tracker_response_not_ok

.. bro:type:: call_argument

   :Type: :bro:type:`record`

      name: :bro:type:`string`
         The name of the parameter.

      type_name: :bro:type:`string`
         The name of the parameters's type.

      default_val: :bro:type:`any` :bro:attr:`&optional`
         The value of the :bro:attr:`&default` attribute if defined.

      value: :bro:type:`any` :bro:attr:`&optional`
         The value of the parameter as passed into a given call instance.
         Might be unset in the case a :bro:attr:`&default` attribute is
         defined.

   Meta-information about a parameter to a function/event.
   
   .. bro:see:: call_argument_vector new_event

.. bro:type:: call_argument_vector

   :Type: :bro:type:`vector` of :bro:type:`call_argument`

   Vector type used to capture parameters of a function/event call.
   
   .. bro:see:: call_argument new_event

.. bro:type:: conn_id

   :Type: :bro:type:`record`

      orig_h: :bro:type:`addr` :bro:attr:`&log`
         The originator's IP address.

      orig_p: :bro:type:`port` :bro:attr:`&log`
         The originator's port number.

      resp_h: :bro:type:`addr` :bro:attr:`&log`
         The responder's IP address.

      resp_p: :bro:type:`port` :bro:attr:`&log`
         The responder's port number.
   :Attributes: :bro:attr:`&log`

   A connection's identifying 4-tuple of endpoints and ports.
   
   .. note:: It's actually a 5-tuple: the transport-layer protocol is stored as
      part of the port values, `orig_p` and `resp_p`, and can be extracted from
      them with :bro:id:`get_port_transport_proto`.

.. bro:type:: connection

   :Type: :bro:type:`record`

      id: :bro:type:`conn_id`
         The connection's identifying 4-tuple.

      orig: :bro:type:`endpoint`
         Statistics about originator side.

      resp: :bro:type:`endpoint`
         Statistics about responder side.

      start_time: :bro:type:`time`
         The timestamp of the connection's first packet.

      duration: :bro:type:`interval`
         The duration of the conversation. Roughly speaking, this is the
         interval between first and last data packet (low-level TCP details
         may adjust it somewhat in ambiguous cases).

      service: :bro:type:`set` [:bro:type:`string`]
         The set of services the connection is using as determined by Bro's
         dynamic protocol detection. Each entry is the label of an analyzer
         that confirmed that it could parse the connection payload.  While
         typically, there will be at most one entry for each connection, in
         principle it is possible that more than one protocol analyzer is able
         to parse the same data. If so, all will be recorded. Also note that
         the recorded services are independent of any transport-level protocols.

      history: :bro:type:`string`
         State history of connections. See *history* in :bro:see:`Conn::Info`.

      uid: :bro:type:`string`
         A globally unique connection identifier. For each connection, Bro
         creates an ID that is very likely unique across independent Bro runs.
         These IDs can thus be used to tag and locate information associated
         with that connection.

      tunnel: :bro:type:`EncapsulatingConnVector` :bro:attr:`&optional`
         If the connection is tunneled, this field contains information about
         the encapsulating "connection(s)" with the outermost one starting
         at index zero.  It's also always the first such encapsulation seen
         for the connection unless the :bro:id:`tunnel_changed` event is
         handled and reassigns this field to the new encapsulation.

      vlan: :bro:type:`int` :bro:attr:`&optional`
         The outer VLAN, if applicable for this connection.

      inner_vlan: :bro:type:`int` :bro:attr:`&optional`
         The inner VLAN, if applicable for this connection.

      dpd: :bro:type:`DPD::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/dpd/main.bro` is loaded)


      conn: :bro:type:`Conn::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/conn/main.bro` is loaded)


      extract_orig: :bro:type:`bool` :bro:attr:`&default` = :bro:see:`Conn::default_extract` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/conn/contents.bro` is loaded)


      extract_resp: :bro:type:`bool` :bro:attr:`&default` = :bro:see:`Conn::default_extract` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/conn/contents.bro` is loaded)


      thresholds: :bro:type:`ConnThreshold::Thresholds` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/conn/thresholds.bro` is loaded)


      dce_rpc: :bro:type:`DCE_RPC::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dce-rpc/main.bro` is loaded)


      dce_rpc_state: :bro:type:`DCE_RPC::State` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dce-rpc/main.bro` is loaded)


      dce_rpc_backing: :bro:type:`table` [:bro:type:`count`] of :bro:type:`DCE_RPC::BackingState` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dce-rpc/main.bro` is loaded)


      dhcp: :bro:type:`DHCP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dhcp/main.bro` is loaded)


      dnp3: :bro:type:`DNP3::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dnp3/main.bro` is loaded)


      dns: :bro:type:`DNS::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dns/main.bro` is loaded)


      dns_state: :bro:type:`DNS::State` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/dns/main.bro` is loaded)


      ftp: :bro:type:`FTP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ftp/main.bro` is loaded)


      ftp_data_reuse: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ftp/main.bro` is loaded)


      ssl: :bro:type:`SSL::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ssl/main.bro` is loaded)


      http: :bro:type:`HTTP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/main.bro` is loaded)


      http_state: :bro:type:`HTTP::State` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/main.bro` is loaded)


      irc: :bro:type:`IRC::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/main.bro` is loaded)

         IRC session information.

      krb: :bro:type:`KRB::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/main.bro` is loaded)


      modbus: :bro:type:`Modbus::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/modbus/main.bro` is loaded)


      mysql: :bro:type:`MySQL::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/mysql/main.bro` is loaded)


      ntlm: :bro:type:`NTLM::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ntlm/main.bro` is loaded)


      radius: :bro:type:`RADIUS::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/radius/main.bro` is loaded)


      rdp: :bro:type:`RDP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/rdp/main.bro` is loaded)


      rfb: :bro:type:`RFB::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/rfb/main.bro` is loaded)


      sip: :bro:type:`SIP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/sip/main.bro` is loaded)


      sip_state: :bro:type:`SIP::State` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/sip/main.bro` is loaded)


      snmp: :bro:type:`SNMP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/snmp/main.bro` is loaded)


      smb_state: :bro:type:`SMB::State` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smb/main.bro` is loaded)


      smtp: :bro:type:`SMTP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/main.bro` is loaded)


      smtp_state: :bro:type:`SMTP::State` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/main.bro` is loaded)


      socks: :bro:type:`SOCKS::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/socks/main.bro` is loaded)


      ssh: :bro:type:`SSH::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ssh/main.bro` is loaded)


      syslog: :bro:type:`Syslog::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/syslog/main.bro` is loaded)


      known_services_done: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/conn/known-services.bro` is loaded)


   A connection. This is Bro's basic connection type describing IP- and
   transport-layer information about the conversation. Note that Bro uses a
   liberal interpretation of "connection" and associates instances of this type
   also with UDP and ICMP flows.

.. bro:type:: count_set

   :Type: :bro:type:`set` [:bro:type:`count`]

   A set of counts.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: dns_answer

   :Type: :bro:type:`record`

      answer_type: :bro:type:`count`
         Answer type. One of :bro:see:`DNS_QUERY`, :bro:see:`DNS_ANS`,
         :bro:see:`DNS_AUTH` and :bro:see:`DNS_ADDL`.

      query: :bro:type:`string`
         Query.

      qtype: :bro:type:`count`
         Query type.

      qclass: :bro:type:`count`
         Query class.

      TTL: :bro:type:`interval`
         Time-to-live.

   The general part of a DNS reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply
      dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TXT_reply dns_WKS_reply

.. bro:type:: dns_dnskey_rr

   :Type: :bro:type:`record`

      query: :bro:type:`string`
         Query.

      answer_type: :bro:type:`count`
         Ans type.

      flags: :bro:type:`count`
         flags filed.

      protocol: :bro:type:`count`
         Protocol, should be always 3 for DNSSEC.

      algorithm: :bro:type:`count`
         Algorithm for Public Key.

      public_key: :bro:type:`string`
         Public Key

      is_query: :bro:type:`count`
         The RR is a query/Response.

   A DNSSEC DNSKEY record.
   
   .. bro:see:: dns_DNSKEY

.. bro:type:: dns_ds_rr

   :Type: :bro:type:`record`

      query: :bro:type:`string`
         Query.

      answer_type: :bro:type:`count`
         Ans type.

      key_tag: :bro:type:`count`
         flags filed.

      algorithm: :bro:type:`count`
         Algorithm for Public Key.

      digest_type: :bro:type:`count`
         Digest Type.

      digest_val: :bro:type:`string`
         Digest Value.

      is_query: :bro:type:`count`
         The RR is a query/Response.

   A DNSSEC DS record.
   
   .. bro:see:: dns_DS

.. bro:type:: dns_edns_additional

   :Type: :bro:type:`record`

      query: :bro:type:`string`
         Query.

      qtype: :bro:type:`count`
         Query type.

      t: :bro:type:`count`
         TODO.

      payload_size: :bro:type:`count`
         TODO.

      extended_rcode: :bro:type:`count`
         Extended return code.

      version: :bro:type:`count`
         Version.

      z_field: :bro:type:`count`
         TODO.

      TTL: :bro:type:`interval`
         Time-to-live.

      is_query: :bro:type:`count`
         TODO.

   An additional DNS EDNS record.
   
   .. bro:see:: dns_EDNS_addl

.. bro:type:: dns_mapping

   :Type: :bro:type:`record`

      creation_time: :bro:type:`time`
         The time when the mapping was created, which corresponds to when
         the DNS query was sent out.

      req_host: :bro:type:`string`
         If the mapping is the result of a name lookup, the queried host name;
         otherwise empty.

      req_addr: :bro:type:`addr`
         If the mapping is the result of a pointer lookup, the queried
         address; otherwise null.

      valid: :bro:type:`bool`
         True if the lookup returned success. Only then are the result fields
         valid.

      hostname: :bro:type:`string`
         If the mapping is the result of a pointer lookup, the resolved
         hostname; otherwise empty.

      addrs: :bro:type:`addr_set`
         If the mapping is the result of an address lookup, the resolved
         address(es); otherwise empty.


.. bro:type:: dns_msg

   :Type: :bro:type:`record`

      id: :bro:type:`count`
         Transaction ID.

      opcode: :bro:type:`count`
         Operation code.

      rcode: :bro:type:`count`
         Return code.

      QR: :bro:type:`bool`
         Query response flag.

      AA: :bro:type:`bool`
         Authoritative answer flag.

      TC: :bro:type:`bool`
         Truncated packet flag.

      RD: :bro:type:`bool`
         Recursion desired flag.

      RA: :bro:type:`bool`
         Recursion available flag.

      Z: :bro:type:`count`
         TODO.

      num_queries: :bro:type:`count`
         Number of query records.

      num_answers: :bro:type:`count`
         Number of answer records.

      num_auth: :bro:type:`count`
         Number of authoritative records.

      num_addl: :bro:type:`count`
         Number of additional records.

   A DNS message.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_message dns_query_reply dns_rejected dns_request

.. bro:type:: dns_nsec3_rr

   :Type: :bro:type:`record`

      query: :bro:type:`string`
         Query.

      answer_type: :bro:type:`count`
         Ans type.

      nsec_flags: :bro:type:`count`
         flags field.

      nsec_hash_algo: :bro:type:`count`
         Hash algorithm.

      nsec_iter: :bro:type:`count`
         Iterations.

      nsec_salt_len: :bro:type:`count`
         Salt length.

      nsec_salt: :bro:type:`string`
         Salt value

      nsec_hlen: :bro:type:`count`
         Hash length.

      nsec_hash: :bro:type:`string`
         Hash value.

      bitmaps: :bro:type:`string_vec`
         Type Bit Maps.

      is_query: :bro:type:`count`
         The RR is a query/Response.

   A DNSSEC NSEC3 record.
   
   .. bro:see:: dns_NSEC3

.. bro:type:: dns_rrsig_rr

   :Type: :bro:type:`record`

      query: :bro:type:`string`
         Query.

      answer_type: :bro:type:`count`
         Ans type.

      type_covered: :bro:type:`count`
         qtype covered by RRSIG RR.

      algorithm: :bro:type:`count`
         Algorithm.

      labels: :bro:type:`count`
         Labels in the owner's name.

      orig_ttl: :bro:type:`interval`
         Original TTL.

      sig_exp: :bro:type:`time`
         Time when signed RR expires.

      sig_incep: :bro:type:`time`
         Time when signed.

      key_tag: :bro:type:`count`
         Key tag value.

      signer_name: :bro:type:`string`
         Signature.

      signature: :bro:type:`string`
         Hash of the RRDATA.

      is_query: :bro:type:`count`
         The RR is a query/Response.

   A DNSSEC RRSIG record.
   
   .. bro:see:: dns_RRSIG

.. bro:type:: dns_soa

   :Type: :bro:type:`record`

      mname: :bro:type:`string`
         Primary source of data for zone.

      rname: :bro:type:`string`
         Mailbox for responsible person.

      serial: :bro:type:`count`
         Version number of zone.

      refresh: :bro:type:`interval`
         Seconds before refreshing.

      retry: :bro:type:`interval`
         How long before retrying failed refresh.

      expire: :bro:type:`interval`
         When zone no longer authoritative.

      minimum: :bro:type:`interval`
         Minimum TTL to use when exporting.

   A DNS SOA record.
   
   .. bro:see:: dns_SOA_reply

.. bro:type:: dns_tsig_additional

   :Type: :bro:type:`record`

      query: :bro:type:`string`
         Query.

      qtype: :bro:type:`count`
         Query type.

      alg_name: :bro:type:`string`
         Algorithm name.

      sig: :bro:type:`string`
         Signature.

      time_signed: :bro:type:`time`
         Time when signed.

      fudge: :bro:type:`time`
         TODO.

      orig_id: :bro:type:`count`
         TODO.

      rr_error: :bro:type:`count`
         TODO.

      is_query: :bro:type:`count`
         TODO.

   An additional DNS TSIG record.
   
   .. bro:see:: dns_TSIG_addl

.. bro:type:: endpoint

   :Type: :bro:type:`record`

      size: :bro:type:`count`
         Logical size of data sent (for TCP: derived from sequence numbers).

      state: :bro:type:`count`
         Endpoint state. For a TCP connection, one of the constants:
         :bro:see:`TCP_INACTIVE` :bro:see:`TCP_SYN_SENT`
         :bro:see:`TCP_SYN_ACK_SENT` :bro:see:`TCP_PARTIAL`
         :bro:see:`TCP_ESTABLISHED` :bro:see:`TCP_CLOSED` :bro:see:`TCP_RESET`.
         For UDP, one of :bro:see:`UDP_ACTIVE` and :bro:see:`UDP_INACTIVE`.

      num_pkts: :bro:type:`count` :bro:attr:`&optional`
         Number of packets sent. Only set if :bro:id:`use_conn_size_analyzer`
         is true.

      num_bytes_ip: :bro:type:`count` :bro:attr:`&optional`
         Number of IP-level bytes sent. Only set if
         :bro:id:`use_conn_size_analyzer` is true.

      flow_label: :bro:type:`count`
         The current IPv6 flow label that the connection endpoint is using.
         Always 0 if the connection is over IPv4.

      l2_addr: :bro:type:`string` :bro:attr:`&optional`
         The link-layer address seen in the first packet (if available).

   Statistics about a :bro:type:`connection` endpoint.
   
   .. bro:see:: connection

.. bro:type:: endpoint_stats

   :Type: :bro:type:`record`

      num_pkts: :bro:type:`count`
         Number of packets.

      num_rxmit: :bro:type:`count`
         Number of retransmissions.

      num_rxmit_bytes: :bro:type:`count`
         Number of retransmitted bytes.

      num_in_order: :bro:type:`count`
         Number of in-order packets.

      num_OO: :bro:type:`count`
         Number of out-of-order packets.

      num_repl: :bro:type:`count`
         Number of replicated packets (last packet was sent again).

      endian_type: :bro:type:`count`
         Endian type used by the endpoint, if it could be determined from
         the sequence numbers used. This is one of :bro:see:`ENDIAN_UNKNOWN`,
         :bro:see:`ENDIAN_BIG`, :bro:see:`ENDIAN_LITTLE`, and
         :bro:see:`ENDIAN_CONFUSED`.

   Statistics about what a TCP endpoint sent.
   
   .. bro:see:: conn_stats

.. bro:type:: entropy_test_result

   :Type: :bro:type:`record`

      entropy: :bro:type:`double`
         Information density.

      chi_square: :bro:type:`double`
         Chi-Square value.

      mean: :bro:type:`double`
         Arithmetic Mean.

      monte_carlo_pi: :bro:type:`double`
         Monte-carlo value for pi.

      serial_correlation: :bro:type:`double`
         Serial correlation coefficient.

   Computed entropy values. The record captures a number of measures that are
   computed in parallel. See `A Pseudorandom Number Sequence Test Program
   <http://www.fourmilab.ch/random>`_ for more information, Bro uses the same
   code.
   
   .. bro:see:: entropy_test_add entropy_test_finish entropy_test_init find_entropy

.. bro:type:: event_peer

   :Type: :bro:type:`record`

      id: :bro:type:`peer_id`
         Locally unique ID of peer (returned by :bro:id:`connect`).

      host: :bro:type:`addr`
         The IP address of the peer.

      p: :bro:type:`port`
         Either the port we connected to at the peer; or our port the peer
         connected to if the session is remotely initiated.

      is_local: :bro:type:`bool`
         True if this record describes the local process.

      descr: :bro:type:`string`
         The peer's :bro:see:`peer_description`.

      class: :bro:type:`string` :bro:attr:`&optional`
         The self-assigned *class* of the peer.

   A communication peer.
   
   .. bro:see:: complete_handshake disconnect finished_send_state
      get_event_peer get_local_event_peer remote_capture_filter
      remote_connection_closed remote_connection_error
      remote_connection_established remote_connection_handshake_done
      remote_event_registered remote_log_peer remote_pong
      request_remote_events request_remote_logs request_remote_sync
      send_capture_filter send_current_packet send_id send_ping send_state
      set_accept_state set_compression_level
   
   .. todo::The type's name is too narrow these days, should rename.

.. bro:type:: fa_file

   :Type: :bro:type:`record`

      id: :bro:type:`string`
         An identifier associated with a single file.

      parent_id: :bro:type:`string` :bro:attr:`&optional`
         Identifier associated with a container file from which this one was
         extracted as part of the file analysis.

      source: :bro:type:`string`
         An identification of the source of the file data. E.g. it may be
         a network protocol over which it was transferred, or a local file
         path which was read, or some other input source.
         Examples are: "HTTP", "SMTP", "IRC_DATA", or the file path.

      is_orig: :bro:type:`bool` :bro:attr:`&optional`
         If the source of this file is a network connection, this field
         may be set to indicate the directionality.

      conns: :bro:type:`table` [:bro:type:`conn_id`] of :bro:type:`connection` :bro:attr:`&optional`
         The set of connections over which the file was transferred.

      last_active: :bro:type:`time`
         The time at which the last activity for the file was seen.

      seen_bytes: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Number of bytes provided to the file analysis engine for the file.

      total_bytes: :bro:type:`count` :bro:attr:`&optional`
         Total number of bytes that are supposed to comprise the full file.

      missing_bytes: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of bytes in the file stream that were completely missed
         during the process of analysis e.g. due to dropped packets.

      overflow_bytes: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of bytes in the file stream that were not delivered to
         stream file analyzers.  Generally, this consists of bytes that
         couldn't be reassembled, either because reassembly simply isn't
         enabled, or due to size limitations of the reassembly buffer.

      timeout_interval: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`default_file_timeout_interval` :bro:attr:`&optional`
         The amount of time between receiving new data for this file that
         the analysis engine will wait before giving up on it.

      bof_buffer_size: :bro:type:`count` :bro:attr:`&default` = :bro:see:`default_file_bof_buffer_size` :bro:attr:`&optional`
         The number of bytes at the beginning of a file to save for later
         inspection in the *bof_buffer* field.

      bof_buffer: :bro:type:`string` :bro:attr:`&optional`
         The content of the beginning of a file up to *bof_buffer_size* bytes.
         This is also the buffer that's used for file/mime type detection.

      info: :bro:type:`Files::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/files/main.bro` is loaded)


      ftp: :bro:type:`FTP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ftp/files.bro` is loaded)


      http: :bro:type:`HTTP::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)


      irc: :bro:type:`IRC::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/files.bro` is loaded)


      pe: :bro:type:`PE::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/files/pe/main.bro` is loaded)


      u2_events: :bro:type:`table` [:bro:type:`count`] of :bro:type:`Unified2::IDSEvent` :bro:attr:`&optional` :bro:attr:`&create_expire` = ``5.0 secs`` :bro:attr:`&expire_func` = :bro:type:`function`
         (present if :doc:`/scripts/base/files/unified2/main.bro` is loaded)

         Recently received IDS events.  This is primarily used
         for tying together Unified2 events and packets.

      logcert: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssl/log-hostcerts-only.bro` is loaded)

   :Attributes: :bro:attr:`&redef`

   A file that Bro is analyzing.  This is Bro's type for describing the basic
   internal metadata collected about a "file", which is essentially just a
   byte stream that is e.g. pulled from a network connection or possibly
   some other input source.

.. bro:type:: fa_metadata

   :Type: :bro:type:`record`

      mime_type: :bro:type:`string` :bro:attr:`&optional`
         The strongest matching MIME type if one was discovered.

      mime_types: :bro:type:`mime_matches` :bro:attr:`&optional`
         All matching MIME types if any were discovered.

      inferred: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Specifies whether the MIME type was inferred using signatures,
         or provided directly by the protocol the file appeared in.

   Metadata that's been inferred about a particular file.

.. bro:type:: files_tag_set

   :Type: :bro:type:`set` [:bro:type:`Files::Tag`]

   A set of file analyzer tags.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: flow_id

   :Type: :bro:type:`record`

      src_h: :bro:type:`addr` :bro:attr:`&log`
         The source IP address.

      src_p: :bro:type:`port` :bro:attr:`&log`
         The source port number.

      dst_h: :bro:type:`addr` :bro:attr:`&log`
         The destination IP address.

      dst_p: :bro:type:`port` :bro:attr:`&log`
         The desintation port number.
   :Attributes: :bro:attr:`&log`

   The identifying 4-tuple of a uni-directional flow.
   
   .. note:: It's actually a 5-tuple: the transport-layer protocol is stored as
      part of the port values, `src_p` and `dst_p`, and can be extracted from
      them with :bro:id:`get_port_transport_proto`.

.. bro:type:: ftp_port

   :Type: :bro:type:`record`

      h: :bro:type:`addr`
         The host's address.

      p: :bro:type:`port`
         The host's port.

      valid: :bro:type:`bool`
         True if format was right. Only then are *h* and *p* valid.

   A parsed host/port combination describing server endpoint for an upcoming
   data transfer.
   
   .. bro:see:: fmt_ftp_port parse_eftp_port parse_ftp_epsv parse_ftp_pasv
      parse_ftp_port

.. bro:type:: geo_location

   :Type: :bro:type:`record`

      country_code: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         The country code.

      region: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         The region.

      city: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         The city.

      latitude: :bro:type:`double` :bro:attr:`&optional` :bro:attr:`&log`
         Latitude.

      longitude: :bro:type:`double` :bro:attr:`&optional` :bro:attr:`&log`
         Longitude.
   :Attributes: :bro:attr:`&log`

   GeoIP location information.
   
   .. bro:see:: lookup_location

.. bro:type:: gtp_access_point_name

   :Type: :bro:type:`string`


.. bro:type:: gtp_cause

   :Type: :bro:type:`count`


.. bro:type:: gtp_charging_characteristics

   :Type: :bro:type:`count`


.. bro:type:: gtp_charging_gateway_addr

   :Type: :bro:type:`addr`


.. bro:type:: gtp_charging_id

   :Type: :bro:type:`count`


.. bro:type:: gtp_create_pdp_ctx_request_elements

   :Type: :bro:type:`record`

      imsi: :bro:type:`gtp_imsi` :bro:attr:`&optional`

      rai: :bro:type:`gtp_rai` :bro:attr:`&optional`

      recovery: :bro:type:`gtp_recovery` :bro:attr:`&optional`

      select_mode: :bro:type:`gtp_selection_mode` :bro:attr:`&optional`

      data1: :bro:type:`gtp_teid1`

      cp: :bro:type:`gtp_teid_control_plane` :bro:attr:`&optional`

      nsapi: :bro:type:`gtp_nsapi`

      linked_nsapi: :bro:type:`gtp_nsapi` :bro:attr:`&optional`

      charge_character: :bro:type:`gtp_charging_characteristics` :bro:attr:`&optional`

      trace_ref: :bro:type:`gtp_trace_reference` :bro:attr:`&optional`

      trace_type: :bro:type:`gtp_trace_type` :bro:attr:`&optional`

      end_user_addr: :bro:type:`gtp_end_user_addr` :bro:attr:`&optional`

      ap_name: :bro:type:`gtp_access_point_name` :bro:attr:`&optional`

      opts: :bro:type:`gtp_proto_config_options` :bro:attr:`&optional`

      signal_addr: :bro:type:`gtp_gsn_addr`

      user_addr: :bro:type:`gtp_gsn_addr`

      msisdn: :bro:type:`gtp_msisdn` :bro:attr:`&optional`

      qos_prof: :bro:type:`gtp_qos_profile`

      tft: :bro:type:`gtp_tft` :bro:attr:`&optional`

      trigger_id: :bro:type:`gtp_trigger_id` :bro:attr:`&optional`

      omc_id: :bro:type:`gtp_omc_id` :bro:attr:`&optional`

      ext: :bro:type:`gtp_private_extension` :bro:attr:`&optional`


.. bro:type:: gtp_create_pdp_ctx_response_elements

   :Type: :bro:type:`record`

      cause: :bro:type:`gtp_cause`

      reorder_req: :bro:type:`gtp_reordering_required` :bro:attr:`&optional`

      recovery: :bro:type:`gtp_recovery` :bro:attr:`&optional`

      data1: :bro:type:`gtp_teid1` :bro:attr:`&optional`

      cp: :bro:type:`gtp_teid_control_plane` :bro:attr:`&optional`

      charging_id: :bro:type:`gtp_charging_id` :bro:attr:`&optional`

      end_user_addr: :bro:type:`gtp_end_user_addr` :bro:attr:`&optional`

      opts: :bro:type:`gtp_proto_config_options` :bro:attr:`&optional`

      cp_addr: :bro:type:`gtp_gsn_addr` :bro:attr:`&optional`

      user_addr: :bro:type:`gtp_gsn_addr` :bro:attr:`&optional`

      qos_prof: :bro:type:`gtp_qos_profile` :bro:attr:`&optional`

      charge_gateway: :bro:type:`gtp_charging_gateway_addr` :bro:attr:`&optional`

      ext: :bro:type:`gtp_private_extension` :bro:attr:`&optional`


.. bro:type:: gtp_delete_pdp_ctx_request_elements

   :Type: :bro:type:`record`

      teardown_ind: :bro:type:`gtp_teardown_ind` :bro:attr:`&optional`

      nsapi: :bro:type:`gtp_nsapi`

      ext: :bro:type:`gtp_private_extension` :bro:attr:`&optional`


.. bro:type:: gtp_delete_pdp_ctx_response_elements

   :Type: :bro:type:`record`

      cause: :bro:type:`gtp_cause`

      ext: :bro:type:`gtp_private_extension` :bro:attr:`&optional`


.. bro:type:: gtp_end_user_addr

   :Type: :bro:type:`record`

      pdp_type_org: :bro:type:`count`

      pdp_type_num: :bro:type:`count`

      pdp_ip: :bro:type:`addr` :bro:attr:`&optional`
         Set if the End User Address information element is IPv4/IPv6.

      pdp_other_addr: :bro:type:`string` :bro:attr:`&optional`
         Set if the End User Address information element isn't IPv4/IPv6.


.. bro:type:: gtp_gsn_addr

   :Type: :bro:type:`record`

      ip: :bro:type:`addr` :bro:attr:`&optional`
         If the GSN Address information element has length 4 or 16, then this
         field is set to be the informational element's value interpreted as
         an IPv4 or IPv6 address, respectively.

      other: :bro:type:`string` :bro:attr:`&optional`
         This field is set if it's not an IPv4 or IPv6 address.


.. bro:type:: gtp_imsi

   :Type: :bro:type:`count`


.. bro:type:: gtp_msisdn

   :Type: :bro:type:`string`


.. bro:type:: gtp_nsapi

   :Type: :bro:type:`count`


.. bro:type:: gtp_omc_id

   :Type: :bro:type:`string`


.. bro:type:: gtp_private_extension

   :Type: :bro:type:`record`

      id: :bro:type:`count`

      value: :bro:type:`string`


.. bro:type:: gtp_proto_config_options

   :Type: :bro:type:`string`


.. bro:type:: gtp_qos_profile

   :Type: :bro:type:`record`

      priority: :bro:type:`count`

      data: :bro:type:`string`


.. bro:type:: gtp_rai

   :Type: :bro:type:`record`

      mcc: :bro:type:`count`

      mnc: :bro:type:`count`

      lac: :bro:type:`count`

      rac: :bro:type:`count`


.. bro:type:: gtp_recovery

   :Type: :bro:type:`count`


.. bro:type:: gtp_reordering_required

   :Type: :bro:type:`bool`


.. bro:type:: gtp_selection_mode

   :Type: :bro:type:`count`


.. bro:type:: gtp_teardown_ind

   :Type: :bro:type:`bool`


.. bro:type:: gtp_teid1

   :Type: :bro:type:`count`


.. bro:type:: gtp_teid_control_plane

   :Type: :bro:type:`count`


.. bro:type:: gtp_tft

   :Type: :bro:type:`string`


.. bro:type:: gtp_trace_reference

   :Type: :bro:type:`count`


.. bro:type:: gtp_trace_type

   :Type: :bro:type:`count`


.. bro:type:: gtp_trigger_id

   :Type: :bro:type:`string`


.. bro:type:: gtp_update_pdp_ctx_request_elements

   :Type: :bro:type:`record`

      imsi: :bro:type:`gtp_imsi` :bro:attr:`&optional`

      rai: :bro:type:`gtp_rai` :bro:attr:`&optional`

      recovery: :bro:type:`gtp_recovery` :bro:attr:`&optional`

      data1: :bro:type:`gtp_teid1`

      cp: :bro:type:`gtp_teid_control_plane` :bro:attr:`&optional`

      nsapi: :bro:type:`gtp_nsapi`

      trace_ref: :bro:type:`gtp_trace_reference` :bro:attr:`&optional`

      trace_type: :bro:type:`gtp_trace_type` :bro:attr:`&optional`

      cp_addr: :bro:type:`gtp_gsn_addr`

      user_addr: :bro:type:`gtp_gsn_addr`

      qos_prof: :bro:type:`gtp_qos_profile`

      tft: :bro:type:`gtp_tft` :bro:attr:`&optional`

      trigger_id: :bro:type:`gtp_trigger_id` :bro:attr:`&optional`

      omc_id: :bro:type:`gtp_omc_id` :bro:attr:`&optional`

      ext: :bro:type:`gtp_private_extension` :bro:attr:`&optional`

      end_user_addr: :bro:type:`gtp_end_user_addr` :bro:attr:`&optional`


.. bro:type:: gtp_update_pdp_ctx_response_elements

   :Type: :bro:type:`record`

      cause: :bro:type:`gtp_cause`

      recovery: :bro:type:`gtp_recovery` :bro:attr:`&optional`

      data1: :bro:type:`gtp_teid1` :bro:attr:`&optional`

      cp: :bro:type:`gtp_teid_control_plane` :bro:attr:`&optional`

      charging_id: :bro:type:`gtp_charging_id` :bro:attr:`&optional`

      cp_addr: :bro:type:`gtp_gsn_addr` :bro:attr:`&optional`

      user_addr: :bro:type:`gtp_gsn_addr` :bro:attr:`&optional`

      qos_prof: :bro:type:`gtp_qos_profile` :bro:attr:`&optional`

      charge_gateway: :bro:type:`gtp_charging_gateway_addr` :bro:attr:`&optional`

      ext: :bro:type:`gtp_private_extension` :bro:attr:`&optional`


.. bro:type:: gtpv1_hdr

   :Type: :bro:type:`record`

      version: :bro:type:`count`
         The 3-bit version field, which for GTPv1 should be 1.

      pt_flag: :bro:type:`bool`
         Protocol Type value differentiates GTP (value 1) from GTP' (value 0).

      rsv: :bro:type:`bool`
         Reserved field, should be 0.

      e_flag: :bro:type:`bool`
         Extension Header flag.  When 0, the *next_type* field may or may not
         be present, but shouldn't be meaningful.  When 1, *next_type* is
         present and meaningful.

      s_flag: :bro:type:`bool`
         Sequence Number flag.  When 0, the *seq* field may or may not
         be present, but shouldn't be meaningful.  When 1, *seq* is
         present and meaningful.

      pn_flag: :bro:type:`bool`
         N-PDU flag.  When 0, the *n_pdu* field may or may not
         be present, but shouldn't be meaningful.  When 1, *n_pdu* is
         present and meaningful.

      msg_type: :bro:type:`count`
         Message Type.  A value of 255 indicates user-plane data is encapsulated.

      length: :bro:type:`count`
         Length of the GTP packet payload (the rest of the packet following
         the mandatory 8-byte GTP header).

      teid: :bro:type:`count`
         Tunnel Endpoint Identifier.  Unambiguously identifies a tunnel
         endpoint in receiving GTP-U or GTP-C protocol entity.

      seq: :bro:type:`count` :bro:attr:`&optional`
         Sequence Number.  Set if any *e_flag*, *s_flag*, or *pn_flag* field
         is set.

      n_pdu: :bro:type:`count` :bro:attr:`&optional`
         N-PDU Number.  Set if any *e_flag*, *s_flag*, or *pn_flag* field is set.

      next_type: :bro:type:`count` :bro:attr:`&optional`
         Next Extension Header Type.  Set if any *e_flag*, *s_flag*, or
         *pn_flag* field is set.

   A GTPv1 (GPRS Tunneling Protocol) header.

.. bro:type:: http_message_stat

   :Type: :bro:type:`record`

      start: :bro:type:`time`
         When the request/reply line was complete.

      interrupted: :bro:type:`bool`
         Whether the message was interrupted.

      finish_msg: :bro:type:`string`
         Reason phrase if interrupted.

      body_length: :bro:type:`count`
         Length of body processed (before finished/interrupted).

      content_gap_length: :bro:type:`count`
         Total length of gaps within *body_length*.

      header_length: :bro:type:`count`
         Length of headers (including the req/reply line, but not CR/LF's).

   HTTP message statistics.
   
   .. bro:see:: http_message_done

.. bro:type:: http_stats_rec

   :Type: :bro:type:`record`

      num_requests: :bro:type:`count`
         Number of requests.

      num_replies: :bro:type:`count`
         Number of replies.

      request_version: :bro:type:`double`
         HTTP version of the requests.

      reply_version: :bro:type:`double`
         HTTP Version of the replies.

   HTTP session statistics.
   
   .. bro:see:: http_stats

.. bro:type:: icmp6_nd_option

   :Type: :bro:type:`record`

      otype: :bro:type:`count`
         8-bit identifier of the type of option.

      len: :bro:type:`count`
         8-bit integer representing the length of the option (including the
         type and length fields) in units of 8 octets.

      link_address: :bro:type:`string` :bro:attr:`&optional`
         Source Link-Layer Address (Type 1) or Target Link-Layer Address (Type 2).
         Byte ordering of this is dependent on the actual link-layer.

      prefix: :bro:type:`icmp6_nd_prefix_info` :bro:attr:`&optional`
         Prefix Information (Type 3).

      redirect: :bro:type:`icmp_context` :bro:attr:`&optional`
         Redirected header (Type 4).  This field contains the context of the
         original, redirected packet.

      mtu: :bro:type:`count` :bro:attr:`&optional`
         Recommended MTU for the link (Type 5).

      payload: :bro:type:`string` :bro:attr:`&optional`
         The raw data of the option (everything after type & length fields),
         useful for unknown option types or when the full option payload is
         truncated in the captured packet.  In those cases, option fields
         won't be pre-extracted into the fields above.

   Options extracted from ICMPv6 neighbor discovery messages as specified
   by :rfc:`4861`.
   
   .. bro:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_advertisement icmp_neighbor_solicitation icmp_redirect
      icmp6_nd_options

.. bro:type:: icmp6_nd_options

   :Type: :bro:type:`vector` of :bro:type:`icmp6_nd_option`

   A type alias for a vector of ICMPv6 neighbor discovery message options.

.. bro:type:: icmp6_nd_prefix_info

   :Type: :bro:type:`record`

      prefix_len: :bro:type:`count`
         Number of leading bits of the *prefix* that are valid.

      L_flag: :bro:type:`bool`
         Flag indicating the prefix can be used for on-link determination.

      A_flag: :bro:type:`bool`
         Autonomous address-configuration flag.

      valid_lifetime: :bro:type:`interval`
         Length of time in seconds that the prefix is valid for purpose of
         on-link determination (0xffffffff represents infinity).

      preferred_lifetime: :bro:type:`interval`
         Length of time in seconds that the addresses generated from the
         prefix via stateless address autoconfiguration remain preferred
         (0xffffffff represents infinity).

      prefix: :bro:type:`addr`
         An IP address or prefix of an IP address.  Use the *prefix_len* field
         to convert this into a :bro:type:`subnet`.

   Values extracted from a Prefix Information option in an ICMPv6 neighbor
   discovery message as specified by :rfc:`4861`.
   
   .. bro:see:: icmp6_nd_option

.. bro:type:: icmp_conn

   :Type: :bro:type:`record`

      orig_h: :bro:type:`addr`
         The originator's IP address.

      resp_h: :bro:type:`addr`
         The responder's IP address.

      itype: :bro:type:`count`
         The ICMP type of the packet that triggered the instantiation of the record.

      icode: :bro:type:`count`
         The ICMP code of the packet that triggered the instantiation of the record.

      len: :bro:type:`count`
         The length of the ICMP payload of the packet that triggered the instantiation of the record.

      hlim: :bro:type:`count`
         The encapsulating IP header's Hop Limit value.

      v6: :bro:type:`bool`
         True if it's an ICMPv6 packet.

   Specifics about an ICMP conversation. ICMP events typically pass this in
   addition to :bro:type:`conn_id`.
   
   .. bro:see:: icmp_echo_reply icmp_echo_request icmp_redirect icmp_sent
      icmp_time_exceeded icmp_unreachable

.. bro:type:: icmp_context

   :Type: :bro:type:`record`

      id: :bro:type:`conn_id`
         The packet's 4-tuple.

      len: :bro:type:`count`
         The length of the IP packet (headers + payload).

      proto: :bro:type:`count`
         The packet's transport-layer protocol.

      frag_offset: :bro:type:`count`
         The packet's fragmentation offset.

      bad_hdr_len: :bro:type:`bool`
         True if the packet's IP header is not fully included in the context
         or if there is not enough of the transport header to determine source
         and destination ports. If that is the case, the appropriate fields
         of this record will be set to null values.

      bad_checksum: :bro:type:`bool`
         True if the packet's IP checksum is not correct.

      MF: :bro:type:`bool`
         True if the packet's *more fragments* flag is set.

      DF: :bro:type:`bool`
         True if the packet's *don't fragment* flag is set.

   Packet context part of an ICMP message. The fields of this record reflect the
   packet that is described by the context.
   
   .. bro:see:: icmp_time_exceeded icmp_unreachable

.. bro:type:: icmp_hdr

   :Type: :bro:type:`record`

      icmp_type: :bro:type:`count`
         type of message

   Values extracted from an ICMP header.
   
   .. bro:see:: pkt_hdr discarder_check_icmp

.. bro:type:: id_table

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`script_id`

   Table type used to map script-level identifiers to meta-information
   describing them.
   
   .. bro:see:: global_ids script_id
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: index_vec

   :Type: :bro:type:`vector` of :bro:type:`count`

   A vector of counts, used by some builtin functions to store a list of indices.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: interconn_endp_stats

   :Type: :bro:type:`record`

      num_pkts: :bro:type:`count`

      num_keystrokes_two_in_row: :bro:type:`count`

      num_normal_interarrivals: :bro:type:`count`

      num_8k0_pkts: :bro:type:`count`

      num_8k4_pkts: :bro:type:`count`

      is_partial: :bro:type:`bool`

      num_bytes: :bro:type:`count`

      num_7bit_ascii: :bro:type:`count`

      num_lines: :bro:type:`count`

      num_normal_lines: :bro:type:`count`

   Deprecated.

.. bro:type:: ip4_hdr

   :Type: :bro:type:`record`

      hl: :bro:type:`count`
         Header length in bytes.

      tos: :bro:type:`count`
         Type of service.

      len: :bro:type:`count`
         Total length.

      id: :bro:type:`count`
         Identification.

      ttl: :bro:type:`count`
         Time to live.

      p: :bro:type:`count`
         Protocol.

      src: :bro:type:`addr`
         Source address.

      dst: :bro:type:`addr`
         Destination address.

   Values extracted from an IPv4 header.
   
   .. bro:see:: pkt_hdr ip6_hdr discarder_check_ip

.. bro:type:: ip6_ah

   :Type: :bro:type:`record`

      nxt: :bro:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :bro:id:`IPPROTO_ICMP`.

      len: :bro:type:`count`
         Length of header in 4-octet units, excluding first two units.

      rsv: :bro:type:`count`
         Reserved field.

      spi: :bro:type:`count`
         Security Parameter Index.

      seq: :bro:type:`count` :bro:attr:`&optional`
         Sequence number, unset in the case that *len* field is zero.

      data: :bro:type:`string` :bro:attr:`&optional`
         Authentication data, unset in the case that *len* field is zero.

   Values extracted from an IPv6 Authentication extension header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. bro:type:: ip6_dstopts

   :Type: :bro:type:`record`

      nxt: :bro:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :bro:id:`IPPROTO_ICMP`.

      len: :bro:type:`count`
         Length of header in 8-octet units, excluding first unit.

      options: :bro:type:`ip6_options`
         The TLV encoded options;

   Values extracted from an IPv6 Destination options extension header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr ip6_option

.. bro:type:: ip6_esp

   :Type: :bro:type:`record`

      spi: :bro:type:`count`
         Security Parameters Index.

      seq: :bro:type:`count`
         Sequence number.

   Values extracted from an IPv6 ESP extension header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. bro:type:: ip6_ext_hdr

   :Type: :bro:type:`record`

      id: :bro:type:`count`
         The RFC 1700 et seq. IANA assigned number identifying the type of
         the extension header.

      hopopts: :bro:type:`ip6_hopopts` :bro:attr:`&optional`
         Hop-by-hop option extension header.

      dstopts: :bro:type:`ip6_dstopts` :bro:attr:`&optional`
         Destination option extension header.

      routing: :bro:type:`ip6_routing` :bro:attr:`&optional`
         Routing extension header.

      fragment: :bro:type:`ip6_fragment` :bro:attr:`&optional`
         Fragment header.

      ah: :bro:type:`ip6_ah` :bro:attr:`&optional`
         Authentication extension header.

      esp: :bro:type:`ip6_esp` :bro:attr:`&optional`
         Encapsulating security payload header.

      mobility: :bro:type:`ip6_mobility_hdr` :bro:attr:`&optional`
         Mobility header.

   A general container for a more specific IPv6 extension header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_hopopts ip6_dstopts ip6_routing ip6_fragment
      ip6_ah ip6_esp

.. bro:type:: ip6_ext_hdr_chain

   :Type: :bro:type:`vector` of :bro:type:`ip6_ext_hdr`

   A type alias for a vector of IPv6 extension headers.

.. bro:type:: ip6_fragment

   :Type: :bro:type:`record`

      nxt: :bro:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :bro:id:`IPPROTO_ICMP`.

      rsv1: :bro:type:`count`
         8-bit reserved field.

      offset: :bro:type:`count`
         Fragmentation offset.

      rsv2: :bro:type:`count`
         2-bit reserved field.

      more: :bro:type:`bool`
         More fragments.

      id: :bro:type:`count`
         Fragment identification.

   Values extracted from an IPv6 Fragment extension header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. bro:type:: ip6_hdr

   :Type: :bro:type:`record`

      class: :bro:type:`count`
         Traffic class.

      flow: :bro:type:`count`
         Flow label.

      len: :bro:type:`count`
         Payload length.

      nxt: :bro:type:`count`
         Protocol number of the next header
         (RFC 1700 et seq., IANA assigned number)
         e.g. :bro:id:`IPPROTO_ICMP`.

      hlim: :bro:type:`count`
         Hop limit.

      src: :bro:type:`addr`
         Source address.

      dst: :bro:type:`addr`
         Destination address.

      exts: :bro:type:`ip6_ext_hdr_chain`
         Extension header chain.

   Values extracted from an IPv6 header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_ext_hdr ip6_hopopts ip6_dstopts
      ip6_routing ip6_fragment ip6_ah ip6_esp

.. bro:type:: ip6_hopopts

   :Type: :bro:type:`record`

      nxt: :bro:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :bro:id:`IPPROTO_ICMP`.

      len: :bro:type:`count`
         Length of header in 8-octet units, excluding first unit.

      options: :bro:type:`ip6_options`
         The TLV encoded options;

   Values extracted from an IPv6 Hop-by-Hop options extension header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr ip6_option

.. bro:type:: ip6_mobility_back

   :Type: :bro:type:`record`

      status: :bro:type:`count`
         Status.

      k: :bro:type:`bool`
         Key Management Mobility Capability.

      seq: :bro:type:`count`
         Sequence number.

      life: :bro:type:`count`
         Lifetime.

      options: :bro:type:`vector` of :bro:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Binding Acknowledgement message.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. bro:type:: ip6_mobility_be

   :Type: :bro:type:`record`

      status: :bro:type:`count`
         Status.

      hoa: :bro:type:`addr`
         Home Address.

      options: :bro:type:`vector` of :bro:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Binding Error message.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. bro:type:: ip6_mobility_brr

   :Type: :bro:type:`record`

      rsv: :bro:type:`count`
         Reserved.

      options: :bro:type:`vector` of :bro:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Binding Refresh Request message.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. bro:type:: ip6_mobility_bu

   :Type: :bro:type:`record`

      seq: :bro:type:`count`
         Sequence number.

      a: :bro:type:`bool`
         Acknowledge bit.

      h: :bro:type:`bool`
         Home Registration bit.

      l: :bro:type:`bool`
         Link-Local Address Compatibility bit.

      k: :bro:type:`bool`
         Key Management Mobility Capability bit.

      life: :bro:type:`count`
         Lifetime.

      options: :bro:type:`vector` of :bro:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Binding Update message.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. bro:type:: ip6_mobility_cot

   :Type: :bro:type:`record`

      nonce_idx: :bro:type:`count`
         Care-of Nonce Index.

      cookie: :bro:type:`count`
         Care-of Init Cookie.

      token: :bro:type:`count`
         Care-of Keygen Token.

      options: :bro:type:`vector` of :bro:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Care-of Test message.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. bro:type:: ip6_mobility_coti

   :Type: :bro:type:`record`

      rsv: :bro:type:`count`
         Reserved.

      cookie: :bro:type:`count`
         Care-of Init Cookie.

      options: :bro:type:`vector` of :bro:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Care-of Test Init message.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. bro:type:: ip6_mobility_hdr

   :Type: :bro:type:`record`

      nxt: :bro:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :bro:id:`IPPROTO_ICMP`.

      len: :bro:type:`count`
         Length of header in 8-octet units, excluding first unit.

      mh_type: :bro:type:`count`
         Mobility header type used to identify header's the message.

      rsv: :bro:type:`count`
         Reserved field.

      chksum: :bro:type:`count`
         Mobility header checksum.

      msg: :bro:type:`ip6_mobility_msg`
         Mobility header message

   Values extracted from an IPv6 Mobility header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. bro:type:: ip6_mobility_hot

   :Type: :bro:type:`record`

      nonce_idx: :bro:type:`count`
         Home Nonce Index.

      cookie: :bro:type:`count`
         Home Init Cookie.

      token: :bro:type:`count`
         Home Keygen Token.

      options: :bro:type:`vector` of :bro:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Home Test message.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. bro:type:: ip6_mobility_hoti

   :Type: :bro:type:`record`

      rsv: :bro:type:`count`
         Reserved.

      cookie: :bro:type:`count`
         Home Init Cookie.

      options: :bro:type:`vector` of :bro:type:`ip6_option`
         Mobility Options.

   Values extracted from an IPv6 Mobility Home Test Init message.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg

.. bro:type:: ip6_mobility_msg

   :Type: :bro:type:`record`

      id: :bro:type:`count`
         The type of message from the header's MH Type field.

      brr: :bro:type:`ip6_mobility_brr` :bro:attr:`&optional`
         Binding Refresh Request.

      hoti: :bro:type:`ip6_mobility_hoti` :bro:attr:`&optional`
         Home Test Init.

      coti: :bro:type:`ip6_mobility_coti` :bro:attr:`&optional`
         Care-of Test Init.

      hot: :bro:type:`ip6_mobility_hot` :bro:attr:`&optional`
         Home Test.

      cot: :bro:type:`ip6_mobility_cot` :bro:attr:`&optional`
         Care-of Test.

      bu: :bro:type:`ip6_mobility_bu` :bro:attr:`&optional`
         Binding Update.

      back: :bro:type:`ip6_mobility_back` :bro:attr:`&optional`
         Binding Acknowledgement.

      be: :bro:type:`ip6_mobility_be` :bro:attr:`&optional`
         Binding Error.

   Values extracted from an IPv6 Mobility header's message data.
   
   .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr

.. bro:type:: ip6_option

   :Type: :bro:type:`record`

      otype: :bro:type:`count`
         Option type.

      len: :bro:type:`count`
         Option data length.

      data: :bro:type:`string`
         Option data.

   Values extracted from an IPv6 extension header's (e.g. hop-by-hop or
   destination option headers) option field.
   
   .. bro:see:: ip6_hdr ip6_ext_hdr ip6_hopopts ip6_dstopts

.. bro:type:: ip6_options

   :Type: :bro:type:`vector` of :bro:type:`ip6_option`

   A type alias for a vector of IPv6 options.

.. bro:type:: ip6_routing

   :Type: :bro:type:`record`

      nxt: :bro:type:`count`
         Protocol number of the next header (RFC 1700 et seq., IANA assigned
         number), e.g. :bro:id:`IPPROTO_ICMP`.

      len: :bro:type:`count`
         Length of header in 8-octet units, excluding first unit.

      rtype: :bro:type:`count`
         Routing type.

      segleft: :bro:type:`count`
         Segments left.

      data: :bro:type:`string`
         Type-specific data.

   Values extracted from an IPv6 Routing extension header.
   
   .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr

.. bro:type:: irc_join_info

   :Type: :bro:type:`record`

      nick: :bro:type:`string`

      channel: :bro:type:`string`

      password: :bro:type:`string`

      usermode: :bro:type:`string`

   IRC join information.
   
   .. bro:see:: irc_join_list

.. bro:type:: irc_join_list

   :Type: :bro:type:`set` [:bro:type:`irc_join_info`]

   Set of IRC join information.
   
   .. bro:see:: irc_join_message

.. bro:type:: l2_hdr

   :Type: :bro:type:`record`

      encap: :bro:type:`link_encap`
         L2 link encapsulation.

      len: :bro:type:`count`
         Total frame length on wire.

      cap_len: :bro:type:`count`
         Captured length.

      src: :bro:type:`string` :bro:attr:`&optional`
         L2 source (if Ethernet).

      dst: :bro:type:`string` :bro:attr:`&optional`
         L2 destination (if Ethernet).

      vlan: :bro:type:`count` :bro:attr:`&optional`
         Outermost VLAN tag if any (and Ethernet).

      inner_vlan: :bro:type:`count` :bro:attr:`&optional`
         Innermost VLAN tag if any (and Ethernet).

      eth_type: :bro:type:`count` :bro:attr:`&optional`
         Innermost Ethertype (if Ethernet).

      proto: :bro:type:`layer3_proto`
         L3 protocol.

   Values extracted from the layer 2 header.
   
   .. bro:see:: pkt_hdr

.. bro:type:: load_sample_info

   :Type: :bro:type:`set` [:bro:type:`string`]


.. bro:type:: mime_header_list

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`mime_header_rec`

   A list of MIME headers.
   
   .. bro:see:: mime_header_rec http_all_headers mime_all_headers

.. bro:type:: mime_header_rec

   :Type: :bro:type:`record`

      name: :bro:type:`string`
         The header name.

      value: :bro:type:`string`
         The header value.

   A MIME header key/value pair.
   
   .. bro:see:: mime_header_list http_all_headers mime_all_headers mime_one_header

.. bro:type:: mime_match

   :Type: :bro:type:`record`

      strength: :bro:type:`int`
         How strongly the signature matched.  Used for
         prioritization when multiple file magic signatures
         match.

      mime: :bro:type:`string`
         The MIME type of the file magic signature match.

   A structure indicating a MIME type and strength of a match against
   file magic signatures.
   
   :bro:see:`file_magic`

.. bro:type:: mime_matches

   :Type: :bro:type:`vector` of :bro:type:`mime_match`

   A vector of file magic signature matches, ordered by strength of
   the signature, strongest first.
   
   :bro:see:`file_magic`

.. bro:type:: ntp_msg

   :Type: :bro:type:`record`

      id: :bro:type:`count`
         Message ID.

      code: :bro:type:`count`
         Message code.

      stratum: :bro:type:`count`
         Stratum.

      poll: :bro:type:`count`
         Poll.

      precision: :bro:type:`int`
         Precision.

      distance: :bro:type:`interval`
         Distance.

      dispersion: :bro:type:`interval`
         Dispersion.

      ref_t: :bro:type:`time`
         Reference time.

      originate_t: :bro:type:`time`
         Originating time.

      receive_t: :bro:type:`time`
         Receive time.

      xmit_t: :bro:type:`time`
         Send time.

   An NTP message.
   
   .. bro:see:: ntp_message

.. bro:type:: packet

   :Type: :bro:type:`record`

      conn: :bro:type:`connection`

      is_orig: :bro:type:`bool`

      seq: :bro:type:`count`
         seq=k => it is the kth *packet* of the connection

      timestamp: :bro:type:`time`

   Deprecated.
   
   .. todo:: Remove. It's still declared internally but doesn't seem  used anywhere
      else.

.. bro:type:: pcap_packet

   :Type: :bro:type:`record`

      ts_sec: :bro:type:`count`
         The non-fractional part of the packet's timestamp (i.e., full seconds since the epoch).

      ts_usec: :bro:type:`count`
         The fractional part of the packet's timestamp.

      caplen: :bro:type:`count`
         The number of bytes captured (<= *len*).

      len: :bro:type:`count`
         The length of the packet in bytes, including link-level header.

      data: :bro:type:`string`
         The payload of the packet, including link-level header.

      link_type: :bro:type:`link_encap`
         Layer 2 link encapsulation type.

   Policy-level representation of a packet passed on by libpcap. The data
   includes the complete packet as returned by libpcap, including the link-layer
   header.
   
   .. bro:see:: dump_packet get_current_packet

.. bro:type:: peer_id

   :Type: :bro:type:`count`

   A locally unique ID identifying a communication peer. The ID is returned by
   :bro:id:`connect`.
   
   .. bro:see:: connect

.. bro:type:: pkt_hdr

   :Type: :bro:type:`record`

      ip: :bro:type:`ip4_hdr` :bro:attr:`&optional`
         The IPv4 header if an IPv4 packet.

      ip6: :bro:type:`ip6_hdr` :bro:attr:`&optional`
         The IPv6 header if an IPv6 packet.

      tcp: :bro:type:`tcp_hdr` :bro:attr:`&optional`
         The TCP header if a TCP packet.

      udp: :bro:type:`udp_hdr` :bro:attr:`&optional`
         The UDP header if a UDP packet.

      icmp: :bro:type:`icmp_hdr` :bro:attr:`&optional`
         The ICMP header if an ICMP packet.

   A packet header, consisting of an IP header and transport-layer header.
   
   .. bro:see:: new_packet

.. bro:type:: pkt_profile_modes

   :Type: :bro:type:`enum`

      .. bro:enum:: PKT_PROFILE_MODE_NONE pkt_profile_modes

         No output.

      .. bro:enum:: PKT_PROFILE_MODE_SECS pkt_profile_modes

         Output every :bro:see:`pkt_profile_freq` seconds.

      .. bro:enum:: PKT_PROFILE_MODE_PKTS pkt_profile_modes

         Output every :bro:see:`pkt_profile_freq` packets.

      .. bro:enum:: PKT_PROFILE_MODE_BYTES pkt_profile_modes

         Output every :bro:see:`pkt_profile_freq` bytes.

   Output modes for packet profiling information.
   
   .. bro:see:: pkt_profile_mode pkt_profile_freq pkt_profile_file

.. bro:type:: pm_callit_request

   :Type: :bro:type:`record`

      program: :bro:type:`count`
         The RPC program.

      version: :bro:type:`count`
         The program version.

      proc: :bro:type:`count`
         The procedure being called.

      arg_size: :bro:type:`count`
         The size of the argument.

   An RPC portmapper *callit* request.
   
   .. bro:see:: pm_attempt_callit pm_request_callit

.. bro:type:: pm_mapping

   :Type: :bro:type:`record`

      program: :bro:type:`count`
         The RPC program.

      version: :bro:type:`count`
         The program version.

      p: :bro:type:`port`
         The port.

   An RPC portmapper mapping.
   
   .. bro:see:: pm_mappings

.. bro:type:: pm_mappings

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`pm_mapping`

   Table of RPC portmapper mappings.
   
   .. bro:see:: pm_request_dump

.. bro:type:: pm_port_request

   :Type: :bro:type:`record`

      program: :bro:type:`count`
         The RPC program.

      version: :bro:type:`count`
         The program version.

      is_tcp: :bro:type:`bool`
         True if using TCP.

   An RPC portmapper request.
   
   .. bro:see:: pm_attempt_getport pm_request_getport

.. bro:type:: raw_pkt_hdr

   :Type: :bro:type:`record`

      l2: :bro:type:`l2_hdr`
         The layer 2 header.

      ip: :bro:type:`ip4_hdr` :bro:attr:`&optional`
         The IPv4 header if an IPv4 packet.

      ip6: :bro:type:`ip6_hdr` :bro:attr:`&optional`
         The IPv6 header if an IPv6 packet.

      tcp: :bro:type:`tcp_hdr` :bro:attr:`&optional`
         The TCP header if a TCP packet.

      udp: :bro:type:`udp_hdr` :bro:attr:`&optional`
         The UDP header if a UDP packet.

      icmp: :bro:type:`icmp_hdr` :bro:attr:`&optional`
         The ICMP header if an ICMP packet.

   A raw packet header, consisting of L2 header and everything in
   :bro:see:`pkt_hdr`. .
   
   .. bro:see:: raw_packet pkt_hdr

.. bro:type:: record_field

   :Type: :bro:type:`record`

      type_name: :bro:type:`string`
         The name of the field's type.

      log: :bro:type:`bool`
         True if the field is declared with :bro:attr:`&log` attribute.

      value: :bro:type:`any` :bro:attr:`&optional`
         The current value of the field in the record instance passed into
         :bro:see:`record_fields` (if it has one).

      default_val: :bro:type:`any` :bro:attr:`&optional`
         The value of the :bro:attr:`&default` attribute if defined.

   Meta-information about a record field.
   
   .. bro:see:: record_fields record_field_table

.. bro:type:: record_field_table

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`record_field`

   Table type used to map record field declarations to meta-information
   describing them.
   
   .. bro:see:: record_fields record_field
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: rotate_info

   :Type: :bro:type:`record`

      old_name: :bro:type:`string`
         Original filename.

      new_name: :bro:type:`string`
         File name after rotation.

      open: :bro:type:`time`
         Time when opened.

      close: :bro:type:`time`
         Time when closed.

   Deprecated.
   
   .. bro:see:: rotate_file rotate_file_by_name rotate_interval

.. bro:type:: script_id

   :Type: :bro:type:`record`

      type_name: :bro:type:`string`
         The name of the identifier's type.

      exported: :bro:type:`bool`
         True if the identifier is exported.

      constant: :bro:type:`bool`
         True if the identifier is a constant.

      enum_constant: :bro:type:`bool`
         True if the identifier is an enum value.

      option_value: :bro:type:`bool`
         True if the identifier is an option.

      redefinable: :bro:type:`bool`
         True if the identifier is declared with the :bro:attr:`&redef` attribute.

      value: :bro:type:`any` :bro:attr:`&optional`
         The current value of the identifier.

   Meta-information about a script-level identifier.
   
   .. bro:see:: global_ids id_table

.. bro:type:: signature_and_hashalgorithm_vec

   :Type: :bro:type:`vector` of :bro:type:`SSL::SignatureAndHashAlgorithm`

   A vector of Signature and Hash Algorithms.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: signature_state

   :Type: :bro:type:`record`

      sig_id: :bro:type:`string`
         ID of the matching signature.

      conn: :bro:type:`connection`
         Matching connection.

      is_orig: :bro:type:`bool`
         True if matching endpoint is originator.

      payload_size: :bro:type:`count`
         Payload size of the first matching packet of current endpoint.

   Description of a signature match.
   
   .. bro:see:: signature_match

.. bro:type:: software

   :Type: :bro:type:`record`

      name: :bro:type:`string`

      version: :bro:type:`software_version`


.. bro:type:: software_version

   :Type: :bro:type:`record`

      major: :bro:type:`int`

      minor: :bro:type:`int`

      minor2: :bro:type:`int`

      addl: :bro:type:`string`


.. bro:type:: string_array

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`

   An ordered array of strings. The entries are indexed by successive numbers.
   Note that it depends on the usage whether the first index is zero or one.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: string_set

   :Type: :bro:type:`set` [:bro:type:`string`]

   A set of strings.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: string_vec

   :Type: :bro:type:`vector` of :bro:type:`string`

   A vector of strings.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: subnet_vec

   :Type: :bro:type:`vector` of :bro:type:`subnet`

   A vector of subnets.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: sw_align

   :Type: :bro:type:`record`

      str: :bro:type:`string`
         String a substring is part of.

      index: :bro:type:`count`
         Offset substring is located.

   Helper type for return value of Smith-Waterman algorithm.
   
   .. bro:see:: str_smith_waterman sw_substring_vec sw_substring sw_align_vec sw_params

.. bro:type:: sw_align_vec

   :Type: :bro:type:`vector` of :bro:type:`sw_align`

   Helper type for return value of Smith-Waterman algorithm.
   
   .. bro:see:: str_smith_waterman sw_substring_vec sw_substring sw_align sw_params

.. bro:type:: sw_params

   :Type: :bro:type:`record`

      min_strlen: :bro:type:`count` :bro:attr:`&default` = ``3`` :bro:attr:`&optional`
         Minimum size of a substring, minimum "granularity".

      sw_variant: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Smith-Waterman flavor to use.

   Parameters for the Smith-Waterman algorithm.
   
   .. bro:see:: str_smith_waterman

.. bro:type:: sw_substring

   :Type: :bro:type:`record`

      str: :bro:type:`string`
         A substring.

      aligns: :bro:type:`sw_align_vec`
         All strings of which it's a substring.

      new: :bro:type:`bool`
         True if start of new alignment.

   Helper type for return value of Smith-Waterman algorithm.
   
   .. bro:see:: str_smith_waterman sw_substring_vec sw_align_vec sw_align sw_params
   

.. bro:type:: sw_substring_vec

   :Type: :bro:type:`vector` of :bro:type:`sw_substring`

   Return type for Smith-Waterman algorithm.
   
   .. bro:see:: str_smith_waterman sw_substring sw_align_vec sw_align sw_params
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: table_string_of_count

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`count`

   A table of counts indexed by strings.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: table_string_of_string

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string`

   A table of strings indexed by strings.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: tcp_hdr

   :Type: :bro:type:`record`

      sport: :bro:type:`port`
         source port.

      dport: :bro:type:`port`
         destination port

      seq: :bro:type:`count`
         sequence number

      ack: :bro:type:`count`
         acknowledgement number

      hl: :bro:type:`count`
         header length (in bytes)

      dl: :bro:type:`count`
         data length (xxx: not in original tcphdr!)

      flags: :bro:type:`count`
         flags

      win: :bro:type:`count`
         window

   Values extracted from a TCP header.
   
   .. bro:see:: pkt_hdr discarder_check_tcp

.. bro:type:: teredo_auth

   :Type: :bro:type:`record`

      id: :bro:type:`string`
         Teredo client identifier.

      value: :bro:type:`string`
         HMAC-SHA1 over shared secret key between client and
         server, nonce, confirmation byte, origin indication
         (if present), and the IPv6 packet.

      nonce: :bro:type:`count`
         Nonce chosen by Teredo client to be repeated by
         Teredo server.

      confirm: :bro:type:`count`
         Confirmation byte to be set to 0 by Teredo client
         and non-zero by server if client needs new key.

   A Teredo origin indication header.  See :rfc:`4380` for more information
   about the Teredo protocol.
   
   .. bro:see:: teredo_bubble teredo_origin_indication teredo_authentication
      teredo_hdr

.. bro:type:: teredo_hdr

   :Type: :bro:type:`record`

      auth: :bro:type:`teredo_auth` :bro:attr:`&optional`
         Teredo authentication header.

      origin: :bro:type:`teredo_origin` :bro:attr:`&optional`
         Teredo origin indication header.

      hdr: :bro:type:`pkt_hdr`
         IPv6 and transport protocol headers.

   A Teredo packet header.  See :rfc:`4380` for more information about the
   Teredo protocol.
   
   .. bro:see:: teredo_bubble teredo_origin_indication teredo_authentication

.. bro:type:: teredo_origin

   :Type: :bro:type:`record`

      p: :bro:type:`port`
         Unobfuscated UDP port of Teredo client.

      a: :bro:type:`addr`
         Unobfuscated IPv4 address of Teredo client.

   A Teredo authentication header.  See :rfc:`4380` for more information
   about the Teredo protocol.
   
   .. bro:see:: teredo_bubble teredo_origin_indication teredo_authentication
      teredo_hdr

.. bro:type:: transport_proto

   :Type: :bro:type:`enum`

      .. bro:enum:: unknown_transport transport_proto

         An unknown transport-layer protocol.

      .. bro:enum:: tcp transport_proto

         TCP.

      .. bro:enum:: udp transport_proto

         UDP.

      .. bro:enum:: icmp transport_proto

         ICMP.

   A connection's transport-layer protocol. Note that Bro uses the term
   "connection" broadly, using flow semantics for ICMP and UDP.

.. bro:type:: udp_hdr

   :Type: :bro:type:`record`

      sport: :bro:type:`port`
         source port

      dport: :bro:type:`port`
         destination port

      ulen: :bro:type:`count`
         udp length

   Values extracted from a UDP header.
   
   .. bro:see:: pkt_hdr discarder_check_udp

.. bro:type:: var_sizes

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`count`

   Table type used to map variable names to their memory allocation.
   
   .. bro:see:: global_sizes
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

.. bro:type:: x509_opaque_vector

   :Type: :bro:type:`vector` of :bro:type:`opaque` of x509

   A vector of x509 opaques.
   
   .. todo:: We need this type definition only for declaring builtin functions
      via ``bifcl``. We should extend ``bifcl`` to understand composite types
      directly and then remove this alias.

Functions
#########
.. bro:id:: add_interface

   :Type: :bro:type:`function` (iold: :bro:type:`string`, inew: :bro:type:`string`) : :bro:type:`string`

   Internal function.

.. bro:id:: add_signature_file

   :Type: :bro:type:`function` (sold: :bro:type:`string`, snew: :bro:type:`string`) : :bro:type:`string`

   Internal function.

.. bro:id:: discarder_check_icmp

   :Type: :bro:type:`function` (p: :bro:type:`pkt_hdr`) : :bro:type:`bool`

   Function for skipping packets based on their ICMP header. If defined, this
   function will be called for all ICMP packets before Bro performs any further
   analysis. If the function signals to discard a packet, no further processing
   will be performed on it.
   

   :p: The IP and ICMP headers of the considered packet.
   

   :returns: True if the packet should not be analyzed any further.
   
   .. bro:see:: discarder_check_ip discarder_check_tcp discarder_check_udp
      discarder_maxlen
   
   .. note:: This is very low-level functionality and potentially expensive.
      Avoid using it.

.. bro:id:: discarder_check_ip

   :Type: :bro:type:`function` (p: :bro:type:`pkt_hdr`) : :bro:type:`bool`

   Function for skipping packets based on their IP header. If defined, this
   function will be called for all IP packets before Bro performs any further
   analysis. If the function signals to discard a packet, no further processing
   will be performed on it.
   

   :p: The IP header of the considered packet.
   

   :returns: True if the packet should not be analyzed any further.
   
   .. bro:see:: discarder_check_tcp discarder_check_udp discarder_check_icmp
      discarder_maxlen
   
   .. note:: This is very low-level functionality and potentially expensive.
      Avoid using it.

.. bro:id:: discarder_check_tcp

   :Type: :bro:type:`function` (p: :bro:type:`pkt_hdr`, d: :bro:type:`string`) : :bro:type:`bool`

   Function for skipping packets based on their TCP header. If defined, this
   function will be called for all TCP packets before Bro performs any further
   analysis. If the function signals to discard a packet, no further processing
   will be performed on it.
   

   :p: The IP and TCP headers of the considered packet.
   

   :d: Up to :bro:see:`discarder_maxlen` bytes of the TCP payload.
   

   :returns: True if the packet should not be analyzed any further.
   
   .. bro:see:: discarder_check_ip discarder_check_udp discarder_check_icmp
      discarder_maxlen
   
   .. note:: This is very low-level functionality and potentially expensive.
      Avoid using it.

.. bro:id:: discarder_check_udp

   :Type: :bro:type:`function` (p: :bro:type:`pkt_hdr`, d: :bro:type:`string`) : :bro:type:`bool`

   Function for skipping packets based on their UDP header. If defined, this
   function will be called for all UDP packets before Bro performs any further
   analysis. If the function signals to discard a packet, no further processing
   will be performed on it.
   

   :p: The IP and UDP headers of the considered packet.
   

   :d: Up to :bro:see:`discarder_maxlen` bytes of the UDP payload.
   

   :returns: True if the packet should not be analyzed any further.
   
   .. bro:see:: discarder_check_ip discarder_check_tcp discarder_check_icmp
      discarder_maxlen
   
   .. note:: This is very low-level functionality and potentially expensive.
      Avoid using it.

.. bro:id:: log_file_name

   :Type: :bro:type:`function` (tag: :bro:type:`string`) : :bro:type:`string`
   :Attributes: :bro:attr:`&redef`

   Deprecated. This is superseded by the new logging framework.

.. bro:id:: max_count

   :Type: :bro:type:`function` (a: :bro:type:`count`, b: :bro:type:`count`) : :bro:type:`count`

   Returns maximum of two ``count`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The maximum of *a* and *b*.

.. bro:id:: max_double

   :Type: :bro:type:`function` (a: :bro:type:`double`, b: :bro:type:`double`) : :bro:type:`double`

   Returns maximum of two ``double`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The maximum of *a* and *b*.

.. bro:id:: max_interval

   :Type: :bro:type:`function` (a: :bro:type:`interval`, b: :bro:type:`interval`) : :bro:type:`interval`

   Returns maximum of two ``interval`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The maximum of *a* and *b*.

.. bro:id:: min_count

   :Type: :bro:type:`function` (a: :bro:type:`count`, b: :bro:type:`count`) : :bro:type:`count`

   Returns minimum of two ``count`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The minimum of *a* and *b*.

.. bro:id:: min_double

   :Type: :bro:type:`function` (a: :bro:type:`double`, b: :bro:type:`double`) : :bro:type:`double`

   Returns minimum of two ``double`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The minimum of *a* and *b*.

.. bro:id:: min_interval

   :Type: :bro:type:`function` (a: :bro:type:`interval`, b: :bro:type:`interval`) : :bro:type:`interval`

   Returns minimum of two ``interval`` values.
   

   :a: First value.

   :b: Second value.
   

   :returns: The minimum of *a* and *b*.

.. bro:id:: open_log_file

   :Type: :bro:type:`function` (tag: :bro:type:`string`) : :bro:type:`file`
   :Attributes: :bro:attr:`&redef`

   Deprecated. This is superseded by the new logging framework.


