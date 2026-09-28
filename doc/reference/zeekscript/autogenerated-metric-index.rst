.. zeek:metric:: process_cpu_system_seconds_total

   :Type: counter
   :Labels:

   Total system CPU time spent

.. zeek:metric:: process_cpu_user_seconds_total

   :Type: counter
   :Labels:

   Total user CPU time spent

.. zeek:metric:: process_open_fds

   :Type: gauge
   :Labels:

   Number of open file descriptors

.. zeek:metric:: process_resident_memory_bytes

   :Type: gauge
   :Labels:

   Resident memory size

.. zeek:metric:: process_start_time_seconds

   :Type: gauge
   :Labels:

   Process start time

.. zeek:metric:: process_virtual_memory_bytes

   :Type: gauge
   :Labels:

   Virtual memory size

.. zeek:metric:: zeek_broker_backpressure_disconnects_total

   :Type: counter
   :Labels: peer

   Number of Broker peerings dropped due to a neighbor falling behind in message I/O

.. zeek:metric:: zeek_broker_incoming_events_total

   :Type: counter
   :Labels:

   Total number of incoming events via broker

.. zeek:metric:: zeek_broker_incoming_ids_total

   :Type: counter
   :Labels:

   Total number of incoming ids via broker

.. zeek:metric:: zeek_broker_incoming_logs_total

   :Type: counter
   :Labels:

   Total number of incoming logs via broker

.. zeek:metric:: zeek_broker_outgoing_events_total

   :Type: counter
   :Labels:

   Total number of outgoing events via broker

.. zeek:metric:: zeek_broker_outgoing_ids_total

   :Type: counter
   :Labels:

   Total number of outgoing ids via broker

.. zeek:metric:: zeek_broker_outgoing_logs_total

   :Type: counter
   :Labels:

   Total number of outgoing logs via broker

.. zeek:metric:: zeek_broker_peer_buffer_messages

   :Type: gauge
   :Labels: peer

   Number of messages queued in Broker's send buffers

.. zeek:metric:: zeek_broker_peer_buffer_overflows_total

   :Type: counter
   :Labels: peer

   Number of overflows in Broker's send buffers

.. zeek:metric:: zeek_broker_peer_buffer_recent_max_messages

   :Type: gauge
   :Labels: peer

   Maximum number of messages recently queued in Broker's send buffers

.. zeek:metric:: zeek_broker_peers

   :Type: gauge
   :Labels:

   Current number of peers connected via broker

.. zeek:metric:: zeek_cluster_core_incoming_events_total

   :Type: counter
   :Labels:

   Number of incoming events

.. zeek:metric:: zeek_cluster_core_outgoing_events_total

   :Type: counter
   :Labels:

   Number of outgoing events

.. zeek:metric:: zeek_dnsmgr_cache_entries

   :Type: gauge
   :Labels: type

   Number of cached hosts in DNS_Mgr

.. zeek:metric:: zeek_dnsmgr_failed_requests_total

   :Type: counter
   :Labels:

   Total number of failed requests through DNS_Mgr

.. zeek:metric:: zeek_dnsmgr_pending_asyncs_requests

   :Type: gauge
   :Labels:

   Number of pending async requests through DNS_Mgr

.. zeek:metric:: zeek_dnsmgr_requests_total

   :Type: counter
   :Labels:

   Total number of requests through DNS_Mgr

.. zeek:metric:: zeek_dnsmgr_successful_requests_total

   :Type: counter
   :Labels:

   Total number of successful requests through DNS_Mgr

.. zeek:metric:: zeek_log_stream_writes_total

   :Type: counter
   :Labels: module stream

   Total number of log writes for the given stream.

.. zeek:metric:: zeek_log_writer_discarded_writes_total

   :Type: counter
   :Labels: writer module stream filter-name path

   Total number of log writes discarded due to size limitations.

.. zeek:metric:: zeek_log_writer_truncated_containers_total

   :Type: counter
   :Labels: writer module stream filter-name path

   Total number of logged container fields limited by length

.. zeek:metric:: zeek_log_writer_truncated_string_fields_total

   :Type: counter
   :Labels: writer module stream filter-name path

   Total number of logged string fields limited by length

.. zeek:metric:: zeek_log_writer_writes_total

   :Type: counter
   :Labels: writer module stream filter-name path

   Total number of log writes passed to a concrete log writer not vetoed by stream or filter policies.

.. zeek:metric:: zeek_msgthread_active_threads

   :Type: gauge
   :Labels:

   Number of active threads

.. zeek:metric:: zeek_msgthread_in_messages_total

   :Type: counter
   :Labels:

   Number of inbound messages received

.. zeek:metric:: zeek_msgthread_out_messages_total

   :Type: counter
   :Labels:

   Number of outbound messages sent

.. zeek:metric:: zeek_msgthread_pending_in_messages

   :Type: gauge
   :Labels:

   Pending number of inbound messages

.. zeek:metric:: zeek_msgthread_pending_messages_in_buckets

   :Type: gauge
   :Labels: leq

   Number of threads with pending inbound messages split into buckets

.. zeek:metric:: zeek_msgthread_pending_messages_out_buckets

   :Type: gauge
   :Labels: leq

   Number of threads with pending outbound messages split into buckets

.. zeek:metric:: zeek_msgthread_pending_out_messages

   :Type: gauge
   :Labels:

   Pending number of outbound messages

.. zeek:metric:: zeek_msgthread_threads_total

   :Type: counter
   :Labels:

   Total number of threads

.. zeek:metric:: zeek_net_dropped_packets_total

   :Type: counter
   :Labels:

   Total number of packets dropped

.. zeek:metric:: zeek_net_filtered_packets_total

   :Type: counter
   :Labels:

   Total number of packets filtered

.. zeek:metric:: zeek_net_link_packets_total

   :Type: counter
   :Labels:

   Total number of packets on the packet source link before filtering

.. zeek:metric:: zeek_net_packet_lag_seconds

   :Type: gauge
   :Labels:

   Difference of network time and wallclock time in seconds.

.. zeek:metric:: zeek_net_received_bytes_total

   :Type: counter
   :Labels:

   Total number of bytes received

.. zeek:metric:: zeek_net_received_packets_total

   :Type: counter
   :Labels:

   Total number of packets received

.. zeek:metric:: zeek_net_timestamp_seconds

   :Type: gauge
   :Labels:

   The current network time.

.. zeek:metric:: zeek_pending_triggers

   :Type: gauge
   :Labels:

   Pending number of triggers

.. zeek:metric:: zeek_telemetry_counter_usage_error_total

   :Type: counter
   :Labels:

   This counter is returned when label usage for counters is wrong. Check reporter.log if non-zero.

.. zeek:metric:: zeek_telemetry_gauge_usage_error

   :Type: gauge
   :Labels:

   This gauge is returned when label usage for gauges is wrong. Check reporter.log if non-zero.

.. zeek:metric:: zeek_telemetry_histogram_usage_error

   :Type: histogram
   :Labels:

   This histogram is returned when label usage for histograms is wrong. Check reporter.log if non-zero.

.. zeek:metric:: zeek_timers_lag_time_seconds

   :Type: gauge
   :Labels:

   Lag between current network time and last expired timer

.. zeek:metric:: zeek_timers_pending

   :Type: gauge
   :Labels: type

   Number of timers for a certain type

.. zeek:metric:: zeek_timers_total

   :Type: counter
   :Labels:

   Cumulative number of timers

.. zeek:metric:: zeek_triggers_total

   :Type: counter
   :Labels:

   Total number of triggers scheduled

.. zeek:metric:: zeek_version_info

   :Type: gauge
   :Labels: version_number major minor patch commit beta debug version_string

   The Zeek version

