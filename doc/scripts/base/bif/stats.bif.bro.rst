:tocdepth: 3

base/bif/stats.bif.bro
======================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
======================================================= =======================================================
:bro:id:`get_broker_stats`: :bro:type:`function`        Returns statistics about Broker communication.
:bro:id:`get_conn_stats`: :bro:type:`function`          Returns Bro traffic statistics.
:bro:id:`get_dns_stats`: :bro:type:`function`           Returns statistics about DNS lookup activity.
:bro:id:`get_event_stats`: :bro:type:`function`         Returns statistics about the event engine.
:bro:id:`get_file_analysis_stats`: :bro:type:`function` Returns statistics about file analysis.
:bro:id:`get_gap_stats`: :bro:type:`function`           Returns statistics about TCP gaps.
:bro:id:`get_matcher_stats`: :bro:type:`function`       Returns statistics about the regular expression engine.
:bro:id:`get_net_stats`: :bro:type:`function`           Returns packet capture statistics.
:bro:id:`get_proc_stats`: :bro:type:`function`          Returns Bro process statistics.
:bro:id:`get_reassembler_stats`: :bro:type:`function`   Returns statistics about reassembler usage.
:bro:id:`get_reporter_stats`: :bro:type:`function`      Returns statistics about reporter messages and weirds.
:bro:id:`get_thread_stats`: :bro:type:`function`        Returns statistics about thread usage.
:bro:id:`get_timer_stats`: :bro:type:`function`         Returns statistics about timer usage.
======================================================= =======================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: get_broker_stats

   :Type: :bro:type:`function` () : :bro:type:`BrokerStats`

   Returns statistics about Broker communication.
   

   :returns: A record with Broker statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_conn_stats

   :Type: :bro:type:`function` () : :bro:type:`ConnStats`

   Returns Bro traffic statistics.
   

   :returns: A record with connection and packet statistics.
   
   .. bro:see:: get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_dns_stats

   :Type: :bro:type:`function` () : :bro:type:`DNSStats`

   Returns statistics about DNS lookup activity.
   

   :returns: A record with DNS lookup statistics.
   
   .. bro:see:: get_conn_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_event_stats

   :Type: :bro:type:`function` () : :bro:type:`EventStats`

   Returns statistics about the event engine.
   

   :returns: A record with event engine statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_file_analysis_stats

   :Type: :bro:type:`function` () : :bro:type:`FileAnalysisStats`

   Returns statistics about file analysis.
   

   :returns: A record with file analysis statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_gap_stats

   :Type: :bro:type:`function` () : :bro:type:`GapStats`

   Returns statistics about TCP gaps.
   

   :returns: A record with TCP gap statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_matcher_stats

   :Type: :bro:type:`function` () : :bro:type:`MatcherStats`

   Returns statistics about the regular expression engine. Statistics include
   the number of distinct matchers, DFA states, DFA state transitions, memory
   usage of DFA states, cache hits/misses, and average number of NFA states
   across all matchers.
   

   :returns: A record with matcher statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_net_stats

   :Type: :bro:type:`function` () : :bro:type:`NetStats`

   Returns packet capture statistics. Statistics include the number of
   packets *(i)* received by Bro, *(ii)* dropped, and *(iii)* seen on the
   link (not always available).
   

   :returns: A record of packet statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_proc_stats

   :Type: :bro:type:`function` () : :bro:type:`ProcStats`

   Returns Bro process statistics.
   

   :returns: A record with process statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_reassembler_stats

   :Type: :bro:type:`function` () : :bro:type:`ReassemblerStats`

   Returns statistics about reassembler usage.
   

   :returns: A record with reassembler statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_reporter_stats

   :Type: :bro:type:`function` () : :bro:type:`ReporterStats`

   Returns statistics about reporter messages and weirds.
   

   :returns: A record with reporter statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats
                get_broker_stats

.. bro:id:: get_thread_stats

   :Type: :bro:type:`function` () : :bro:type:`ThreadStats`

   Returns statistics about thread usage.
   

   :returns: A record with thread usage statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_timer_stats
                get_broker_stats
                get_reporter_stats

.. bro:id:: get_timer_stats

   :Type: :bro:type:`function` () : :bro:type:`TimerStats`

   Returns statistics about timer usage.
   

   :returns: A record with timer usage statistics.
   
   .. bro:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_broker_stats
                get_reporter_stats


