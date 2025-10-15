.. _troubleshooting:

===============
Troubleshooting
===============

This page lists approaches and mentions logs and metrics available
to understand and debug Zeek's performance.

There may be assumptions about Linux deployments regarding kernel features
and tooling available.

Memory Leaks and State Growth
=============================

When memory of any Zeek process continuously grows in production or testing
settings, there might be a memory leak in Zeek's C++ core or it might be
scripting state growth. Examples of the latter are a global table that is
populated but elements aren't expired or removed. Containers attached to
connections may also cause unbounded state growth when these connections
are long-lived.

For such issues, using jemalloc's memory profiling can be invaluable. A good
introduction to this topic is `Justin Azoff's profiling presentation`_ (`slides`_).


Jemalloc Memory Profiling
-------------------------

For memory profiling with `jemalloc`_ you need jemalloc compiled with
profiling enabled. Some Linux distributions provide a libjemalloc package that
is configured this way. For example, Debian on the amd64 architecture
has it enabled while Fedora 38 does not. You're advised to verify the
``config.prof`` line in the jemalloc stats output as shown below.

.. note::

   If your distribution does not provide a suitable libjemalloc package,
   building jemalloc from source configured with the required options
   is reasonably easy.

   .. code-block:: console

      $ git clone git@github.com:jemalloc/jemalloc.git
      $ cd jemalloc
      $ git checkout 5.2.1  # or newer releases
      $ ./autogen.sh && ./configure --enable-prof

      # Optionally, use LD_PRELOAD
      $ export LD_PRELOAD=$(pwd)/lib/libjemalloc.so
      # ...or install the custom libjemalloc build.
      $ sudo make install

You can either build Zeek from source and pass the ``--enable-jemalloc`` flag
(possibly with ``--with-jemalloc=/usr/local/`` for a custom build) to always
use the jemalloc allocater (recommended), or set ``LD_PRELOAD`` as shown above.
Using ``LD_PRELOAD`` can be convenient if you're not
in a position to rebuild Zeek or you're consuming upstream binary packages that
did not use ``--enable-jemalloc``, or you want to use a custom ad-hoc/patched
jemalloc build.

To verify jemalloc profiling is functional, run the following command and
check that ``config.prof`` reports ``true``.

.. code-block:: console

   $ MALLOC_CONF="stats_print:true" zeek -e 'event zeek_init() {}' 2>&1  | grep 'config.prof'
   config.prof: true
   config.prof_libgcc: true
   config.prof_libunwind: false
   ...


If there is no output or ``config.prof`` says ``false``, verify your Zeek
and libjemalloc setup.

.. note::

   Neither ``LD_PRELOAD`` nor ``MALLOC_CONF`` work with a setuid or setcap
   ``zeek`` binary and you might need to run as root or another privileged
   user instead.

At this point you can run Zeek with a ``MALLOC_CONF`` setting that will dump
memory profiles roughly every 256MB of allocation activity (controlled by the
``lg_prof_interval`` setting - 2**28 = 256 MB).

.. code-block:: console

   $ MALLOC_CONF="prof:true,prof_prefix:jeprof.out,prof_final:true,lg_prof_interval:28" zeek -C -i eth0

The files dumped by jemalloc will have a naming pattern of ``jeprof.out.<pid>...``
and can be postprocessed with the ``jeprof`` utility.

.. code-block:: console

   $ jeprof $(which zeek)  jeprof.out.*
   Welcome to jeprof!  For help, type 'help'.
   (jeprof) top
   Total: 1773.2 MB
      381.8  21.5%  21.5%    381.8  21.5% __gnu_cxx::new_allocator::allocate
      232.6  13.1%  34.6%    232.6  13.1% std::__cxx11::basic_string::_M_construct
      147.5   8.3%  43.0%    265.0  14.9% zeek::make_intrusive
      144.0   8.1%  51.1%    144.0   8.1% monitoring_thread_loop
      135.0   7.6%  58.7%    135.0   7.6% zeek::util::safe_realloc
      117.0   6.6%  65.3%    802.6  45.3% yyparse
       63.0   3.6%  68.9%    108.0   6.1% zeeklex
       54.0   3.0%  71.9%     54.0   3.0% zeek::Obj::SetLocationInfo
       49.0   2.8%  74.7%     49.0   2.8% alloc_aligned_chunks
       45.0   2.5%  77.2%     45.0   2.5% zeek::detail::EquivClass::EquivClass


It can be more insightful to generate a graph as SVG or GIF from the ``.heap`` files
as these make the call chain more visible directly (click image to enlarge).

.. code-block:: console

   $ jeprof $(which zeek) --svg jeprof.out.3075061.* > out.svg

.. image:: /images/troubleshooting/http-fake-state-growth.gif
   :alt: State growth in a ``std::vector<std::string>``
   :scale: 10%

In above image, ``basic_string _M_construct`` called from ``HTTP_Analyzer DeliverStream``
is standing out as well as ``new_allocator allocate`` called from ``std::vector _M_realloc_insert``.
This memory growth was provoked by patching the HTTP analyzer such that all input
data passed to ``DeliverStream()`` was also copied into a single statically allocated
``std::vector<std::string>`` and never freed again.

ZeekControl Integration
~~~~~~~~~~~~~~~~~~~~~~~

When working in a ZeekControl based environment, the `zeek-jemalloc`_ plugin
can help with setting up the required environment variables. The ``.heap``
files will be located in a worker's individual spool directory and can be
processed with the ``jeprof`` utility as shown above.

.. _zeek-jemalloc: https://github.com/JustinAzoff/zeek-jemalloc-profiling/tree/master
.. _justin azoff's profiling presentation: https://www.youtube.com/watch?v=gWSXbqxnJfs
.. _slides: https://old.zeek.org/zeekweek2019/slides/justin-azoff-profiling.pdf
.. _jemalloc: https://jemalloc.net/


CPU Profiling
=============

When a Zeek worker is using close to all of a single CPU as seen via ``zeekctl top``
or ``top -p <pid>``, this usually means it is either receiving too many packets
and is simply overloaded, or there's a performance problem. Particularly at
low packet rates or with pathological packet streams it is worth debugging

Perf and Flame Graphs
---------------------

It can be valuable to leverage the `perf`_ tool on Linux and generate
`Flame Graphs`_ from the recorded data.

.. note::

   For best results it's recommended to build Zeek and third-party libraries
   used by Zeek with frame pointers enabled setting the ``-fno-omit-frame-pointer``
   compile flag.

   .. code-block:: console

      $ CXXFLAGS="-fno-omit-frame-pointer" CFLAGS="-fno-omit-frame-pointer" ./configure --build-type=RelWithDebugInfo ...

   Using ``-fno-omit-frame-pointer`` may have a performance impact. Therefore,
   Linux distributions may or may not use it by default to compile libraries.
   You're advised to test performance differences in your environment and whether
   having frame pointers available for troubleshooting in production is more
   important than any performance gains.

   On Ubuntu you may explore using the ``libc6-prof`` for a glibc library
   compiled with frame pointers enabled. On Fedora 38 on the other hand
   most packages should be compiled with
   `frame pointers enabled by default <https://fedoraproject.org/wiki/Changes/fno-omit-frame-pointer>`_.

Assuming the PID of a Zeek worker is 3639255, a perf profile with call graph
information can be collected as follows:

.. code-block:: console

   $ perf record -g -p 3639255
   ^C[ perf record: Woken up 8 times to write data ]
   [ perf record: Captured and wrote 2.893 MB perf.data (13865 samples) ]

The resulting ``perf.data`` file can be visualized and post-processed
via ``perf report``, ``perf script``, etc.

When Zeek workers are pinned to CPUs, it can also be useful to record all
activity on that CPU via ``perf record -g -C <cpu>`` instead.

To produce a flame graph ``perf.data``, run the following command pipeline,
assuming a git checkout of the `FlameGraph`_ repository at an appropriate
location.

.. code-block:: console

   $ perf script | /path/to/FlameGraph/stackcollapse-perf.pl | /path/to/FlameGraph/flamegraph.pl  > out.svg

The resulting flame graph may look as follows:

.. image:: /images/troubleshooting/flamegraph.png
   :alt: Example flame graph.
   :scale: 25%

Visualizing flame graphs this way removes the time dimension. `FlameScope`_ is
a project allowing exploration of different time ranges within the recorded data
which can be valuable if you observe Zeek processes freezing or hanging.

.. _perf: https://perf.wiki.kernel.org/index.php/Main_Page
.. _Flame Graphs: https://www.brendangregg.com/flamegraphs.html
.. _FlameGraph: https://github.com/brendangregg/FlameGraph
.. _FlameScope: https://github.com/Netflix/flamescope
.. _Fedora -fno-omit-framepointers: https://fedoraproject.org/wiki/Changes/fno-omit-frame-pointer


Metrics and Stats
=================

Telemetry Framework and Prometheus
----------------------------------

Starting with Zeek 5.1, the script-level as well as C++ API of the :ref:`framework-telemetry`
is being leveraged more extensively to expose metrics about Zeek's operational behavior.
Generally we recommend consuming these metrics through the Prometheus endpoint
exposed on ``http://manager-ip:9911/metrics`` by default.

Currently, basic version information, network and process metrics, log records per
log stream and log writers, data about event invocations as well as Broker
subsystem metrics are exposed.

Below is an example of using ``curl`` to list some of the metrics. In a production
setup, usually a `Prometheus Server`_ is configured to scrape above endpoint
which then stores metrics data for later visualization.

.. code-block:: console

   $ curl -s localhost:9911/metrics | grep -E '^(zeek_version|zeek_log|zeek_event|zeek_net|process_|zeek_active_sessions|zeek_total_sessions)'
   zeek_version_info{beta="false",commit="622",debug="false",endpoint="",major="6",minor="0",patch="0",version_number="60000",version_string="6.0.0-dev.622"} 1.000000 1684826824560
   zeek_event_handler_invocations_total{endpoint="",name="zeek_init"} 1 1684826824560
   ...
   zeek_event_handler_invocations_total{endpoint="",name="dns_message"} 4 1684826824560
   zeek_event_handler_invocations_total{endpoint="",name="dns_request"} 2 1684826824560
   zeek_event_handler_invocations_total{endpoint="",name="dns_end"} 4 1684826824560
   zeek_event_handler_invocations_total{endpoint="",name="connection_state_remove"} 547 1684826824560
   ...
   zeek_event_handler_invocations_total{endpoint="",name="file_hash"} 1628 1684826824560
   zeek_event_handler_invocations_total{endpoint="",name="file_state_remove"} 814 1684826824560
   zeek_net_dropped_packets_total{endpoint=""} 0.000000 1684826824560
   zeek_net_link_packets_total{endpoint=""} 19664.000000 1684826824560
   zeek_net_received_bytes_total{endpoint=""} 1699891.000000 1684826824560
   zeek_net_received_packets_total{endpoint=""} 9832.000000 1684826824560
   ...
   zeek_log_writer_writes_total{endpoint="",filter_name="default",module="DNS",path="dns",stream="DNS::LOG",writer="Log::WRITER_ASCII"} 2 1684826824560
   zeek_log_writer_writes_total{endpoint="",filter_name="default",module="HTTP",path="http",stream="HTTP::LOG",writer="Log::WRITER_ASCII"} 819 1684826824560
   zeek_log_writer_writes_total{endpoint="",filter_name="default",module="Conn",path="conn",stream="Conn::LOG",writer="Log::WRITER_ASCII"} 547 1684826824560
   zeek_log_writer_writes_total{endpoint="",filter_name="default",module="Files",path="files",stream="Files::LOG",writer="Log::WRITER_ASCII"} 814 1684826824560
   ...
   zeek_log_stream_writes_total{endpoint="",module="DNS",stream="DNS::LOG"} 2 1684826824560
   zeek_log_stream_writes_total{endpoint="",module="HTTP",stream="HTTP::LOG"} 819 1684826824560
   zeek_log_stream_writes_total{endpoint="",module="Conn",stream="Conn::LOG"} 547 1684826824560
   zeek_log_stream_writes_total{endpoint="",module="Files",stream="Files::LOG"} 814 1684826824560
   zeek_active_sessions{endpoint="",protocol="tcp"} 0 1684829159305
   ...
   zeek_total_sessions_total{endpoint="",protocol="tcp"} 45101 1684829159305
   zeek_total_sessions_total{endpoint="",protocol="udp"} 39849 1684829159305
   zeek_total_sessions_total{endpoint="",protocol="icmp"} 320 1684829159305
   process_open_fds{endpoint=""} 62 1684826824560
   process_cpu_seconds_total{endpoint=""} 1.950000 1684826824560
   process_virtual_memory_bytes{endpoint=""} 1917345792 1684826824560
   process_resident_memory_bytes{endpoint=""} 268935168 1684826824560


If you prefer to consume metrics via logs, the ``telemetry.log``
(:zeek:see:`Telemetry::Info`) may work. Its
format is a bit unusual, however. See the :ref:`framework-telemetry`'s
documentation for more details about the log and how to add further metrics
from your own Zeek scripts.

.. _Prometheus server: https://prometheus.io/


stats.log
---------

The ``stats.log`` is enabled when loading the :doc:`/scripts/policy/misc/stats.zeek` script.
This is the default with the stock ``local.zeek`` included with Zeek. This
log provides stats about Zeek's operational behavior in a structured log format.

See the :zeek:see:`Stats::Info` record documentation for a description of
the individual fields.

The default reporting interval is 5 minutes. It can make sense to reduce
this interval for testing or during troubleshooting via
``redef Stats::report_interval=30sec``. Stats collection may have a
non-negligible impact on performance and running, for example,
every second may be detrimental.

For historic reasons, this log contains delta values for ``pkts_proc``,
``bytes_recv``, ``events_proc``, ``tcp_conns``, etc. This can make it
difficult to use the values as-is in metrics systems that expect counter
metrics to continuously grow and compute rates or delta values on the fly.

.. note::

   If you're creating your own custom metrics or stats-like log, consider
   using absolute values for counter metrics. Relative values can
   always be derived from two absolute values. The inverse is not true.
   Popular metrics systems usually assume absolute counter values, too.

Following an example of a ``stats.log`` entry:

.. code-block:: console

   $ zeek -C -i eth0 local Stats::report_interval=30sec LogAscii::use_json=T
   $ jq < stats.log
   ...
   {
       "ts": 1684828680.616951,
       "peer": "zeek",
       "mem": 344,
       "pkts_proc": 300000,
       "bytes_recv": 78092228,
       "pkts_dropped": 0,
       "pkts_link": 299609,
       "pkt_lag": 0.003422975540161133,
       "events_proc": 448422,
       "events_queued": 448422,
       "active_tcp_conns": 2279,
       "active_udp_conns": 2809,
       "active_icmp_conns": 96,
       "tcp_conns": 6747,
       "udp_conns": 5954,
       "icmp_conns": 48,
       "timers": 67510,
       "active_timers": 35086,
       "files": 8165,
       "active_files": 0,
       "dns_requests": 218,
       "active_dns_requests": 2,
       "reassem_tcp_size": 7816,
       "reassem_file_size": 0,
       "reassem_frag_size": 0,
       "reassem_unknown_size": 0
   }

prof.log
--------

The ``prof.log`` provides aggregated information about Zeek's runtime status
in a fairly non-structured text format.
Likely future metrics will be added through the Telemetry framework mentioned
above, but as of now it does contain information about queue sizes within
the threading subsystem and other details that are not yet exposed otherwise.

To enable ``prof.log``, load the :doc:`/scripts/policy/misc/profiling.zeek` script
in ``local.zeek`` or start Zeek with ``misc/profiling`` on the command-line:

.. code-block:: console

   $ zeek -C -i eth0 misc/profiling

The following provides an example of ``prof.log`` content:

.. code-block:: console

   $ cat prof.log
   1684828232.344252 Comm: peers=0 stores=1 pending_queries=0 events_in=0 events_out=0 logs_in=0 logs_out=0 ids_in=0 ids_out=0 1684828262.344351 ------------------------
   1684828262.344351 Memory: total=406480K total_adj=149536K malloced: 0K
   1684828262.344351 Run-time: user+sys=53.2 user=44.6 sys=8.6 real=631.1
   1684828262.344351 Conns: total=84712 current=6759/6759
   1684828262.344351 Conns: tcp=3847/3860 udp=2815/2883 icmp=97/98
   1684828262.344351 TCP-States:        Inact.  Syn.    SA      Part.   Est.    Fin.    Rst.
   1684828262.344351 TCP-States:Inact.                                                          
   1684828262.344351 TCP-States:Syn.    76                                              36      
   1684828262.344351 TCP-States:SA                                                              
   1684828262.344351 TCP-States:Part.                                                           
   1684828262.344351 TCP-States:Est.                                    652     2214    36      
   1684828262.344351 TCP-States:Fin.                                            753             
   1684828262.344351 TCP-States:Rst.                                    16      64              
   1684828262.344351 Connections expired due to inactivity: 2426
   1684828262.344351 Timers: current=47708 max=47896 lag=0.00s
   1684828262.344351 DNS_Mgr: requests=1596 succesful=1596 failed=0 pending=0 cached_hosts=0 cached_addrs=1207
   1684828262.344351 Triggers: total=4900 pending=0
   1684828262.344351         ConnectionDeleteTimer = 905
   1684828262.344351         ConnectionInactivityTimer = 6759
   1684828262.344351         DNSExpireTimer = 1840
   1684828262.344351         FileAnalysisInactivityTimer = 32836
   1684828262.344351         ScheduleTimer = 11
   1684828262.344351         TableValTimer = 34
   1684828262.344351         TCPConnectionAttemptTimer = 166
   1684828262.344351         TCPConnectionExpireTimer = 5156
   1684828262.344351         ThreadHeartbeat = 1
   1684828262.344351 Threads: current=21
   1684828262.344351   dns/Log::WRITER_ASCII     in=586 out=258 pending=0/0 (#queue r/w: in=586/586 out=258/258)
   1684828262.344351   known_hosts/Log::WRITER_ASCII in=475 out=258 pending=0/0 (#queue r/w: in=475/475 out=258/258)
   1684828262.344351   software/Log::WRITER_ASCII in=478 out=258 pending=0/0 (#queue r/w: in=478/478 out=258/258)
   ...
   1684828262.344351   files/Log::WRITER_ASCII   in=483 out=258 pending=0/0 (#queue r/w: in=483/483 out=258/258)
   1684828262.344351   http/Log::WRITER_ASCII    in=483 out=258 pending=0/0 (#queue r/w: in=483/483 out=258/258)
   1684828262.344351   weird/Log::WRITER_ASCII   in=260 out=257 pending=0/0 (#queue r/w: in=260/260 out=257/257)
   1684828262.344351   conn/Log::WRITER_ASCII    in=486 out=257 pending=0/0 (#queue r/w: in=486/486 out=257/257)
