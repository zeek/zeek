
This document summarizes the most important changes in the current Bro
release. For an exhaustive list of changes, see the ``CHANGES`` file
(note that submodules, such as BroControl and Broccoli, come with
their own ``CHANGES``.)

Bro 2.3
=======

[In progress]

Dependencies
------------

- Bro no longer requires a pre-installed libmagic (because it now
  ships its own).

- Libmagic is no longer a dependency.

New Functionality
-----------------

- Support for GRE tunnel decapsulation, including enhanced GRE
  headers. GRE tunnels are treated just like IP-in-IP tunnels by
  parsing past the GRE header in between the delivery and payload IP
  packets.

- The DNS analyzer now actually generates the dns_SRV_reply() event.
  It had been documented before, yet was never raised.

- Bro now uses "file magic signatures" to identify file types. These
  are defined via two new constructs in the signature rule parsing
  grammar: "file-magic" gives a regular expression to match against,
  and "file-mime" gives the MIME type string of content that matches
  the magic and an optional strength value for the match. (See also
  "Changed Functionality" below for changes due to switching from
  using libmagic to such wsignatures.)

- A new built-in function, "file_magic", can be used to get all file
  magic matches and their corresponding strength against a given chunk
  of data.


Changed Functionality
---------------------

- string slices now exclude the end index (e.g., "123"[1:2] returns
  "2"). Generally, Bro's string slices now behave similar to Python.

- ssl_client_hello() now receives a vector of ciphers, instead of a
  set, to preserve their order.

- Notice::end_suppression() has been removed.

- Bro now parses X.509 extensions headers and, as a result, the
  corresponding event got a new signature:

      event x509_extension(c: connection, is_orig: bool, cert: X509, ext: X509_extension_info);

- Bro no longer special-cases SYN/FIN/RST-filtered traces by not
  reporting missing data. The old behavior can be reverted by
  redef'ing "detect_filtered_trace".

  TODO: Update if we add a detector for filtered traces.

- We have removed the packet sorter component.

- Bro no longer uses libmagic to identify file types but instead now
  comes with its own signature library (which initially is still
  derived from libmagic;s database). This leads to a number of further
  changes with regards to MIME types:

    * The second parameter of the "identify_data" built-in function
      can no longer be used to get verbose file type descriptions,
      though it can still be used to get the strongest matching file
      magic signature.

    * The "file_transferred" event's "descr" parameter no longer
      contains verbose file type descriptions.

    * The BROMAGIC environment variable no longer changes any behavior
      in Bro as magic databases are no longer used/installed.

    * Removed "binary" and "octet-stream" mime type detections. They
      don' provide any more information than an uninitialized
      mime_type field.

    * The "fa_file" record now contains a "mime_types" field that
      contains all magic signatures that matched the file content
      (where the "mime_type" field is just a shortcut for the
      strongest match).

Bro 2.2
=======

New Functionality
-----------------

- A completely overhauled intelligence framework for consuming
  external intelligence data. It provides an abstracted mechanism
  for feeding data into the framework to be matched against the
  data available. It also provides a function named ``Intel::match``
  which makes any hits on intelligence data available to the
  scripting language.

  Using input framework, the intel framework can load data from
  text files. It can also update and add data if changes are
  made to the file being monitored. Files to monitor for
  intelligence can be provided by redef-ing the
  ``Intel::read_files`` variable.

  The intel framework is cluster-ready. On a cluster, the
  manager is the only node that needs to load in data from disk,
  the cluster support will distribute the data across a cluster
  automatically.

  Scripts are provided at ``policy/frameworks/intel/seen`` that
  provide a broad set of sources of data to feed into the intel
  framwork to be matched.

- A new file analysis framework moves most of the processing of file
  content from script-land into the core, where it belongs. See
  ``doc/file-analysis.rst``, or the online documentation, for more
  information.

  Much of this is an internal change, but the framework also comes
  with the following user-visible functionality (some of that was
  already available before but is done differently, and more
  efficiently, now):

      - HTTP:

        * Identify MIME type of messages.
        * Extract messages to disk.
        * Compute MD5 for messages.

      - SMTP:

        * Identify MIME type of messages.
        * Extract messages to disk.
        * Compute MD5 for messages.
        * Provide access to start of entity data.

      - FTP data transfers:

        * Identify MIME types of data.
        * Record to disk.

      - IRC DCC transfers: Record to disk.

      - Support for analyzing data transferred via HTTP range requests.

      - A binary input reader interfaces the input framework with the
        file analysis, allowing to inject files on disk into Bro's
        content processing.

- A new framework for computing a wide array of summary statistics,
  such as counters and thresholds checks, standard deviation and mean,
  set cardinality, top K, and more. The framework operates in
  real-time, independent of the underlying data, and can aggregate
  information from many independent monitoring points (including
  clusters). It provides a transparent, easy-to-use user interface,
  and can optionally deploy a set of probabilistic data structures for
  memory-efficient operation. The framework is located in
  ``scripts/base/frameworks/sumstats``.

  A number of new applications now ship with Bro that are built on top
  of the summary statistics framework:

    * Scan detection: Detectors for port and address scans. See
      ``policy/misc/scan.bro`` (these scan detectors used to exist in
      Bro versions <2.0; it's now back, but quite different).

    * Tracerouter detector: ``policy/misc/detect-traceroute.bro``

    * Web application detection/measurement:
      ``policy/misc/app-stats/*``

    * FTP and SSH brute-forcing detector:
      ``policy/protocols/ftp/detect-bruteforcing.bro``,
      ``policy/protocols/ssh/detect-bruteforcing.bro``

    * HTTP-based SQL injection detector:
      ``policy/protocols/http/detect-sqli.bro`` (existed before, but
      now ported to the new framework)

- GridFTP support. This is an extension to the standard FTP analyzer
  and includes:

      - An analyzer for the GSI mechanism of GSSAPI FTP AUTH method.
        GSI authentication involves an encoded TLS/SSL handshake over
        the FTP control session. For FTP sessions that attempt GSI
        authentication, the ``service`` field of the connection log
        will include ``gridftp`` (as well as also ``ftp`` and
        ``ssl``).

      - An example of a GridFTP data channel detection script. It
        relies on the heuristics of GridFTP data channels commonly
        default to SSL mutual authentication with a NULL bulk cipher
        and that they usually transfer large datasets (default
        threshold of script is 1 GB). For identified GridFTP data
        channels, the ``services`` fields of the connection log will
        include ``gridftp-data``.

- Modbus and DNP3 support. Script-level support is only basic at this
  point but see ``src/analyzer/protocol/{modbus,dnp3}/events.bif``, or
  the online documentation, for the events Bro generates. For Modbus,
  there are also some example policies in
  ``policy/protocols/modbus/*``.

- The documentation now includes a new introduction to writing Bro
  scripts. See ``doc/scripting/index.rst`` or, much better, the online
  version. There's also the beginning of a chapter on "Using Bro" in
  ``doc/using/index.rst``.

- GPRS Tunnelling Protocol (GTPv1) decapsulation.

- The scripting language now provide "hooks", a new flavor of
  functions that share characteristics of both standard functions and
  events. They are like events in that multiple bodies can be defined
  for the same hook identifier. They are more like functions in the
  way they are invoked/called, because, unlike events, their execution
  is immediate and they do not get scheduled through an event queue.
  Also, a unique feature of a hook is that a given hook handler body
  can short-circuit the execution of remaining hook handlers simply by
  exiting from the body as a result of a ``break`` statement (as
  opposed to a ``return`` or just reaching the end of the body). See
  ``doc/scripts/builtins.rst``, or the online documentation, for more
  informatin.

- Bro's language now has a working ``switch`` statement that generally
  behaves like C-style switches (except that case labels can be
  comprised of multiple literal constants delimited by commas).  Only
  atomic types are allowed for now.  Case label bodies that don't
  execute a ``return`` or ``break`` statement will fall through to
  subsequent cases. A ``default`` case label is supported.

- Bro's language now has a new set of types ``opaque of X``. Opaque
  values can be passed around like other values but they can only be
  manipulated with BiF functions, not with other operators. Currently,
  the following opaque types are supported::

        opaque of md5
        opaque of sha1
        opaque of sha256
        opaque of cardinality
        opaque of topk
        opaque of bloomfilter

  These go along with the corrsponding BiF functions ``md5_*``,
  ``sha1_*``, ``sha256_*``, ``entropy_*``, etc. . Note that where
  these functions existed before, they have changed their signatures
  to work with opaques types rather than global state.

- The scripting language now supports constructing sets, tables,
  vectors, and records by name::

        type MyRecordType: record {
            c: count;
            s: string &optional;
        };

        global r: MyRecordType = record($c = 7);

        type MySet: set[MyRec];
        global s = MySet([$c=1], [$c=2]);

- Strings now support the subscript operator to extract individual
  characters and substrings (e.g., ``s[4]``, ``s[1:5]``). The index
  expression can take up to two indices for the start and end index of
  the substring to return (e.g. ``mystring[1:3]``).

- Functions now support default parameters, e.g.::

      global foo: function(s: string, t: string &default="abc", u: count &default=0);

- Scripts can now use two new "magic constants" ``@DIR`` and
  ``@FILENAME`` that expand to the directory path of the current
  script and just the script file name without path, respectively.

- ``ssl.log`` now also records the subject client and issuer
  certificates.

- The ASCII writer can now output CSV files on a per filter basis.

- New SQLite reader and writer plugins for the logging framework allow
  to read/write persistent data from on disk SQLite databases.

- A new packet filter framework supports BPF-based load-balancing,
  shunting, and sampling; plus plugin support to customize filters
  dynamically.

- Bro now provides Bloom filters of two kinds: basic Bloom filters
  supporting membership tests, and counting Bloom filters that track
  the frequency of elements. The corresponding functions are::

    bloomfilter_basic_init(fp: double, capacity: count, name: string &default=""): opaque of bloomfilter
    bloomfilter_basic_init2(k: count, cells: count, name: string &default=""): opaque of bloomfilter
    bloomfilter_counting_init(k: count, cells: count, max: count, name: string &default=""): opaque of bloomfilter
    bloomfilter_add(bf: opaque of bloomfilter, x: any)
    bloomfilter_lookup(bf: opaque of bloomfilter, x: any): count
    bloomfilter_merge(bf1: opaque of bloomfilter, bf2: opaque of bloomfilter): opaque of bloomfilter
    bloomfilter_clear(bf: opaque of bloomfilter)

  See ``src/probabilistic/bloom-filter.bif``, or the online
  documentation, for full documentation.

- Bro now provides a probabilistic data structure for computing
  "top k" elements. The corresponding functions are::

    topk_init(size: count): opaque of topk
    topk_add(handle: opaque of topk, value: any)
    topk_get_top(handle: opaque of topk, k: count)
    topk_count(handle: opaque of topk, value: any): count
    topk_epsilon(handle: opaque of topk, value: any): count
    topk_size(handle: opaque of topk): count
    topk_sum(handle: opaque of topk): count
    topk_merge(handle1: opaque of topk, handle2: opaque of topk)
    topk_merge_prune(handle1: opaque of topk, handle2: opaque of topk)

  See ``src/probabilistic/top-k.bif``, or the online documentation,
  for full documentation.

- Bro now provides a probabilistic data structure for computing set
  cardinality, using the HyperLogLog algorithm.  The corresponding
  functions are::

    hll_cardinality_init(err: double, confidence: double): opaque of cardinality
    hll_cardinality_add(handle: opaque of cardinality, elem: any): bool
    hll_cardinality_merge_into(handle1: opaque of cardinality, handle2: opaque of cardinality): bool
    hll_cardinality_estimate(handle: opaque of cardinality): double
    hll_cardinality_copy(handle: opaque of cardinality): opaque of cardinality

  See ``src/probabilistic/cardinality-counter.bif``, or the online
  documentation, for full documentation.

- ``base/utils/exec.bro`` provides a module to start external
  processes asynchronously and retrieve their output on termination.
  ``base/utils/dir.bro`` uses it to monitor a directory for changes,
  and ``base/utils/active-http.bro`` for providing an interface for
  querying remote web servers.

- BroControl can now pin Bro processes to CPUs on supported platforms:
  To use CPU pinning, a new per-node option ``pin_cpus`` can be
  specified in node.cfg if the OS is either Linux or FreeBSD.

- BroControl now returns useful exit codes.  Most BroControl commands
  return 0 if everything was OK, and 1 otherwise.  However, there are
  a few exceptions.  The "status" and "top" commands return 0 if all Bro
  nodes are running, and 1 if not all nodes are running.  The "cron"
  command always returns 0 (but it still sends email if there were any
  problems).  Any command provided by a plugin always returns 0.

- BroControl now has an option "env_vars" to set Bro environment variables.
  The value of this option is a comma-separated list of environment variable
  assignments (e.g., "VAR1=value, VAR2=another").  The "env_vars" option
  can apply to all Bro nodes (by setting it in broctl.cfg), or can be
  node-specific (by setting it in node.cfg).  Environment variables in
  node.cfg have priority over any specified in broctl.cfg.

- BroControl now supports load balancing with PF_RING while sniffing
  multiple interfaces.  Rather than assigning the same PF_RING cluster ID
  to all workers on a host, cluster ID assignment is now based on which
  interface a worker is sniffing (i.e., all workers on a host that sniff
  the same interface will share a cluster ID).  This is handled by
  BroControl automatically.

- BroControl has several new options:  MailConnectionSummary (for
  disabling the sending of connection summary report emails),
  MailAlarmsInterval (for specifying a different interval to send alarm
  summary emails), CompressCmd (if archived log files will be compressed,
  this specifies the command that will be used to compress them),
  CompressExtension (if archived log files will be compressed, this
  specifies the file extension to use).

- BroControl comes with its own test-suite now. ``make test`` in
  ``aux/broctl`` will run it.

In addition to these, Bro 2.2 comes with a large set of smaller
extensions, tweaks, and fixes across the whole code base, including
most submodules.

Changed Functionality
---------------------

- Previous versions of ``$prefix/share/bro/site/local.bro`` (where
  "$prefix" indicates the installation prefix of Bro), aren't compatible
  with Bro 2.2.  This file won't be overwritten when installing over a
  previous Bro installation to prevent clobbering users' modifications,
  but an example of the new version is located in
  ``$prefix/share/bro/site/local.bro.example``.  So if no modification
  has been done to the previous local.bro, just copy the new example
  version over it, else merge in the differences.  For reference,
  a common error message when attempting to use an outdated local.bro
  looks like::

    fatal error in /usr/local/bro/share/bro/policy/frameworks/software/vulnerable.bro, line 41: BroType::AsRecordType (table/record) (set[record { min:record { major:count; minor:count; minor2:count; minor3:count; addl:string; }; max:record { major:count; minor:count; minor2:count; minor3:count; addl:string; }; }])

- The type of ``Software::vulnerable_versions`` changed to allow
  more flexibility and range specifications.  An example usage:

  .. code:: bro

        const java_1_6_vuln = Software::VulnerableVersionRange(
            $max = Software::Version($major = 1, $minor = 6, $minor2 = 0, $minor3 = 44)
        );

        const java_1_7_vuln = Software::VulnerableVersionRange(
            $min = Software::Version($major = 1, $minor = 7),
            $max = Software::Version($major = 1, $minor = 7, $minor2 = 0, $minor3 = 20)
        );

        redef Software::vulnerable_versions += {
            ["Java"] = set(java_1_6_vuln, java_1_7_vuln)
        };

- The interface to extracting content from application-layer protocols
  (including HTTP, SMTP, FTP) has changed significantly due to the
  introduction of the new file analysis framework (see above).

- Removed the following, already deprecated, functionality:

    * Scripting language:
        - ``&disable_print_hook attribute``.

    * BiF functions:
        - ``parse_dotted_addr()``, ``dump_config()``,
          ``make_connection_persistent()``, ``generate_idmef()``,
          ``split_complete()``

        - ``md5_*``, ``sha1_*``, ``sha256_*``, and ``entropy_*`` have
          all changed their signatures to work with opaque types (see
          above).

- Removed a now unused argument from ``do_split`` helper function.

- ``this`` is no longer a reserved keyword.

- The Input Framework's ``update_finished`` event has been renamed to
  ``end_of_data``. It will now not only fire after table-reads have
  been completed, but also after the last event of a whole-file-read
  (or whole-db-read, etc.).

- Renamed the option defining the frequency of alarm summary mails to
  ``Logging::default_alarm_mail_interval``. When using BroControl, the
  value can now be set with the new broctl.cfg option
  ``MailAlarmsInterval``.

- We have completely rewritten the ``notice_policy`` mechanism. It now
  no longer uses a record of policy items but a ``hook``, a new
  language element that's roughly equivalent to a function with
  multiple bodies (see above). For existing code, the two main changes
  are:

    - What used to be a ``redef`` of ``Notice::policy`` now becomes a
      hook implementation. Example:

      Old::

        redef Notice::policy += {
            [$pred(n: Notice::Info) = {
                return n$note == SSH::Login && n$id$resp_h == 10.0.0.1;
                },
            $action = Notice::ACTION_EMAIL]
            };

      New::

        hook Notice::policy(n: Notice::Info)
            {
            if ( n$note == SSH::Login && n$id$resp_h == 10.0.0.1 )
                add n$actions[Notice::ACTION_EMAIL];
            }

    - notice() is now likewise a hook, no longer an event. If you
      have handlers for that event, you'll likely just need to change
      the type accordingly. Example:

      Old::

        event notice(n: Notice::Info) { ... }

      New::

        hook notice(n: Notice::Info) { ... }

- The ``notice_policy.log`` is gone. That's a result of the new notice
  policy setup.

- Removed the ``byte_len()`` and ``length()`` bif functions. Use the
  ``|...|`` operator instead.

- The ``SSH::Login`` notice has been superseded by an corresponding
  intelligence framework observation (``SSH::SUCCESSFUL_LOGIN``).

- ``PacketFilter::all_packets`` has been replaced with
  ``PacketFilter::enable_auto_protocol_capture_filters``.

- We removed the BitTorrent DPD signatures pending further updates to
  that analyzer.

- In previous versions of BroControl, running "broctl cron" would create
  a file ``$prefix/logs/stats/www`` (where "$prefix" indicates the
  installation prefix of Bro).  Now, it is created as a directory.
  Therefore, if you perform an upgrade install and you're using BroControl,
  then you may see an email (generated by "broctl cron") containing an
  error message:  "error running update-stats".  To fix this problem,
  either remove that file (it is not needed) or rename it.

- Due to lack of maintenance the Ruby bindings for Broccoli are now
  deprecated, and the build process no longer includes them by
  default. For the time being, they can still be enabled by
  configuring with ``--enable-ruby``, however we plan to remove
  Broccoli's Ruby support with the next Bro release.

Bro 2.1
=======

New Functionality
-----------------

- Bro now comes with extensive IPv6 support. Past versions offered
  only basic IPv6 functionality that was rarely used in practice as it
  had to be enabled explicitly. IPv6 support is now fully integrated
  into all parts of Bro including protocol analysis and the scripting
  language. It's on by default and no longer requires any special
  configuration.

  Some of the most significant enhancements include support for IPv6
  fragment reassembly, support for following IPv6 extension header
  chains, and support for tunnel decapsulation (6to4 and Teredo). The
  DNS analyzer now handles AAAA records properly, and DNS lookups that
  Bro itself performs now include AAAA queries, so that, for example,
  the result returned by script-level lookups is a set that can
  contain both IPv4 and IPv6 addresses. Support for the most common
  ICMPv6 message types has been added. Also, the FTP EPSV and EPRT
  commands are now handled properly. Internally, the way IP addresses
  are stored has been improved, so Bro can handle both IPv4
  and IPv6 by default without any special configuration.

  In addition to Bro itself, the other Bro components have also been
  made IPv6-aware by default. In particular, significant changes were
  made to trace-summary, PySubnetTree, and Broccoli to support IPv6.

- Bro now decapsulates tunnels via its new tunnel framework located in
  scripts/base/frameworks/tunnels. It currently supports Teredo,
  AYIYA, IP-in-IP (both IPv4 and IPv6), and SOCKS. For all these, it
  logs the outer tunnel connections in both conn.log and tunnel.log,
  and then proceeds to analyze the inner payload as if it were not
  tunneled, including also logging that session in conn.log. For
  SOCKS, it generates a new socks.log in addition with more
  information.

- Bro now features a flexible input framework that allows users to
  integrate external information in real-time into Bro while it's
  processing network traffic. The most direct use-case at the moment
  is reading data from ASCII files into Bro tables, with updates
  picked up automatically when the file changes during runtime. See
  doc/input.rst for more information.

  Internally, the input framework is structured around the notion of
  "reader plugins" that make it easy to interface to different data
  sources. We will add more in the future.

- BroControl now has built-in support for host-based load-balancing
  when using either PF_RING, Myricom cards, or individual interfaces.
  Instead of adding a separate worker entry in node.cfg for each Bro
  worker process on each worker host, it is now possible to just
  specify the number of worker processes on each host and BroControl
  configures everything correctly (including any neccessary enviroment
  variables for the balancers).

  This change adds three new keywords to the node.cfg file (to be used
  with worker entries): lb_procs (specifies number of workers on a
  host), lb_method (specifies what type of load balancing to use:
  pf_ring, myricom, or interfaces), and lb_interfaces (used only with
  "lb_method=interfaces" to specify which interfaces to load-balance
  on).

- Bro's default ASCII log format is not exactly the most efficient way
  for storing and searching large volumes of data. An alternatives,
  Bro now comes with experimental support for two alternative output
  formats:

    * DataSeries: an efficient binary format for recording structured
      bulk data. DataSeries is developed and maintained at HP Labs.
      See doc/logging-dataseries for more information.

    * ElasticSearch: a distributed RESTful, storage engine and search
      engine built on top of Apache Lucene. It scales very well, both
      for distributed indexing and distributed searching. See
      doc/logging-elasticsearch.rst for more information.

  Note that at this point, we consider Bro's support for these two
  formats as prototypes for collecting experience with alternative
  outputs. We do not yet recommend them for production (but welcome
  feedback!)


Changed Functionality
---------------------

The following summarizes the most important differences in existing
functionality. Note that this list is not complete, see CHANGES for
the full set.

- Changes in dependencies:

    * Bro now requires CMake >= 2.6.3.

    * On Linux, Bro now links in tcmalloc (part of Google perftools)
      if found at configure time. Doing so can significantly improve
      memory and CPU use.

      On the other platforms, the new configure option
      --enable-perftools can be used to enable linking to tcmalloc.
      (Note that perftools's support for non-Linux platforms may be
      less reliable).

- The configure switch --enable-brov6 is gone.

- DNS name lookups performed by Bro now also query AAAA records. The
  results of the A and AAAA queries for a given hostname are combined
  such that at the scripting layer, the name resolution can yield a
  set with both IPv4 and IPv6 addresses.

- The connection compressor was already deprecated in 2.0 and has now
  been removed from the code base.

- We removed the "match" statement, which was no longer used by any of
  the default scripts, nor was it likely to be used by anybody anytime
  soon. With that, "match" and "using" are no longer reserved keywords.

- The syntax for IPv6 literals changed from "2607:f8b0:4009:802::1012"
  to "[2607:f8b0:4009:802::1012]". When an IP address variable or IP
  address literal is enclosed in pipes (for example,
  ``|[fe80::db15]|``) the result is now the size of the address in
  bits (32 for IPv4 and 128 for IPv6).

- Bro now spawns threads for doing its logging. From a user's
  perspective not much should change, except that the OS may now show
  a bunch of Bro threads.

- We renamed the configure option --enable-perftools to
  --enable-perftools-debug to indicate that the switch is only relevant
  for debugging the heap.

- Bro's ICMP analyzer now handles both IPv4 and IPv6 messages with a
  joint set of events.  The `icmp_conn` record got a new boolean field
  'v6' that indicates whether the ICMP message is v4 or v6.

- Log postprocessor scripts get an additional argument indicating the
  type of the log writer in use (e.g., "ascii").

- BroControl's make-archive-name script also receives the writer
  type, but as its 2nd(!) argument. If you're using a custom version
  of that script, you need to adapt it. See the shipped version for
  details.

- Signature files can now be loaded via the new "@load-sigs"
  directive. In contrast to the existing (and still supported)
  signature_files constant, this can be used to load signatures
  relative to the current script (e.g., "@load-sigs ./foo.sig").

- The options "tunnel_port" and "parse_udp_tunnels" have been removed.
  Bro now supports decapsulating tunnels directly for protocols it
  understands.

- ASCII logs now record the time when they were opened/closed at the
  beginning and end of the file, respectively (wall clock). The
  options LogAscii::header_prefix and LogAscii::include_header have
  been renamed to LogAscii::meta_prefix and LogAscii::include_meta,
  respectively.

- The ASCII writers "header_*" options have been renamed to "meta_*"
  (because there's now also a footer).

- Some built-in functions have been removed: "addr_to_count" (use
  "addr_to_counts" instead), "bro_has_ipv6" (this is no longer
  relevant because Bro now always supports IPv6), "active_connection"
  (use "connection_exists" instead), and "connection_record" (use
  "lookup_connection" instead).

- The "NFS3::mode2string" built-in function has been renamed to
  "file_mode".

- Some built-in functions have been changed: "exit" (now takes the
  exit code as a parameter), "to_port" (now takes a string as
  parameter instead of a count and transport protocol, but
  "count_to_port" is still available), "connect" (now takes an
  additional string parameter specifying the zone of a non-global IPv6
  address), and "listen" (now takes three additional parameters to
  enable listening on IPv6 addresses).

- Some Bro script variables have been renamed:
  "LogAscii::header_prefix" has been renamed to
  "LogAscii::meta_prefix", "LogAscii::include_header" has been renamed
  to "LogAscii::include_meta".

- Some Bro script variables have been removed: "tunnel_port",
  "parse_udp_tunnels", "use_connection_compressor",
  "cc_handle_resets", "cc_handle_only_syns", and
  "cc_instantiate_on_data".

- A couple events have changed: the "icmp_redirect" event now includes
  the target and destination addresses and any Neighbor Discovery
  options in the message, and the last parameter of the
  "dns_AAAA_reply" event has been removed because it was unused.

- The format of the ASCII log files has changed very slightly.  Two
  new lines are automatically added, one to record the time when the
  log was opened, and the other to record the time when the log was
  closed.

- In BroControl, the option (in broctl.cfg) "CFlowAddr" was renamed to
  "CFlowAddress".


Bro 2.0
=======

As the version number jump from 1.5 suggests, Bro 2.0 is a major
upgrade and lots of things have changed. Most importantly, we have
rewritten almost all of Bro's default scripts from scratch, using
quite different structure now and focusing more on operational
deployment. The result is a system that works much better "out of the
box", even without much initial site-specific configuration. The
down-side is that 1.x configurations will need to be adapted to work
with the new version. The two rules of thumb are:

    (1) If you have written your own Bro scripts
        that do not depend on any of the standard scripts formerly
        found in ``policy/``, they will most likely just keep working
        (although you might want to adapt them to use some of the new
        features, like the new logging framework; see below).

    (2) If you have custom code that depends on specifics of 1.x
        default scripts (including most configuration tuning), that is
        unlikely to work with 2.x. We recommend to start by using just
        the new scripts first, and then port over any customizations
        incrementally as necessary (they may be much easier to do now,
        or even unnecessary). Send mail to the Bro user mailing list
        if you need help.

Below we summarize changes from 1.x to 2.x in more detail. This list
isn't complete, see the ``CHANGES`` file in the distribution.
for the full story.

Script Organization
-------------------

In versions before 2.0, Bro scripts were all maintained in a flat
directory called ``policy/`` in the source tree.  This directory is now
renamed to ``scripts/`` and contains major subdirectories ``base/``,
``policy/``, and ``site/``, each of which may also be subdivided
further.

The contents of the new ``scripts/`` directory, like the old/flat
``policy/`` still gets installed under the ``share/bro``
subdirectory of the installation prefix path just like previous
versions.  For example, if Bro was compiled like ``./configure
--prefix=/usr/local/bro && make && make install``, then the script
hierarchy can be found in ``/usr/local/bro/share/bro``.

The main
subdirectories of that hierarchy are as follows:

- ``base/`` contains all scripts that are loaded by Bro by default
  (unless the ``-b`` command line option is used to run Bro in a
  minimal configuration). Note that is a major conceptual change:
  rather than not loading anything by default, Bro now uses an
  extensive set of default scripts out of the box.

  The scripts under this directory generally either accumulate/log
  useful state/protocol information for monitored traffic, configure a
  default/recommended mode of operation, or provide extra Bro
  scripting-layer functionality that has no significant performance cost.

- ``policy/`` contains all scripts that a user will need to explicitly
  tell Bro to load.  These are scripts that implement
  functionality/analysis that not all users may want to use and may have
  more significant performance costs. For a new installation, you
  should go through these and see what appears useful to load.

- ``site/`` remains a directory that can be used to store locally
  developed scripts. It now comes with some preinstalled example
  scripts that contain recommended default configurations going beyond
  the ``base/`` setup. E.g. ``local.bro`` loads extra scripts from
  ``policy/`` and does extra tuning. These files can be customized in
  place without being overwritten by upgrades/reinstalls, unlike
  scripts in other directories.

With version 2.0, the default ``BROPATH`` is set to automatically
search for scripts in ``policy/``, ``site/`` and their parent
directory, but **not** ``base/``.  Generally, everything under
``base/`` is loaded automatically, but for users of the ``-b`` option,
it's important to know that loading a script in that directory
requires the extra ``base/`` path qualification.  For example, the
following two scripts:

* ``$PREFIX/share/bro/base/protocols/ssl/main.bro``
* ``$PREFIX/share/bro/policy/protocols/ssl/validate-certs.bro``

are referenced from another Bro script like:

.. code:: bro

    @load base/protocols/ssl/main
    @load protocols/ssl/validate-certs

Notice how ``policy/`` can be omitted as a convenience in the second
case. ``@load`` can now also use relative path, e.g., ``@load
../main``.


Logging Framework
-----------------

- The logs generated by scripts that ship with Bro are entirely redone
  to use a standardized, machine parsable format via the new logging
  framework. Generally, the log content has been restructured towards
  making it more directly useful to operations. Also, several
  analyzers have been significantly extended and thus now log more
  information. Take a look at ``ssl.log``.

  * A particular format change that may be useful to note is that the
    ``conn.log`` ``service`` field is derived from DPD instead of
    well-known ports (while that was already possible in 1.5, it was
    not the default).

  * Also, ``conn.log`` now reports raw number of packets/bytes per
    endpoint.

- The new logging framework makes it possible to extend, customize,
  and filter logs very easily.

- A common pattern found in the new scripts is to store logging stream
  records for protocols inside the ``connection`` records so that
  state can be collected until enough is seen to log a coherent unit
  of information regarding the activity of that connection.  This
  state is now frequently seen/accessible in event handlers, for
  example, like ``c$<protocol>`` where ``<protocol>`` is replaced by
  the name of the protocol.  This field is added to the ``connection``
  record by ``redef``'ing it in a
  ``base/protocols/<protocol>/main.bro`` script.

- The logging code has been rewritten internally, with script-level
  interface and output backend now clearly separated. While ASCII
  logging is still the default, we will add further output types in
  the future (binary format, direct database logging).


Notice Framework
----------------

The way users interact with "notices" has changed significantly in order
to make it easier to define a site policy and more extensible for adding
customized actions.


New Default Settings
--------------------

- Dynamic Protocol Detection (DPD) is now enabled/loaded by default.

- The default packet filter now examines all packets instead of
  dynamically building a filter based on which protocol analysis scripts
  are loaded. See ``PacketFilter::all_packets`` for how to revert to old
  behavior.

API Changes
-----------

- The ``@prefixes`` directive works differently now.
  Any added prefixes are now searched for and loaded *after* all input
  files have been parsed.  After all input files are parsed, Bro
  searches ``BROPATH`` for prefixed, flattened versions of all of the
  parsed input files.  For example, if ``lcl`` is in ``@prefixes``, and
  ``site.bro`` is loaded, then a file named ``lcl.site.bro`` that's in
  ``BROPATH`` would end up being automatically loaded as well.  Packages
  work similarly, e.g. loading ``protocols/http`` means a file named
  ``lcl.protocols.http.bro`` in ``BROPATH`` gets loaded automatically.

- The ``make_addr`` BIF now returns a ``subnet`` versus an ``addr``


Variable Naming
---------------

- ``Module`` is more widely used for namespacing. E.g. the new
  ``site.bro`` exports the ``local_nets`` identifier (among other
  things) into the ``Site`` module.

- Identifiers may have been renamed to conform to new `scripting
  conventions
  <http://www.bro.org/development/howtos/script-conventions.html>`_


Removed Functionality
---------------------

We have remove a bunch of functionality that was rarely used and/or
had not been maintained for a while already:

    - The ``net`` script data type.
    - The ``alarm`` statement; use the notice framework instead.
    - Trace rewriting.
    - DFA state expiration in regexp engine.
    - Active mapping.
    - Native DAG support (may come back eventually)
    - ClamAV support.
    - The connection compressor is now disabled by default, and will
      be removed in the future.

BroControl Changes
------------------

BroControl looks pretty much similar to the version coming with Bro 1.x,
but has been cleaned up and streamlined significantly internally.

BroControl has a new ``process`` command to process a trace on disk
offline using a similar configuration to what BroControl installs for
live analysis.

BroControl now has an extensive plugin interface for adding new
commands and options. Note that this is still considered experimental.

We have removed the ``analysis`` command, and BroControl currently
does not send daily alarm summaries anymore (this may be restored
later).

Development Infrastructure
--------------------------

Bro development has moved from using SVN to Git for revision control.
Users that want to use the latest Bro development snapshot by checking it out
from the source repositories should see the `development process
<http://www.bro.org/development/process.html>`_. Note that all the various
sub-components now reside in their own repositories. However, the
top-level Bro repository includes them as git submodules so it's easy
to check them all out simultaneously.

Bro now uses `CMake <http://www.cmake.org>`_ for its build system so
that is a new required dependency when building from source.

Bro now comes with a growing suite of regression tests in
``testing/``.
