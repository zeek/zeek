.. _jq_home: https://jqlang.org/

.. _jq_manual: https://jqlang.org/manual/

.. _log-inspection:

######
 Logs
######

At this point, Zeek should be fully working within the tutorial's container.
Now, we will see the power of Zeek: creating logs.

In this section, we will go over how to interact with Zeek's logs and access
the fields we need. We will also touch a few of the common logs and how to
pivot amongst them.

******************
 Zeek Log Formats
******************

Zeek's default log format is tab-separated values, or TSV. TSV logs are
lightweight, efficient, and easy to parse. But, they're not as suitable
for human consumption. Thankfully, Zeek comes with a tool called
``zeek-cut`` in order to examine these logs.

First, run Zeek on the pcap from the quickstart for demonstration:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap
   # cat conn.log
   #separator \x09
   #set_separator  ,
   #empty_field    (empty)
   #unset_field    -
   #path   conn
   #open   2025-12-05-16-38-23
   #fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto    service duration        orig_bytes      resp_bytes      conn_state      local_orig       local_resp      missed_bytes    history orig_pkts       orig_ip_bytes   resp_pktsresp_ip_bytes   tunnel_parents  ip_proto
   #types  time    string  addr    port    addr    port    enum    string  interval        count    count   string  bool    bool    count   string  count   count   count   count   set[string]      count
   1747147647.668533       CgnovV3tXhiyU385S       192.168.1.8     52917   192.0.78.212    80       tcp     http    0.098478        71      377     SF      T       F       0       ShADadFf 6       335     4       549     -       6
   1747147654.275660       Cr9BdR12amVJ5y2dE9      192.168.1.8     52918   192.0.78.150    80       tcp     http    0.100107        73      377     SF      T       F       0       ShADadFf 6       337     4       549     -       6
   #close  2025-12-05-16-38-23

This has a lot of information. We can pipe this through ``zeek-cut`` in
order to get more condensed information:

.. code:: console

   # cat conn.log | zeek-cut -m
   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   service  duration        orig_bytes      resp_bytes      conn_state      local_orig      local_resp       missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes    tunnel_parents  ip_proto
   1747147647.668533       CgnovV3tXhiyU385S       192.168.1.8     52917   192.0.78.212    80       tcp     http    0.098478        71      377     SF      T       F       0       ShADadFf 6       335     4       549     -       6
   1747147654.275660       Cr9BdR12amVJ5y2dE9      192.168.1.8     52918   192.0.78.150    80       tcp     http    0.100107        73      377     SF      T       F       0       ShADadFf 6       337     4       549     -       6

This removes much of the random TSV declarations (like
``#set_separator``). The header name for each log column is provided due
to the ``-m`` flag. You can also ask ``zeek-cut`` to only provide
certain fields. In this case, we may only care about the uid and ip
addresses. You can ask for just those fields:

.. code:: console

   # cat conn.log | zeek-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p
   uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p
   CgnovV3tXhiyU385S       192.168.1.8     52917   192.0.78.212    80
   Cr9BdR12amVJ5y2dE9      192.168.1.8     52918   192.0.78.150    8

Now, we can find the ``weird.log``:

.. code:: console

   # cat weird.log | zeek-cut -m uid name
   uid     name
   Cr9BdR12amVJ5y2dE9      unknown_HTTP_method

Notice how the ``uid`` field in ``weird.log`` is the same as one of the
entries in ``conn.log``. This indicates that those entries are from the
same connection. You can "pivot" between these two logs, or any other
logs, using ``uid`` fields!

The ``conn.log`` entries we saw before had some timestamps, but they
were in epoch time. We can use ``-d`` in order to convert those to a
human readable format:

.. code:: console

   # cat conn.log | zeek-cut -m ts
   ts
   1747147647.668533
   1747147654.275660
   # cat conn.log | zeek-cut -m -d ts
   ts
   2025-05-13T14:47:27+0000
   2025-05-13T14:47:34+0000

How do we know which fields to look for? As seen before, the TSV logs
have field names as headers near the top of the log. But, these can
often be hard to parse as-is. There is a better way.

*************
 Log Schemas
*************

The exact set and shape of Zeek's logs is highly site-dependent. While
every Zeek version ships with a set of logs enabled by default, it also
includes optional ones that you're welcome to enable. (Feel free to
peruse the full set.) In addition, many of Zeek's add-on packages
introduce logs of their own, or enrich existing ones with additional
metadata. And finally, Zeek's logging framework lets you apply your own
log customizations with a bit of scripting.

Zeek's logschema package helps you understand your Zeek logs. It
produces log schemas that detail your installation's set of logs and
their fields. For each field, the schemas provide rich metadata
including name, type, and docstrings. They can also explain the source
of a field, such as the specific script or the name of the Zeek package
that added it. Log schemas are also a great way to understand how and
whether your logs change when you upgrade to a newer version of Zeek.

To produce schemas, you need to tell Zeek which schema exporters to
load. An easy way to do this is to simply start Zeek with your installed
packages and an exporter of your choice. To get started, try the
following:

.. code:: console

   # zkg install logschema
   The following packages will be INSTALLED:
     zeek/zeek/logschema (v2.0.0)

   Proceed? [Y/n] y
   Running unit tests for "zeek/zeek/logschema"
   Installing "zeek/zeek/logschema"
   Installed "zeek/zeek/logschema" (v2.0.0)
   Loaded "zeek/zeek/logschema"
   # zeek logschema/export/jsonschema packages

Your local directory will now contain a JSON Schema description for each
of your installation's logs. If we want to find more about Zeek's DNS
log, we can do the following:

.. code:: console

   # cat zeek-dns-log.schema.json | jq

   {
     "$schema": "https://json-schema.org/draft/2020-12/schema",
     "title": "Schema for Zeek dns.log",
     "description": "JSON Schema for Zeek dns.log",
     "type": "object",
     "properties": {
        ...
        "uid": {
         "description": "A unique identifier of the connection over which DNS messages\nare being transferred.",
         "type": "string",
         "x-zeek": {
           "type": "string",
           "record_type": "DNS::Info",
           "script": "base/protocols/dns/main.zeek"
         }
      },
      ...
      "answers": {
         "description": "The set of resource descriptions in the query answer.",
         "type": "array",
         "items": {
           "type": "string"
         },
         "x-zeek": {
           "type": "vector of string",
           "record_type": "DNS::Info",
           "script": "base/protocols/dns/main.zeek"
         }
       },
       ...
   }

Most fields are omitted with ``...`` for brevity, but two fields were
included: ``uid`` and ``answers``. Let's use one of the testing PCAPs to
make some DNS logs:

.. code:: console

   # zeek -r traces/zeek-testing/dns/naptr.pcap

Then, we can find these in our DNS logs and examine the logs via
``zeek-cut``:

.. code:: console

   # cat dns.log | zeek-cut -m uid answers
   uid     answers
   Cr3Q4KSOgWL8IEAu2       NAPTR 100 100 s SIPS+D2T _sips._tcp.fp-de-carrier-vodafone.rcs.telephony.goog

From the log schemas, we can tell what fields a particular log has, then
find the values we need within those logs.

***********
 JSON logs
***********

Zeek also allows emitting logs in JSON form, rather than as TSV files.
This is generally more intuitive, especially since each field has its
field name as a JSON key. We already saw this in the quickstart, which
you can replicate:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap LogAscii::use_json=T
   # jq . -c conn.log
   {"ts":1747147647.668533,"uid":"ChtMU84Gm7vUkJ5XI7",...}
   {"ts":1747147654.27566,"uid":"CIV7B237oz89VBWTF4",...}

.. note::

   You can do the same in a cluster by modifying your site's
   ``local.zeek``:

   .. code:: console

      # vim $PREFIX/share/zeek/site/local.zeek

   Then add a line (anywhere!) that loads the
   ``policy/tuning/json-logs`` script:

   .. code:: zeek

      @load policy/tuning/json-logs

   Now, any logs that the cluster creates will be in JSON.

We can use ``jq`` for much more. You can find more about ``jq`` on the
`JQ homepage <jq_home_>`_. Here we use ``jq`` to print just the
originator and responder host addresses:

.. code:: console

   # jq -c '[."id.orig_h", ."id.resp_h"]' conn.log
   ["192.168.1.8","192.0.78.212"]
   ["192.168.1.8","192.0.78.150"]

For more information, look at the `jq manual <jq_manual_>`_.

JSON logs are used for a few purposes. First, they may be a better start
in a data-pipeline: JSON is a far more ubiquitous format, so integrating
with other tools is often far easier. Second, JSON logs contain the log
column as a key, making it far easier to understand the logs at a
glance.

However, JSON logs may take up more space. Including the keys for every
value is redundant and wastes space. Since Zeek's ``conn.log`` can get
very large, this can make the logs take up far more space than they
otherwise would.

It's up to the user whether TSV logs or JSON logs should be used. If
neither work, you may also create a custom writer. You may find more log
writers in the :ref:`Log Writers <log-writers>` section in :ref:`Popular
Customizations <popular-customizations>`.

.. _zeekcontrol_logs:

*****************************
 Analyzing Logs from Zeekctl
*****************************

This section analyzed logs created from Zeek invoked on capture files.
However, in a production environment, you will most likely use a cluster
and analyze the compressed logs from the cluster. To mimic this, you may
also use ``tcpreplay`` in order to replay traffic onto your cluster,
then analyze the logs in a similar way. In the tutorial's container, replay
the quickstart's pcap in between starting and stopping the cluster, like
so:

.. code:: console

   # zeekctl deploy
   checking configurations ...
   installing ...
   creating policy directories ...
   installing site policies ...
   generating standalone-layout.zeek ...
   generating local-networks.zeek ...
   generating zeekctl-config.zeek ...
   generating zeekctl-config.sh ...
   stopping ...
   stopping zeek ...
   starting ...
   starting zeek ...
   # tcpreplay -i eth0 traces/zeek-doc/quickstart.pcap
   Actual: 20 packets (2050 bytes) sent in 6.70 seconds
   Rated: 305.6 Bps, 0.002 Mbps, 2.98 pps
   Flows: 4 flows, 0.59 fps, 20 unique flow packets, 0 unique non-flow packets
   Statistics for network device: eth0
           Successful packets:        20
           Failed packets:            0
           Truncated packets:         0
           Retried packets (ENOBUFS): 0
           Retried packets (EAGAIN):  0
   # zeekctl stop
   stopping zeek ...


When running a Zeek cluster with ``zeekctl``, logs are stored within the
``logs`` directory relative to Zeek's installation directory. Thus, when
running in the tutorial's container, the logs will get stored in
``/usr/local/zeek/logs``. The current set of aggregated logs are in
``logs/current``. Archived logs are stored in a directory corresponding
with the date, such as ``logs/2025-08-20``. Log files also get renamed
to include a timestamp, so ``conn.log`` might become
``conn.2025-08-20-15-23-42.log``.

These are all gzip-compressed logs, as they end with the ``.gz``
extension. You can use a tool such as ``zcat`` to examine these. We can
look at ``conn.log``'s contents from the command line, then pipe these into
``zeek-cut`` just as before:

.. code:: console

   # zcat $PREFIX/logs/2025-12-11/conn.21\:55\:57-21\:56\:05.log.gz | zeek-cut -m
   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   service  duration        orig_bytes      resp_bytes      conn_state      local_orig      local_resp       missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes    tunnel_parents  ip_proto
   1765490152.990320       C8jSq83hCChihltDYd      192.168.1.8     52917   192.0.78.212    80       tcp     http    0.098612        71      377     SF      T       F       0       ShADTadtFf       12      670     8       1098    -       6
   1765490152.990319       CLyR2u2eyJp1MRMVp4      192.168.1.8     52917   192.0.78.212    80       tcp     http    0.098612        71      377     SF      T       F       0       ShADTadtFf       12      670     8       1098    -       6
   1765490159.598223       CzA1sF3CaHAqo6yyO3      192.168.1.8     52918   192.0.78.150    80       tcp     http    0.100184        73      377     SF      T       F       0       ShADTadtFf       12      674     8       1098    -       6
   1765490159.598222       CfdV2t3GpevvRneXl7      192.168.1.8     52918   192.0.78.150    80       tcp     http    0.100184        73      377     SF      T       F       0       ShADTadtFf       12      674     8       1098    -       6

******************
 Zeek's Core Logs
******************

Zeek ships with a number of logs by default-–-no configuration
necessary. The most important log is called ``conn.log``. This captures
“layer 3” and “layer 4” elements, such as who is talking to whom, for
how long, and with what protocol. In order to learn more about what
``conn.log`` offers, let's use the logschema package again:

.. code:: console

   # zeek logschema/export/jsonschema packages

   # cat zeek-conn-log.schema.json | jq
   {
     "$schema": "https://json-schema.org/draft/2020-12/schema",
     "title": "Schema for Zeek conn.log",
     "description": "JSON Schema for Zeek conn.log",
     "type": "object",
     "properties": {
       "ts": {
         "description": "This is the time of the first packet.",
         "type": "number",
         "examples": [
           "1737691432.132607"
         ],
         "x-zeek": {
           "type": "time",
           "record_type": "Conn::Info",
           "script": "base/protocols/conn/main.zeek"
         }
       },
       "uid": {
         "description": "A unique identifier of the connection.",
         "type": "string",
         "x-zeek": {
           "type": "string",
           "record_type": "Conn::Info",
           "script": "base/protocols/conn/main.zeek"
         }
       },
       ...
       "service": {
         "description": "A comma-separated list of confirmed protocol(s).\nWith :zeek:see:DPD::track_removed_services_in_connection, the list\nincludes the same protocols prefixed with \"-\" to record that Zeek\ndropped them due to parsing violations.\"",
         "type": "string",
         "x-zeek": {
           "type": "string",
           "record_type": "Conn::Info",
           "script": "base/protocols/conn/main.zeek"
         }
       },
       ...
     },
     "required": [
       "ts",
       "uid",
       "id.orig_h",
       "id.orig_p",
       "id.resp_h",
       "id.resp_p",
       "proto"
     ]
   }

You can find all fields within the schema's ``"properties"``. Here we
also show the ``service`` field, which is useful for pivoting between
logs. With that field, we can see which protocols Zeek confirmed. Then,
we can check that protocol's logs.

For example, let's look at the logs from the quickstart one more time.
Generate the traffic as TSV logs, first:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap

You can see that both ``conn.log`` entries include ``http`` in the
service field:

.. code:: console

   # cat conn.log | zeek-cut -m uid service
   uid     service
   C8i2Yl19BvJGppTPwc      http
   Cztl1P36g6jG9s0wTb      http

All of the (two) connections were HTTP. Given this, we can check the
HTTP log:

.. code:: console

   # cat http.log | zeek-cut -m uid
   uid
   C8i2Yl19BvJGppTPwc
   Cztl1P36g6jG9s0wTb

Those are the two UIDs we saw before. This pivoting is exactly how you
can correlate an HTTP connection with its ``conn.log`` entries,
``weird.log`` weirds, and more.

However, there are simply too many core logs, and too many ways to use
them, to cover here. For more information, see the :doc:`logs section
</logs/index>`.
