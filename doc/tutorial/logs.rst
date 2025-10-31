.. _logs:

######
 Logs
######

At this point, we have a working Zeek cluster configured to your system.
Now, we will see the power of Zeek: creating logs.

When running a Zeek cluster with ``zeekctl``, logs are stored within the
``logs`` directory relative to Zeek’s installation directory. Thus, when
running in the tutorial’s Docker container, the logs will get stored in
``/usr/local/zeek/logs``. The current set of aggregated logs are in
``logs/current``. Archived logs are stored in a directory corresponding
with the date, such as ``logs/2025-08-20``. Log files also get renamed
to include a timestamp, so ``conn.log`` might become
``conn.2025-08-20-15-23-42.log``.

.. note::

   For this tutorial, you may also use the ``PREFIX`` environment
   variable. This has been setup to point to ``/usr/local/zeek`` by the
   docker setup script.

The process of moving logs from being “current” to “archived” is called
rotation. You may change how frequently logs get rotated with
``zeekctl``\ ’s ``LogRotationInterval`` option (TODO: Link and explain
how to add the option?).

In this section, we will go over:

#. How to interact with Zeek’s logs and access the fields you want

2) A few of the common logs you will work with and how to pivot amongst
them

3. How real systems ingest, process, and store Zeek logs

******************
 Zeek Log Formats
******************

Zeek’s default log format is tab-separated values, or TSV. TSV logs are
lightweight, efficient, and easy to parse. But, they’re not as suitable
for human consumption. Thankfully, Zeek comes with a tool called
``zeek-cut`` in order to examine these logs.

For this section, we will use ``tcpreplay`` in order to generate traffic
from a pcap. This way, we can run a Zeek cluster and see how you may
interact with archived logs using Zeek’s tooling. In the docker
container, replay the quickstart’s pcap in between starting and stopping
the cluster, like so:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeekctl deploy
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
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ tcpreplay -i eth0 traces/zeek-doc/quickstart.pcap
   Actual: 20 packets (2050 bytes) sent in 6.70 seconds
   Rated: 305.6 Bps, 0.002 Mbps, 2.98 pps
   Flows: 4 flows, 0.59 fps, 20 unique flow packets, 0 unique non-flow packets
   Statistics for network device: eth0
           Successful packets:        20
           Failed packets:            0
           Truncated packets:         0
           Retried packets (ENOBUFS): 0
           Retried packets (EAGAIN):  0
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeekctl stop
   stopping zeek ...

Now, there should be logs in the ``$PREFIX/logs/DATE`` directory, where
``DATE`` is the current date. These are all gzip-compressed logs, as
they end with the ``.gz`` extension. You can use a tool such as ``zcat``
to examine these. For example, let’s look at ``conn.log`` (TODO:
Normalize how we talk about dates and timestamps and stuff):

.. code:: console

   $ zcat < $PREFIX/logs/2025-10-30/conn.21\:05\:03-21\:05\:10.log.gz
   #separator \x09
   #set_separator  ,
   #empty_field    (empty)
   #unset_field    -
   #path   conn
   #open   2025-10-30-21-05-03
   #fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto       service duration        orig_bytes      resp_bytes      conn_state      local_orig local_resp       missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes       tunnel_parents  ip_proto
   #types  time    string  addr    port    addr    port    enum    string  interval        count       count   string  bool    bool    count   string  count   count   count   count   set[string] count
   1761858297.903499       CRQaDt4ZfFmKyUINR4      192.168.1.8     52917   192.0.78.212    80 tcp      http    0.098687        71      377     SF      T       F       0       ShADTadtFf 12       670     8       1098    -       6
   1761858304.511300       Cq6HJ1lEBlYcXcZB        192.168.1.8     52918   192.0.78.150    80 tcp      http    0.100184        73      377     SF      T       F       0       ShADTadtFf 12       674     8       1098    -       6
   #close  2025-10-30-21-05-10

This has a lot of information. We can pipe this through ``zeek-cut`` in
order to get more condensed information:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zcat < $PREFIX/logs/2025-10-30/conn.21\:05\:03-21\:05\:10.log.gz | zeek-cut -m
   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   service     duration        orig_bytes      resp_bytes      conn_state      local_orig      local_resp  missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes       tunnel_parents  ip_proto
   1761858297.903499       CRQaDt4ZfFmKyUINR4      192.168.1.8     52917   192.0.78.212    80 tcp      http    0.098687        71      377     SF      T       F       0       ShADTadtFf 12       670     8       1098    -       6
   1761858304.511300       Cq6HJ1lEBlYcXcZB        192.168.1.8     52918   192.0.78.150    80 tcp      http    0.100184        73      377     SF      T       F       0       ShADTadtFf 12       674     8       1098    -       6

This removes much of the random TSV declarations (like
``#set_separator``). The header name for each log column is provided due
to the ``-m`` flag. You can also ask ``zeek-cut`` to only provide
certain fields. In this case, we may only care about the uid, and ip
addresses. You can ask for just those fields:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zcat < $PREFIX/logs/2025-10-30/conn.21\:05\:03-21\:05\:10.log.gz | zeek-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p
   uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p
   CRQaDt4ZfFmKyUINR4      192.168.1.8     52917   192.0.78.212    80
   Cq6HJ1lEBlYcXcZB        192.168.1.8     52918   192.0.78.150    80

Now, we can find the weird.log in that directory:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zcat < $PREFIX/logs/2025-10-30/weird.21\:05\:04-21\:05\:10.log.gz | zeek-cut uid name
   Cq6HJ1lEBlYcXcZB        unknown_HTTP_method

Since the UID is the same on the second conn.log entry and the single
weird.log entry, they are the same connection. You can “pivot” between
these two logs, or any other logs! Any entries with the same UID are
from that same connection.

How do we know which fields to look for? As seen before, the TSV logs
have field names as headers near the top of the log. But, these can
often be hard to parse as-is. There is a better way.

*************
 Log Schemas
*************

The exact set and shape of Zeek’s logs is highly site-dependent. While
every Zeek version ships with a set of logs enabled by default, it also
includes optional ones that you’re welcome to enable. (Feel free to
peruse the full set.) In addition, many of Zeek’s add-on packages
introduce logs of their own, or enrich existing ones with additional
metadata. And finally, Zeek’s logging framework lets you apply your own
log customizations with a bit of scripting.

Zeek’s logschema package helps you understand your Zeek logs. It
produces log schemas that detail your installation’s set of logs and
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

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zkg install logschema
   The following packages will be INSTALLED:
     zeek/zeek/logschema (v2.0.0)

   Proceed? [Y/n] y
   Running unit tests for "zeek/zeek/logschema"
   Installing "zeek/zeek/logschema"
   Installed "zeek/zeek/logschema" (v2.0.0)
   Loaded "zeek/zeek/logschema"
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeek logschema/export/jsonschema packages

Your local directory will now contain a JSON Schema description for each
of your installation’s logs. If we want to find more about Zeek’s DNS
log, we can do the following:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ cat zeek-dns-log.schema.json | jq

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
       …
   }

Most fields are omitted with ``...`` for brevity, but two fields were
included: ``uid`` and ``answers``. Let's use one of the testing PCAPs to
make some DNS logs:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeekctl deploy
   <removed for brevity>
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ tcpreplay -i eth0 traces/zeek-testing/dns/naptr.pcap
   <removed for brevity>
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeekctl stop
   stopping zeek ...

Then, we can find these in our DNS logs and examine the logs via
``zeek-cut``:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zcat < $PREFIX/logs/2025-10-31/dns.14\:00\:13-14\:00\:18.log.gz | zeek-cut uid answers
   C5Vg0OAHusZgPpN1a       NAPTR 100 100 s SIPS+D2T _sips._tcp.fp-de-carrier-vodafone.rcs.telephony.goog

***********
 JSON logs
***********

Zeek also allows emitting logs in JSON form, rather than as TSV files.
This is generally more intuitive, especially since each field has its
field name as a JSON key. We already saw this in the quickstart, which
you can replicate:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeek -r traces/zeek-doc/quickstart.pcap LogAscii::use_json=T
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ cat conn.log | jq
   {
     "ts": 1747147647.668533,
     "uid": "CdNTLx4dUOPnF06Zy",
     ...
   }

You can do the same in a cluster by simply modifying your site's
``local.zeek``:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ vim $PREFIX/share/zeek/site/local.zeek

Then simply add a line (anywhere!) that loads the
``policy/tuning/json-logs`` script:

.. code:: zeek

   @load policy/tuning/json-logs

Then redeploy the cluster and replay the quickstart pcap:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeekctl deploy
   <removed for brevity>
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ tcpreplay -i eth0 traces/zeek-doc/quickstart.pcap
   <removed for brevity>
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeekctl stop
   stopping zeek ...

And finally, see the produced log. Pick the ``conn.log`` with the most
recent timestamp for this:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zcat $PREFIX/logs/2025-10-31/conn.14\:14\:42-14\:14\:52.log.gz  | jq
   {
     "ts": 1761920077.568221,
     "uid": "CyIGBd1t1afUDc5c01",
     ...
   }

JSON logs are used for a few purposes. First, they may be a better start
in a data-pipeline: JSON is a far more ubiquitous format, so integrating
with other tools is often far easier. Second, JSON logs contain the log
column as a key, making it far easier to understand the logs at a
glance.

However, they also have drawbacks. JSON logs are not streamable: an
incomplete JSON log is no longer valid JSON, as the braces will not be
closed. Furthermore, including the keys for every value is redundant and
wastes space. Since Zeek's ``conn.log`` can get very large, this can
make the logs take up far more space than they otherwise would.

It's up to the user whether TSV logs or JSON logs should be used.
Luckily, it's a simple change either way.

******************
 Zeek's Core Logs
******************

Zeek ships with a number of logs by default – no configuration
necessary. In this section, we will look at a few of these logs, their
important fields, and how to pivot amongst them in order to understand
your network traffic. For more detail about the majority of Zeek’s
included logs, go to the :doc:`logs section </logs/index>`.

Zeek’s most important log is called ``conn.log``. This captures “layer
3” and “layer 4” elements, such as who is talking to whom, for how long,
and with what protocol. In order to learn more about what ``conn.log``
offers, let’s use the logschema package again:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeek logschema/export/jsonschema packages

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ cat zeek-conn-log.schema.json | jq
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

You can find all fields within the schema’s ``”properties”`` – since we
are interested in the generated HTTP traffic from before, we mainly care
about two fields: ``uid`` and ``service``. UID will help “pivot” from
conn.log into http.log later, while ``service`` will help determine
which protocols were confirmed for that connection. We can find those
fields with the following:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zcat $PREFIX/logs/2025-10-31/conn.13\:48\:27-13\:48\:48.log.gz | zeek-cut uid service
   CYu35U3lzHj4keTQs4      http
   CeOHyV3P5Vs7Yyl6Qd      http

TODO: Finish this section :)
