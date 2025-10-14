.. _logs:

######
 Logs
######

At this point, Zeek should be fully working on the docker image.
Now, we will see the power of Zeek: creating logs.

When running a Zeek cluster with ``zeekctl``, logs are stored within the
``logs`` directory relative to Zeek’s installation directory. Thus, when
running in the tutorial’s Docker container, the logs will get stored in
``/usr/local/zeek/logs``. The current set of aggregated logs are in
``logs/current``. Archived logs are stored in a directory corresponding
with the date, such as ``logs/2025-08-20``. Log files also get renamed
to include a timestamp, so ``conn.log`` might become
``conn.2025-08-20-15-23-42.log``.

The process of moving logs from being “current” to “archived” is called
rotation. You may change how frequently logs get rotated with
``zeekctl``\ ’s ``LogRotationInterval`` option (TODO: Link and explain
how to add the option?).

In this section, we will go over:

1) How to interact with Zeek’s logs and access the fields you want (THIS
IS “Zeek Log Formats and Inspection” SECTION)

2) A few of the common logs you will work with and how to pivot amongst
them (GO OVER conn.log, dns.log, ssl.log - SHOW HOW TO FIND MORE)

3) How real systems ingest, process, and store Zeek logs (THIS SECTION
IS NEW, BUT MAYBE PUT IN LOG ENRICHMENT AND KAFKA WRITER CUSTOMIZATIONS)

******************
 Zeek Log Formats
******************

Zeek’s default log format is tab-separated values, or TSV. TSV logs are
lightweight, efficient, and easy to parse. But, they’re not as suitable
for human consumption. Thankfully, Zeek comes with a tool called
``zeek-cut`` in order to examine these logs.

For this section, we will use `tcpreplay` in order to generate traffic
from a pcap. This way, we can run a Zeek cluster and see how you may
interact with archived logs using Zeek’s tooling. In the docker
container, replay the quickstart’s pcap in between starting and stopping
the cluster (TODO: should I put less of the output from commands?):

   .. code:: console

      root@zeek-tutorial:/opt $ zeekctl deploy
      checking configurations ...
      installing ...
      removing old policies in /usr/local/zeek/spool/installed-scripts-do-not-touch/site ...
      removing old policies in /usr/local/zeek/spool/installed-scripts-do-not-touch/auto ...
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
      root@zeek-tutorial:/opt $ tcpreplay -i eth0 traces/quickstart.pcap
      Actual: 20 packets (2050 bytes) sent in 6.70 seconds
      Rated: 305.6 Bps, 0.002 Mbps, 2.98 pps
      Flows: 4 flows, 0.59 fps, 20 unique flow packets, 0 unique non-flow packets
      Statistics for network device: eth0
              Successful packets:        20
              Failed packets:            0
              Truncated packets:         0
              Retried packets (ENOBUFS): 0
              Retried packets (EAGAIN):  0
      root@zeek-tutorial:/opt $ zeekctl stop
      stopping zeek ...

Now, there should be logs in the ``logs/DATE`` directory in your Zeek
installation. These are all gzip-compressed logs, as they end with the
``.gz`` extension. You can use a tool such as ``zcat`` to examine these.
For example, let’s look at ``conn.log`` (TODO: Normalize how we talk
about dates and timestamps and stuff):

   .. code:: console

      root@zeek-tutorial:/opt $ zcat < /usr/local/zeek/logs/2025-09-10/conn.15\:56\:17-15\:57\:07.log.gz
      #separator \x09
      #set_separator  ,
      #empty_field    (empty)
      #unset_field    -
      #path   conn
      #open   2025-05-22-15-05-14
      #fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto       service duration        orig_bytes      resp_bytes      conn_state      local_orig local_resp       missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes       tunnel_parents  ip_proto
      #types  time    string  addr    port    addr    port    enum    string  interval        count       count   string  bool    bool    count   string  count   count   count   count   set[string] count
      1747940682.774160       CUeRmfIt4UVGDtey6       192.168.1.1     19908   192.168.1.8     12458       udp     -       0.003133        3654    0       S0      T       T       0       D  203      9338    0       0       -       17

This has a lot of information. We can pipe this through ``zeek-cut`` and
get (TODO: Maybe use ``-m``):

   .. code:: console

      root@zeek-tutorial:/opt $ zcat < ~/.local/zeek/logs/2025-05-22/conn.15:05:14-15:05:18.log.gz | zeek-cut
      1747940682.774160 CUeRmfIt4UVGDtey6 192.168.1.1 19908 192.168.1.8 12458 udp - 0.003133 3654 0 S0 T T 0 D 203 9338 0 0 - 17

Which removes all of the header information - this may be useful, but
there’s more. You can ask ``zeek-cut`` to only provide certain fields.
In this case, we may only care about the uid, and ip addresses. You can
ask for just those fields:

   .. code:: console

      root@zeek-tutorial:/opt $ zcat < /usr/local/zeek/logs/2025-09-10/conn.15\:56\:17-15\:57\:07.log.gz | zeek-cut -d uid id.orig_h id.orig_p id.resp_h id.resp_p
      CuBQO541HNkqlHqu5 192.168.1.8 52917 192.0.78.212 80 CcjU1f2OJNnIuUPX3e 192.168.1.8 52918 192.0.78.150 80

TODO: Normalize the UIDs so they match between weird/conn.log

Now, we can find the weird.log in that directory:

   .. code:: console

      root@zeek-tutorial:/opt $ zcat < /usr/local/zeek/logs/2025-09-10/weird.15\:56\:18-15\:57\:07.log.gz | zeek-cut uid name
      CcjU1f2OJNnIuUPX3e unknown_HTTP_method

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

[[ THE FOLLOWING IS COPY-PASTED FROM THE LOGSCHEMA SECTION ]]

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

      root@zeek-tutorial:/opt $ zkg install logschema
      root@zeek-tutorial:/opt $ zeek logschema/export/jsonschema packages

[[END EXACT COPY]]

Your local directory will now contain a JSON Schema description for each
of your installation’s logs. If we want to find more about Zeek’s DNS
log, we can do the following:

   .. code:: console

      root@zeek-tutorial:/opt $ cat zeek-dns-log.schema.json | jq
      {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Schema for Zeek dns.log",
        "description": "JSON Schema for Zeek dns.log",
        "type": "object",
        "properties": {
        …,
        "uid": {
            "description": "A unique identifier of the connection over which DNS messages\nare being transferred.",
            "type": "string",
            "x-zeek": {
              "type": "string",
              "record_type": "DNS::Info",
              "is_optional": false,
              "script": "base/protocols/dns/main.zeek"
            }
          },
          …
         "answers": {
            "description": "The set of resource descriptions in the query answer.",
            "type": "array",
            "items": {
              "type": "string"
            },
            "x-zeek": {
              "type": "vector of string",
              "record_type": "DNS::Info",
              "is_optional": true,
              "script": "base/protocols/dns/main.zeek"
            }
          },
         …
      }

Most fields are omitted with ``...`` for brevity, but there are some
useful fields, like ``uid`` and ``answers``. We can find these in our
DNS logs from earlier and examine the logs via ``zeek-cut``:

   .. code:: console

      root@zeek-tutorial:/opt $ zcat < ~/.local/zeek/logs/2025-05-22/dns.15:10:06-15:10:36.log.gz | zeek-cut -d uid answers
      C9x0FM1IWYhDMjY3Mh      192.0.78.212,192.0.78.150
      C5kMJQNZUsemhJENf       -
      Cf0uuG49Kez6nNBvC1      -
      …

TODO: Json?

******************
 Zeek's Core Logs
******************

Zeek ships with a number of logs by default – no configuration
necessary. In this section, we will look at a few of these logs, their
important fields, and how to pivot amongst them in order to understand
your network traffic. For more detail about the majority of Zeek’s
included logs, go to the logs section (TODO link).

Zeek’s most important log is called ``conn.log``. This captures “layer
3” and “layer 4” elements, such as who is talking to whom, for how long,
and with what protocol. In order to learn more about what ``conn.log``
offers, let’s use the logschema package again:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek logschema/export/jsonschema packages
      root@zeek-tutorial:/opt $ cat zeek-conn-log.schema.json| jq
      {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Schema for Zeek conn.log",
        "description": "JSON Schema for Zeek conn.log",
        "type": "object",
        "properties": {
          TODO: Figure out how to list these?
        }
      };

You can find all fields within the schema’s ``”properties”`` – since we
are interested in the generated HTTP traffic from before, we mainly care
about two fields: ``uid`` and ``service``. UID will help “pivot” from
conn.log into http.log later, while ``service`` will help determine
which protocols were confirmed for that connection. We can find those
fields with the following:

TODO: fix log paths, that's my local path

   .. code:: console

      root@zeek-tutorial:/opt $ zcat < ~/.local/zeek/logs/2025-05-22/conn.15:10:06-15:10:36.log.gz | zeek-cut -d uid service
      CSWRb24zBaNLpYJ8N2      http
      C5Ee6U2oEJOCGjygMe      http
      Cdc6qu3VoRoZyx3QZ4      http
      C9x0FM1IWYhDMjY3Mh      dns
      C5kMJQNZUsemhJENf       dns
      Cup19I1ximEB1fzzt9      dns
      …

TODO: Finish this section :)
