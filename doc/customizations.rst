.. _popular-customizations:

======================
Popular Customizations
======================

This page outlines customizations and additions that are popular
among Zeek users.

.. note::

  This page lists externally-maintained Zeek packages. The Zeek team does not
  provide support or maintenance for these packages. If you find bugs or have
  feature requests, please reach out to the respective package maintainers directly.

  You may also post in the :slacklink:`Zeek Slack <>` #packages
  channel or :discourselink:`forum <>` to get help from the broader
  Zeek community.


Log Enrichment
==============

Community ID
------------

.. versionadded:: 6.0

Zeek includes native `Community ID Flow Hashing`_ support. This functionality
has previously been provided through the `zeek-community-id`_ package.

.. note::

  At this point, the external `zeek-community-id`_ package is still
  available to support Zeek deployments running older versions. However,
  the scripts provided by the package cause conflicts with those provided in
  Zeek 6.0 - do not load both.

Loading the
:doc:`/scripts/policy/protocols/conn/community-id-logging.zeek`
and
:doc:`/scripts/policy/frameworks/notice/community-id.zeek`
scripts adds an additional ``community_id`` field to the
:zeek:see:`Conn::Info` and :zeek:see:`Notice::Info` record.

.. code-block:: console

   $ zeek -r ./traces/get.trace protocols/conn/community-id-logging LogAscii::use_json=T
   $ jq < conn.log
   {
     "ts": 1362692526.869344,
     "uid": "CoqLmg1Ds5TE61szq1",
     "id.orig_h": "141.142.228.5",
     "id.orig_p": 59856,
     "id.resp_h": "192.150.187.43",
     "id.resp_p": 80,
     "proto": "tcp",
     ...
     "community_id": "1:yvyB8h+3dnggTZW0UEITWCst97w="
   }


The Community ID Flow Hash of a :zeek:see:`conn_id` instance can be computed
with the :zeek:see:`community_id_v1` builtin function directly on the command-line
or used in custom scripts.

.. code-block:: console

    $ zeek -e 'print community_id_v1([$orig_h=141.142.228.5, $orig_p=59856/tcp, $resp_h=192.150.187.43, $resp_p=80/tcp])'
    1:yvyB8h+3dnggTZW0UEITWCst97w=

.. _Community ID Flow Hashing: https://github.com/corelight/community-id-spec
.. _zeek-community-id: https://github.com/corelight/zeek-community-id/>`_

.. _geolocation:

Address geolocation and AS lookups
----------------------------------

.. _libmaxminddb: https://github.com/maxmind/libmaxminddb

Zeek supports IP address geolocation as well as AS (autonomous system)
lookups. This requires two things:

    * Compilation of Zeek with the `libmaxminddb`_ library and development
      headers. If you're using our :ref:`Docker images <docker-images>` or
      :ref:`binary packages <binary-packages>`, there's nothing to do: they ship
      with GeoIP support.
    * Installation of corresponding MaxMind database files on your
      system.

To check whether your Zeek supports geolocation, run ``zeek-config --have-geoip``
(available since Zeek 6.2) or simply try an address lookup. The following
indicates that your Zeek lacks support:

.. code-block:: console

    $ zeek -e 'lookup_location(1.2.3.4)'
    error in <command line>, line 1: Zeek was not configured for GeoIP support (lookup_location(1.2.3.4))

Read on for more details about building Zeek with GeoIP support, and how to
configure access to the database files.

Building Zeek with libmaxminddb
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you build Zeek yourself, you need to install libmaxminddb prior to
configuring your build.

* RPM/RedHat-based Linux:

  .. code-block:: console

      sudo yum install libmaxminddb-devel

* DEB/Debian-based Linux:

  .. code-block:: console

      sudo apt-get install libmaxminddb-dev

* FreeBSD:

  .. code-block:: console

      sudo pkg install libmaxminddb

* Mac OS X:

  You need to install from your preferred package management system
  (e.g. Homebrew, MacPorts, or Fink).  For Homebrew, the name of the package
  that you need is libmaxminddb.

The ``configure`` script's output indicates whether it successfully located
libmaxminddb. If your system's MaxMind library resides in a non-standard path,
you may need to specify it via ``./configure --with-geoip=<path>``.

Installing and configuring GeoIP databases
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

MaxMind's databases ship as individual files that you can `download
<https://www.maxmind.com/en/accounts/current/geoip/downloads>`_ from their
website after `signing up <https://www.maxmind.com/en/geolite2/signup>`_ for an
account. Some Linux distributions also offer free databases in their package
managers.

There are three types of databases: city-level geolocation, country-level
geolocation, and mapping of IP addresses to autonomous systems (AS number and
organization). Download these and decide on a place to put them on your
file system. If you use automated tooling or system packages for the
installation, that path may be chosen for you, such as ``/usr/share/GeoIP``.

Zeek provides three ways to configure access to the databases:

* Specifying the path and filenames via script variables. Use the
  :zeek:see:`mmdb_dir` variable, unset by default, to point to the directory
  containing the database(s). By default Zeek looks for databases called
  ``GeoLite2-City.mmdb``, ``GeoLite2-Country.mmdb``, and
  ``GeoLite2-ASN.mmdb``. Starting with Zeek 6.2 you can adjust these names by
  redefining the :zeek:see:`mmdb_city_db`, :zeek:see:`mmdb_country_db`, and
  :zeek:see:`mmdb_asn_db` variables.
* Relying on Zeek's pre-configured search paths and filenames. The
  :zeek:see:`mmdb_dir_fallbacks` variable contains default
  search paths that Zeek will try in turn when :zeek:see:`mmdb_dir` is not
  set. Prior to Zeek 6.2 these paths were hardcoded; they're now redefinable.
  For geolocation, Zeek first attempts the city-level databases due to their
  greater precision, and falls back to the city-level one.  You can adjust the
  database filenames via :zeek:see:`mmdb_city_db` and related variables, as
  covered above.
* Opening databases explicitly via scripting. The
  :zeek:see:`mmdb_open_location_db` and :zeek:see:`mmdb_open_asn_db`
  functions take full paths to database files. Zeek only ever uses one
  geolocation and one ASN database, and these loads override any databases
  previously loaded. These loads can occur at any point.

Querying the databases
^^^^^^^^^^^^^^^^^^^^^^

Two built-in functions provide GeoIP functionality:

.. code-block:: zeek

    function lookup_location(a:addr): geo_location
    function lookup_autonomous_system(a:addr): geo_autonomous_system

:zeek:see:`lookup_location` returns a :zeek:see:`geo_location` record with
country/region/etc fields, while :zeek:see:`lookup_autonomous_system` returns a
:zeek:see:`geo_autonomous_system` record indicating the AS number and
organization. Depending on the queried IP address some fields may be
uninitialized, so you should guard access with an ``a?$b`` :ref:`existence test
<record-field-operators>`.

Zeek tests the database files for staleness. If it detects that a database has
been updated, it will automatically reload it. Zeek does not automatically add
GeoIP intelligence to its logs, but several add-on scripts and packages provide
such functionality. These include:

* The :ref:`notice framework <notice-framework>` lets you configure notice types
  that you'd like to augment with location information. See
  :zeek:see:`Notice::lookup_location_types` and
  :zeek:see:`Notice::ACTION_ADD_GEODATA` for details.
* The :doc:`/scripts/policy/protocols/smtp/detect-suspicious-orig.zeek` and
  :doc:`/scripts/policy/protocols/ssh/geo-data.zeek` policy scripts.
* Several `Zeek packages <https://packages.zeek.org>`_.

Testing
^^^^^^^

Before using the GeoIP functionality it is a good idea to verify that
everything is setup correctly. You can quickly check if the GeoIP
functionality works by running commands like these:

.. code-block:: console

    zeek -e "print lookup_location(8.8.8.8);"

If you see an error message similar to "Failed to open GeoIP location database",
then your database configuration is broken. You may need to rename or move your
GeoIP database files.

Example
^^^^^^^

The following shows every FTP connection from hosts in Ohio, US:

.. code-block:: zeek

    event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
    {
      local client = c$id$orig_h;
      local loc = lookup_location(client);

      if (loc?$region && loc$region == "OH" && loc?$country_code && loc$country_code == "US")
      {
        local city = loc?$city ? loc$city : "<unknown>";

        print fmt("FTP Connection from:%s (%s,%s,%s)", client, city,
          loc$region, loc$country_code);
      }
    }


Log Writers
===========

Kafka
-----

For exporting logs to `Apache Kafka`_ in a streaming fashion, the externally-maintained
`zeek-kafka`_ package is a popular choice and easy to configure. It relies on `librdkafka`_.

.. code-block:: zeek

   redef Log::default_writer = Log::WRITER_KAFKAWRITER;

   redef Kafka::kafka_conf += {
       ["metadata.broker.list"] = "192.168.0.1:9092"
   };

.. _Apache Kafka: https://kafka.apache.org/
.. _zeek-kafka: https://github.com/SeisoLLC/zeek-kafka/
.. _librdkafka: https://github.com/confluentinc/librdkafka


Logging
=======

JSON Streaming Logs
-------------------

The externally-maintained `json-streaming-logs`_ package tailors Zeek
for use with log shippers like `Filebeat`_ or `fluentd`_. It configures
additional log files prefixed with ``json_streaming_``, adds ``_path``
and ``_write_ts`` fields to log records and configures log rotation
appropriately.

If you do not use a logging archive and want to stream all logs away
from the system where Zeek is running without leveraging Kafka, this
package helps you with that.

.. _json-streaming-logs: https://github.com/corelight/json-streaming-logs
.. _Filebeat: https://www.elastic.co/beats/filebeat
.. _fluentd: https://www.fluentd.org/


Long Connections
----------------

Zeek logs connection entries into the ``conn.log`` only upon termination
or due to expiration of inactivity timeouts. Depending on the protocol and
chosen timeout values this can significantly delay the appearance of a log
entry for a given connection. The delay may be up to an hour for lingering
SSH connections or connections where the final FIN or RST packets were missed.

The `zeek-long-connections`_ package alleviates this by creating a ``conn_long.log``
log with the same format as ``conn.log``, but containing entries for connections
that have been existing for configurable intervals.
By default, the first entry for a connection is logged after 10mins. Depending on
the environment, this can be lowered as even a 10 minute delay may be significant
for detection purposes in streaming setup.

.. _zeek-long-connections: https://github.com/corelight/zeek-long-connections


Profiling and Debugging
=======================

jemalloc profiling
------------------

For investigation of memory leaks or state-growth issues within Zeek,
jemalloc's profiling is invaluable. A package providing a bit support
for configuring jemalloc's profiling facilities is `zeek-jemalloc-profiling`_.

Some general information about memory profiling exists in the :ref:`Troubleshooting <troubleshooting>`
section.

.. _zeek-jemalloc-profiling: https://github.com/JustinAzoff/zeek-jemalloc-profiling
