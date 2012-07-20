
========================================
Indexed Logging Output with ElasticSearch
========================================

.. rst-class:: opening

   Bro's default ASCII log format is not exactly the most efficient
   way for storing and searching large volumes of data. ElasticSearch
   is a new and exciting technology for dealing with tons of data.
   ElasticSearch is a search engine built on top of Apache's Lucene
   project. It scales very well, both for distributed indexing and 
   distributed searching.

.. contents::

Installing ElasticSearch
------------------------

ElasticSearch requires a JRE to run. Please download the latest version
from: <http://www.elasticsearch.org/download/>. Once extracted, start
ElasticSearch with::

# ./bin/elasticsearch

Compiling Bro with ElasticSearch Support
----------------------------------------

First, ensure that you have libcurl installed the run configure.::

    # ./configure
    [...]
    ====================|  Bro Build Summary  |=====================
    [...]
    cURL:              true
    [...]
    ElasticSearch:     true
    [...]
    ================================================================

Activating ElasticSearch
------------------------

The direct way to use ElasticSearch is to switch *all* log files over to
ElasticSearch. To do that, just add ``redef
Log::default_writer=Log::WRITER_ELASTICSEARCH;`` to your ``local.bro``.
For testing, you can also just pass that on the command line::

    bro -r trace.pcap Log::default_writer=Log::WRITER_ELASTICSEARCH

With that, Bro will now write all its output into ElasticSearch. You can 
inspect these using ElasticSearch's REST-ful interface. For more
information, see: <http://www.elasticsearch.org/guide/reference/api/>.

There is also a rudimentary web interface to ElasticSearch, available at:
<http://mobz.github.com/elasticsearch-head/>.

You can also switch only individual files over to ElasticSearch by adding
code like this to your ``local.bro``::

.. code::bro

    event bro_init()
        {
        local f = Log::get_filter(Conn::LOG, "default"); # Get default filter for connection log.
        f$writer = Log::WRITER_ELASTICSEARCH;               # Change writer type.
        Log::add_filter(Conn::LOG, f);                   # Replace filter with adapted version.
        }

Configuring ElasticSearch
-------------------------

Bro's ElasticSearch writer comes with a few configuration options::

- cluster_name: Currently unused.

- server_host:  Where to send the data. Default localhost.

- server_port:  What port to send the data to. Default 9200.

- index_prefix:   ElasticSearch indexes are like databases in a standard DB model. 
  This is the name of the index to which to send the data. Default bro.

- type_prefix:  ElasticSearch types are like tables in a standard DB model. This is a prefix that gets prepended to Bro log names. Example: type_prefix = "bro_" would create types "bro_dns", "bro_http", etc. Default: none.

- batch_size:   How many messages to buffer before sending to ElasticSearch. This is mainly a memory optimization - changing this doesn't seem to affect indexing performance that much. Default: 10,000.

TODO
----

Lots.

- Perform multicast discovery for server.
- Better error detection.
- Better defaults (don't index loaded-plugins, for instance).
