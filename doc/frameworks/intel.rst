
======================
Intelligence Framework
======================

Introduction
============

The goals of Zeek’s Intelligence Framework are to consume intelligence data,
make it available for matching, and provide infrastructure to improve
performance and memory utilization.

Data in the Intelligence Framework is an atomic piece of intelligence such as
an IP address or an e-mail address. This atomic data will be packed with
metadata such as a freeform source field, a freeform descriptive field, and a
URL which might lead to more information about the specific item. The metadata
in the default scripts has been deliberately kept to a minimum.

Quick Start
===========

First we need to define the intelligence data to match. Let's look for the
domain ``www.reddit.com``. For the details of the file format see the
:ref:`Loading Intelligence <loading-intelligence>` section below.

::

  #fields	indicator	indicator_type	meta.source
  www.reddit.com	Intel::DOMAIN	my_special_source

Now we need to tell Zeek about the data. Add this line to your local.zeek to
load an intelligence file:

.. code-block:: zeek

  redef Intel::read_files += { "/somewhere/yourdata.txt" };

In a cluster, the text files only need to reside on the manager.

Add the following line to :file:`local.zeek` to load the scripts that send
“seen” data into the Intelligence Framework to be checked against the loaded
intelligence data:

.. code-block:: zeek

  @load frameworks/intel/seen

Intelligence data matches will be logged to the :file:`intel.log` file. A match
on ``www.reddit.com`` might look like this::

  {
  "ts":1320279566.452687,
  "uid":"C4llPsinsviGyNY45",
  "id.orig_h":"192.168.2.76",
  "id.orig_p":52026,
  "id.resp_h":"132.235.215.119",
  "id.resp_p":80,
  "seen.indicator":"www.reddit.com",
  "seen.indicator_type":"Intel::DOMAIN",
  "seen.where":"HTTP::IN_HOST_HEADER",
  "seen.node":"zeek",
  "matched":[
	  "Intel::DOMAIN"
  ],
  "sources":[
	  "my_special_source"
  ]}

You can explore this example on `try.zeek.org
<https://try.zeek.org/#/?example=intel-intel-1>`_.

Architecture
============

The Intelligence Framework can be thought of as containing three separate
portions. The first part involves loading intelligence data. The second is a
mechanism for indicating to the intelligence framework that a piece of data
which needs to be checked has been seen. The third handles when a positive
match has been discovered.

.. image:: /images/intel-architecture.png
  :align: center

The figure above depicts how these portions work together: loading intelligence
*inserts* the data into an in-memory data store that is managed by the
intelligence framework. During traffic analysis, scripts report the *seen* data
to the framework to check against the loaded items.

.. _loading-intelligence:

Loading Intelligence
--------------------

By default, intelligence data is loaded through plain text files using the
Input Framework. In clusters the manager is the only node that needs the
intelligence data. The intelligence framework has distribution mechanisms which
will push data out to all of the nodes that need it.

Here is an example of the intelligence data format. All fields must be
separated by a single tab character and fields containing only a hyphen are
considered to be null values. Note that there may be additional fields
depending on the loaded extensions. One example is the
:doc:`/scripts/policy/frameworks/intel/do_notice.zeek` script as described
below.

::

  #fields indicator       indicator_type  meta.source     meta.desc       meta.url
  1.2.3.4 Intel::ADDR     source1 Sending phishing email  http://source1.com/badhosts/1.2.3.4
  a.b.com Intel::DOMAIN   source2 Name used for data exfiltration -

For a list of all built-in ``indicator_type`` values, please refer to the
documentation of :zeek:see:`Intel::Type`.

To load the data once the files are created, add the following to your
``local.zeek`` to specify which intel files to load (with your own file names
of course):

.. code-block:: zeek

  redef Intel::read_files += {
          "/somewhere/feed1.txt",
          "/somewhere/feed2.txt",
  };

Remember, the files only need to be present on the file system of the manager
node on cluster deployments.

The intel framework is very flexible so that intelligence matching can be
extended in numerous ways. For example, the
:doc:`/scripts/policy/frameworks/intel/do_notice.zeek`
script implements a
simple mechanism to raise a Zeek notice (of type :zeek:see:`Intel::Notice`) for
user-specified intelligence matches. To use this feature, add the following
line to ``local.zeek``:

.. code-block:: zeek

  @load frameworks/intel/do_notice

The script adds additional metadata fields. In particular, if the ``do_notice``
field of type bool is set to ``T`` for an intelligence item, Zeek will create a
notice when the item is matched.

Seen Data
---------

When some bit of data is extracted from network traffic (such as an email
address in the “From” header in a SMTP message), the Intelligence Framework
needs to be informed that this data was discovered so that its presence will be
checked within the loaded intelligence data. This is accomplished through the
:zeek:see:`Intel::seen` function.

Zeek includes a default set of scripts that will send data to the intelligence
framework. To load all of the scripts included with Zeek for sending “seen”
data to the intelligence framework, just add this line to ``local.zeek``:

.. code-block:: zeek

  @load frameworks/intel/seen

Alternatively, specific scripts in that directory can be loaded. Keep in mind
that as more data is sent to the intelligence framework, the CPU load consumed
by Zeek will increase depending on how many times the :zeek:see:`Intel::seen`
function is being called. The effect of this condition depends on the nature
and volume of the traffic Zeek monitors.

Zeek's intelligence framework can only match loaded items if corresponding
occurrences are reported as *seen*. For example, the scripts included with Zeek
will only report IP addresses from established TCP connections to the
intelligence framework. Thus, neither UDP traffic nor one-sided traffic will
trigger intelligence hits by default. However, it is easy to report additional
observations to the framework. The following will report the IPs of all
connections (including ICMP, UDP and one-sided traffic) to the intelligence
framework:

.. code-block:: zeek

  event new_connection(c: connection)
	  {
	  Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
	  Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
	  }

Note that using the :zeek:see:`new_connection` event could have a significant
impact on the overall performance as much more data might be processed by the
intelligence framework.

Intelligence Matches
--------------------

The Intelligence Framework provides an event that is generated whenever a match
is discovered. This event is named :zeek:see:`Intel::match` and receives two
arguments.  First, a record of type :zeek:see:`Intel::Seen` that describes the
observation as reported to the framework. It contains information about what
was seen (e.g., the domain ``www.slideshare.net``), where it was seen (e.g. in
an X509 certificate) and further context (e.g., a connection or a file record)
if available. The second argument is a set of intelligence items that matched
the observation. A set is used because multiple items may match a given
observation. For example, assume you have ingested the IP ``1.2.3.4`` from
source A and from source B as well as the subnet ``1.2.3.0/24`` from source B.
If the IP ``1.2.3.4`` is seen in your traffic, the match event will receive all
three intelligence items.

In a cluster setup, the match event is raised on the manager. This is important
to keep in mind when writing a script that handles the event. While the context
information about the match is available through the event parameters, the
handler itself is executed on the manager. Thus, one cannot access any state
that is local to the worker node that reported the observation in the first
place. Other interaction is also limited. For example, one cannot reliably
trigger file extraction based on an intelligence hit: Once the manager
processes the match event and comes to the conclusion that file extraction
would be desired, the worker that triggered the hit is most likely done
processing the corresponding data. Instead, one would need to start by
extracting all files that are potentially relevant, keep the ones that refer to
an intelligence hit and regularly discard the others.

Intelligence matches are logged to the :file:`intel.log` file. For further
description of each field in that file, see the documentation for the
:zeek:see:`Intel::Info` record.

The following are two matches from a sample :file:`intel.log`::

  {
    "ts": "2019-03-12T18:22:19.252191Z",
    "uid": "Cpue7J1KNReqCodXHc",
    "id.orig_h": "192.168.4.6",
    "id.orig_p": 64738,
    "id.resp_h": "13.107.18.13",
    "id.resp_p": 443,
    "seen.indicator": "www.slideshare.net",
    "seen.indicator_type": "Intel::DOMAIN",
    "seen.where": "X509::IN_CERT",
    "seen.node": "so16-enp0s8-1",
    "matched": [
      "Intel::DOMAIN"
    ],
    "sources": [
      "from http://hosts-file.net/fsa.txt via intel.criticalstack.com"
    ],
    "fuid": "FnRp0j1YMig5KhcMDg",
    "file_mime_type": "application/x-x509-user-cert",
    "file_desc": "13.107.18.13:443/tcp"
  }
  {
    "ts": "2019-03-12T18:32:19.821962Z",
    "uid": "CvusFJ2HdbTnCLxEUa",
    "id.orig_h": "192.168.4.6",
    "id.orig_p": 64826,
    "id.resp_h": "13.107.42.14",
    "id.resp_p": 443,
    "seen.indicator": "www.slideshare.net",
    "seen.indicator_type": "Intel::DOMAIN",
    "seen.where": "X509::IN_CERT",
    "seen.node": "so16-enp0s8-1",
    "matched": [
      "Intel::DOMAIN"
    ],
    "sources": [
      "from http://hosts-file.net/fsa.txt via intel.criticalstack.com"
    ],
    "fuid": "FUrrLa45T7a8hjdRy",
    "file_mime_type": "application/x-x509-user-cert",
    "file_desc": "13.107.42.14:443/tcp"
  }

These examples show there were matches in a domain observed in a X509
certificate. That domain was ``www.slideshare.net``. This is unusual as that
domain is used for legitimate purposes. This example demonstrates that analysts
must vet intelligence feeds for their local use and applicability.
