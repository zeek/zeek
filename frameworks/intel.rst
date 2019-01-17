
======================
Intelligence Framework
======================

Intro
-----

Intelligence data is critical to the process of monitoring for
security purposes.  There is always data which will be discovered
through the incident response process and data which is shared through
private communities.  The goals of Bro's Intelligence Framework are to
consume that data, make it available for matching, and provide
infrastructure around improving performance, memory utilization, and
generally making all of this easier.

Data in the Intelligence Framework is an atomic piece of intelligence
such as an IP address or an e-mail address along with a suite of
metadata about it such as a freeform source field, a freeform
descriptive field and a URL which might lead to more information about
the specific item.  The metadata in the default scripts has been
deliberately kept minimal so that the community can find the
appropriate fields that need to be added by writing scripts which extend the
base record using the normal record extension mechanism.

Quick Start
-----------

Refer to the "Loading Intelligence" section below to see the format
for Intelligence Framework text files, then load those text files with
this line in local.bro::

	redef Intel::read_files += { "/somewhere/yourdata.txt" };

The text files need to reside only on the manager if running in a
cluster.

Add the following line to local.bro in order to load the scripts
that send "seen" data into the Intelligence Framework to be checked against
the loaded intelligence data::

	@load policy/frameworks/intel/seen

Intelligence data matches will be logged to the intel.log file.

Architecture
------------

The Intelligence Framework can be thought of as containing three
separate portions.  The first part is how intelligence is loaded,
followed by the mechanism for indicating to the intelligence framework
that a piece of data which needs to be checked has been seen, and
thirdly the part where a positive match has been discovered.

Loading Intelligence
********************

Intelligence data can only be loaded through plain text files using
the Input Framework conventions.  Additionally, on clusters the
manager is the only node that needs the intelligence data.  The
intelligence framework has distribution mechanisms which will push
data out to all of the nodes that need it.

Here is an example of the intelligence data format (note that there will be
additional fields if you are using CIF intelligence data or if you are
using the policy/frameworks/intel/do_notice script).  Note that all fields
must be separated by a single tab character and fields containing only a
hyphen are considered to be null values. ::

	#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
	1.2.3.4	Intel::ADDR	source1	Sending phishing email	http://source1.com/badhosts/1.2.3.4
	a.b.com	Intel::DOMAIN	source2	Name used for data exfiltration	-

For a list of all built-in `indicator_type` values, please refer to the
documentation of :bro:see:`Intel::Type`.

Note that if you are using data from the Collective Intelligence Framework,
then you will need to add the following line to your local.bro in order
to support additional metadata fields used by CIF::

	@load policy/integration/collective-intel

There is a simple mechanism to raise a Bro notice (of type Intel::Notice)
for user-specified intelligence matches.  To use this feature, add the
following line to local.bro in order to support additional metadata fields
(documented in the :bro:see:`Intel::MetaData` record)::

	@load policy/frameworks/intel/do_notice

To load the data once the files are created, use the following example
to specify which files to load (with your own file names of course)::

	redef Intel::read_files += {
		"/somewhere/feed1.txt",
		"/somewhere/feed2.txt",
	};

Remember, the files only need to be present on the file system of the
manager node on cluster deployments.

Seen Data
*********

When some bit of data is extracted (such as an email address in the
"From" header in a message over SMTP), the Intelligence Framework
needs to be informed that this data was discovered so that its presence
will be checked within the loaded intelligence data.  This is
accomplished through the :bro:see:`Intel::seen` function, however
typically users won't need to work with this function due to the
scripts included with Bro that will call this function.

To load all of the scripts included with Bro for sending "seen" data to
the intelligence framework, just add this line to local.bro::

	@load policy/frameworks/intel/seen

Alternatively, specific scripts in that directory can be loaded.
Keep in mind that as more data is sent into the
intelligence framework, the CPU load consumed by Bro will increase
depending on how many times the :bro:see:`Intel::seen` function is
being called which is heavily traffic dependent.


Intelligence Matches
********************

Against all hopes, most networks will eventually have a hit on
intelligence data which could indicate a possible compromise or other
unwanted activity.  The Intelligence Framework provides an event that
is generated whenever a match is discovered named :bro:see:`Intel::match`.

Due to design restrictions placed upon
the intelligence framework, there is no assurance as to where this
event will be generated.  It could be generated on the worker where
the data was seen or on the manager.  When the ``Intel::match`` event is
handled, only the data given as event arguments to the event can be
assured since the host where the data was seen may not be where
``Intel::match`` is handled.

Intelligence matches are logged to the intel.log file.  For a description of
each field in that file, see the documentation for the :bro:see:`Intel::Info`
record.

