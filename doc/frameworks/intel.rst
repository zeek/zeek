
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

Data in the Intelligence Framework is the atomic piece of intelligence
such as an IP address or an e-mail address along with a suite of
metadata about it such as a freeform source field, a freeform
descriptive field and a URL which might lead to more information about
the specific item.  The metadata in the default scripts has been
deliberately kept minimal so that the community can find the
appropriate fields that need added by writing scripts which extend the
base record using the normal record extension mechanism.

Quick Start
-----------

Load the package of scripts that sends data into the Intelligence
Framework to be checked by loading this script in local.bro::

	@load policy/frameworks/intel/seen

Refer to the "Loading Intelligence" section below to see the format
for Intelligence Framework text files, then load those text files with
this line in local.bro::

	redef Intel::read_files += { "/somewhere/yourdata.txt" };

The data itself only needs to reside on the manager if running in a
cluster.

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

Here is an example of the intelligence data format.  Note that all
whitespace field separators are literal tabs and fields containing only a
hyphen are considered to be null values. ::

	#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
	1.2.3.4	Intel::ADDR	source1	Sending phishing email	http://source1.com/badhosts/1.2.3.4
	a.b.com	Intel::DOMAIN	source2	Name used for data exfiltration	-

For a list of all built-in `indicator_type` values, please refer to the
documentation of :bro:see:`Intel::Type`.

To load the data once files are created, use the following example
code to define files to load with your own file names of course::

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
needs to be informed that this data was discovered and it's presence
should be checked within the intelligence data set.  This is
accomplished through the :bro:see:`Intel::seen` function.

Typically users won't need to work with this function due to built in
hook scripts that Bro ships with that will "see" data and send it into
the intelligence framework.  A user may only need to load the entire
package of hook scripts as a module or pick and choose specific
scripts to load.  Keep in mind that as more data is sent into the
intelligence framework, the CPU load consumed by Bro will increase
depending on how many times the :bro:see:`Intel::seen` function is
being called which is heavily traffic dependent.

The full package of hook scripts that Bro ships with for sending this
"seen" data into the intelligence framework can be loading by adding
this line to local.bro::

	@load policy/frameworks/intel/seen

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

