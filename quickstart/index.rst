.. _ZeekControl documentation: https://github.com/zeek/zeekctl
.. _FAQ: https://www.zeek.org/documentation/faq.html

.. _quickstart:

=================
Quick Start Guide
=================

Zeek works on most modern, Unix-based systems and requires no custom
hardware.  It can be downloaded in either pre-built binary package or
source code forms.  See :ref:`installing-zeek` for instructions on how to
install Zeek. 

In the examples below, ``$PREFIX`` is used to reference the Zeek
installation root directory, which by default is ``/usr/local/zeek`` if
you install from source. 

Managing Zeek with ZeekControl
==============================

ZeekControl is an interactive shell for easily operating/managing Zeek
installations on a single system or even across multiple systems in a
traffic-monitoring cluster.  This section explains how to use ZeekControl
to manage a stand-alone Zeek installation.  For a complete reference on
ZeekControl, see the `ZeekControl documentation`_.
For instructions on how to configure a Zeek cluster,
see the :doc:`Cluster Configuration <../configuration/index>` documentation.

A Minimal Starting Configuration
--------------------------------

These are the basic configuration changes to make for a minimal ZeekControl
installation that will manage a single Zeek instance on the ``localhost``:

1) In ``$PREFIX/etc/node.cfg``, set the right interface to monitor.
2) In ``$PREFIX/etc/networks.cfg``, comment out the default settings and add
   the networks that Zeek will consider local to the monitored environment.
3) In ``$PREFIX/etc/zeekctl.cfg``, change the ``MailTo`` email address to a
   desired recipient and the ``LogRotationInterval`` to a desired log
   archival frequency.

Now start the ZeekControl shell like:

.. sourcecode:: console

   zeekctl

Since this is the first-time use of the shell, perform an initial installation
of the ZeekControl configuration:

.. sourcecode:: console

   [ZeekControl] > install

Then start up a Zeek instance:

.. sourcecode:: console

   [ZeekControl] > start

If there are errors while trying to start the Zeek instance, you can
can view the details with the ``diag`` command.  If started successfully,
the Zeek instance will begin analyzing traffic according to a default
policy and output the results in ``$PREFIX/logs``.

.. note:: The user starting ZeekControl needs permission to capture
   network traffic. If you are not root, you may need to grant further
   privileges to the account you're using; see the FAQ_.  Also, if it
   looks like Zeek is not seeing any traffic, check out the FAQ entry on
   checksum offloading.

You can leave it running for now, but to stop this Zeek instance you would do:

.. sourcecode:: console

   [ZeekControl] > stop

Browsing Log Files
------------------

By default, logs are written out in human-readable (ASCII) format and
data is organized into columns (tab-delimited). Logs that are part of
the current rotation interval are accumulated in
``$PREFIX/logs/current/`` (if Zeek is not running, the directory will
be empty). For example, the ``http.log`` contains the results of Zeek
HTTP protocol analysis. Here are the first few columns of
``http.log``::

    # ts          uid          orig_h        orig_p  resp_h         resp_p
    1311627961.8  HSH4uV8KVJg  192.168.1.100 52303   192.150.187.43 80

Logs that deal with analysis of a network protocol will often start like this:
a timestamp, a unique connection identifier (UID), and a connection 4-tuple
(originator host/port and responder host/port).  The UID can be used to
identify all logged activity (possibly across multiple log files) associated
with a given connection 4-tuple over its lifetime.

The remaining columns of protocol-specific logs then detail the
protocol-dependent activity that's occurring.  E.g. ``http.log``'s next few
columns (shortened for brevity) show a request to the root of Zeek website::

    # method   host         uri  referrer  user_agent
    GET        zeek.org  /    -         <...>Chrome/12.0.742.122<...>

Some logs are worth explicit mention:

    ``conn.log``
        Contains an entry for every connection seen on the wire, with
        basic properties such as time and duration, originator and
        responder IP addresses, services and ports, payload size, and
        much more. This log provides a comprehensive record of the
        network's activity.

    ``notice.log``
        Identifies specific activity that Zeek recognizes as
        potentially interesting, odd, or bad. In Zeek-speak, such
        activity is called a "notice".

By default, ``ZeekControl`` regularly takes all the logs from
``$PREFIX/logs/current`` and archives/compresses them to a directory
named by date, e.g. ``$PREFIX/logs/2011-10-06``.  The frequency at
which this is done can be configured via the ``LogRotationInterval``
option in ``$PREFIX/etc/zeekctl.cfg``.

Deployment Customization
------------------------

The goal of most Zeek *deployments* may be to send email alarms when a network
event requires human intervention/investigation, but sometimes that conflicts
with Zeek's goal as a *distribution* to remain policy and site neutral -- the
events on one network may be less noteworthy than the same events on another.
As a result, deploying Zeek can be an iterative process of
updating its policy to take different actions for events that are noticed, and
using its scripting language to programmatically extend traffic analysis
in a precise way.

One of the first steps to take in customizing Zeek might be to get familiar
with the notices it can generate by default and either tone down or escalate
the action that's taken when specific ones occur.

Let's say that we've been looking at the ``notice.log`` for a bit and see two
changes we want to make:

1) ``SSL::Invalid_Server_Cert`` (found in the ``note`` column) is one type of
   notice that means an SSL connection was established and the server's
   certificate couldn't be validated using Zeek's default trust roots, but
   we want to ignore it.
2) ``SSL::Certificate_Expired`` is a notice type that is triggered when
   an SSL connection was established using an expired certificate.  We
   want email when that happens, but only for certain servers on the
   local network (Zeek can also proactively monitor for certs that will
   soon expire, but this is just for demonstration purposes).

We've defined *what* we want to do, but need to know *where* to do it.
The answer is to use a script written in the Zeek programming language, so
let's do a quick intro to Zeek scripting.

Zeek Scripts
~~~~~~~~~~~~

Zeek ships with many pre-written scripts that are highly customizable
to support traffic analysis for your specific environment.  By
default, these will be installed into ``$PREFIX/share/zeek`` and can be
identified by the use of a ``.zeek`` file name extension.  These files
should **never** be edited directly as changes will be lost when
upgrading to newer versions of Zeek.  The exception to this rule is the
directory ``$PREFIX/share/zeek/site`` where local site-specific files
can be put without fear of being clobbered later. The other main
script directories under ``$PREFIX/share/zeek`` are ``base`` and
``policy``.  By default, Zeek automatically loads all scripts under
``base`` (unless the ``-b`` command line option is supplied), which
deal either with collecting basic/useful state about network
activities or providing frameworks/utilities that extend Zeek's
functionality without any performance cost.  Scripts under the
``policy`` directory may be more situational or costly, and so users
must explicitly choose if they want to load them.

The main entry point for the default analysis configuration of a standalone
Zeek instance managed by ZeekControl is the ``$PREFIX/share/zeek/site/local.zeek``
script.  We'll be adding to that in the following sections, but first
we have to figure out what to add.

Redefining Script Option Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Many simple customizations just require you to redefine a variable
from a standard Zeek script with your own value, using Zeek's ``redef``
operator.

The typical way a standard Zeek script advertises tweak-able options to users
is by defining variables with the ``&redef`` attribute and ``const`` qualifier. 
A redefineable constant might seem strange, but what that really means is that
the variable's value may not change at run-time, but whose initial value can be
modified via the ``redef`` operator at parse-time.

Let's continue on our path to modify the behavior for the two SSL
notices.  Looking at :doc:`/scripts/base/frameworks/notice/main.zeek`,
we see that it advertises:

.. sourcecode:: zeek

    module Notice;

    export {
        ...
        ## Ignored notice types.
        const ignored_types: set[Notice::Type] = {} &redef;
    }

That's exactly what we want to do for the first notice.  Add to ``local.zeek``:

.. sourcecode:: zeek

    redef Notice::ignored_types += { SSL::Invalid_Server_Cert };

.. note:: The ``Notice`` namespace scoping is necessary here because the
   variable was declared and exported inside the ``Notice`` module, but is
   being referenced from outside of it.  Variables declared and exported
   inside a module do not have to be scoped if referring to them while still
   inside the module.

Then go into the ZeekControl shell to check whether the configuration change
is valid before installing it and then restarting the Zeek instance.  The
"deploy" command does all of this automatically:

.. sourcecode:: console

   [ZeekControl] > deploy
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

Now that the SSL notice is ignored, let's look at how to send an email
on the other notice.  The notice framework has a similar option called
``emailed_types``, but using that would generate email for all SSL
servers with expired certificates and we only want email for connections
to certain ones.  There is a ``policy`` hook that is actually what is
used to implement the simple functionality of ``ignored_types`` and
``emailed_types``, but it's extensible such that the condition and
action taken on notices can be user-defined.

In ``local.zeek``, let's define a new ``policy`` hook handler body:

.. literalinclude:: conditional-notice.zeek
   :caption:
   :language: zeek
   :linenos:

.. sourcecode:: console

   $ zeek -r tls/tls-expired-cert.trace conditional-notice.zeek
   $ cat notice.log
   #separator \x09
   #set_separator    ,
   #empty_field      (empty)
   #unset_field      -
   #path     notice
   #open     2018-12-14-17-36-05
   #fields   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type  file_desc       proto   note    msg     sub     src     dst     p       n       peer_descr      actions suppress_for    dropped remote_location.country_code    remote_location.region  remote_location.city    remote_location.latitude        remote_location.longitude
   #types    time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  set[enum]       interval        bool    string  string  string  double  double
   1394745603.293028 CHhAvVGS1DHFjwGM9       192.168.4.149   60539   87.98.220.10    443     F1fX1R2cDOzbvg17ye      -       -       tcp     SSL::Certificate_Expired        Certificate CN=www.spidh.org,OU=COMODO SSL,OU=Domain Control Validated expired at 2014-03-04-23:59:59.000000000 -       192.168.4.149   87.98.220.10    443     -       -       Notice::ACTION_EMAIL,Notice::ACTION_LOG 86400.000000    F       -       -       -       -       -
   #close    2018-12-14-17-36-05

You'll just have to trust the syntax for now, but what we've done is
first declare our own variable to hold a set of watched addresses,
``watched_servers``; then added a hook handler body to the policy that
will generate an email whenever the notice type is an SSL expired
certificate and the responding host stored inside the ``Info`` record's
connection field is in the set of watched servers.

.. note:: Record field member access is done with the '$' character
   instead of a '.' as might be expected from other languages, in
   order to avoid ambiguity with the built-in address type's use of '.'
   in IPv4 dotted decimal representations.

Remember, to finalize that configuration change perform the ``deploy``
command inside the ZeekControl shell.

Next Steps
----------

By this point, we've learned how to set up the most basic Zeek instance and
tweak the most basic options.  Here's some suggestions on what to explore next:

* We only looked at how to change options declared in the notice framework,
  there's many more options to look at in other script packages.
* Continue reading with :ref:`Using Zeek <using-zeek>` chapter which goes
  into more depth on working with Zeek; then look at
  :ref:`writing-scripts` for learning how to start writing your own
  scripts.
* Look at the scripts in ``$PREFIX/share/zeek/policy`` for further ones
  you may want to load; you can browse their documentation at the
  :ref:`overview of script packages <script-packages>`.
* Reading the code of scripts that ship with Zeek is also a great way to gain
  further understanding of the language and how scripts tend to be
  structured.
* Review the FAQ_.
* Continue reading below for another mini-tutorial on using Zeek as a standalone
  command-line utility.

Zeek as a Command-Line Utility
==============================

If you prefer not to use ZeekControl (e.g. don't need its automation
and management features), here's how to directly control Zeek for your
analysis activities from the command line for both live traffic and
offline working from traces.

Monitoring Live Traffic
-----------------------

Analyzing live traffic from an interface is simple:

.. sourcecode:: console

   zeek -i en0 <list of scripts to load>

``en0`` can be replaced by the interface of your choice. A selection
of common base scripts will be loaded by default.

Zeek will output log files into the working directory.

.. note:: The FAQ_ entries about
   capturing as an unprivileged user and checksum offloading are
   particularly relevant at this point.


Reading Packet Capture (pcap) Files
-----------------------------------

Capturing packets from an interface and writing them to a file can be done
like this:

.. sourcecode:: console

   sudo tcpdump -i en0 -s 0 -w mypackets.trace

Where ``en0`` can be replaced by the correct interface for your system as
shown by e.g. ``ifconfig``. (The ``-s 0`` argument tells it to capture
whole packets; in cases where it's not supported use ``-s 65535`` instead).

After a while of capturing traffic, kill the ``tcpdump`` (with ctrl-c),
and tell Zeek to perform all the default analysis on the capture which primarily includes :

.. sourcecode:: console

   zeek -r mypackets.trace

Zeek will output log files into the working directory.

If you are interested in more detection, you can again load the ``local``
script that we include as a suggested configuration:

.. sourcecode:: console

  zeek -r mypackets.trace local

Telling Zeek Which Scripts to Load
----------------------------------

A command-line invocation of Zeek typically looks like:

.. sourcecode:: console

   zeek <options> <scripts...>

Where the last arguments are the specific policy scripts that this Zeek
instance will load.  These arguments don't have to include the ``.zeek``
file extension, and if the corresponding script resides in the default
search path, then it requires no path qualification.  The following 
directories are included in the default search path for Zeek scripts::
   
   ./
   <prefix>/share/zeek/
   <prefix>/share/zeek/policy/
   <prefix>/share/zeek/site/

These prefix paths can be used to load scripts like this:

.. sourcecode:: console

   zeek -r mypackets.trace frameworks/files/extract-all

This will load the 
``<prefix>/share/zeek/policy/frameworks/files/extract-all.zeek`` script which will
cause Zeek to extract all of the files it discovers in the PCAP.

.. note:: If one wants Zeek to be able to load scripts that live outside the
   default directories in Zeek's installation root, the full path to the file(s)
   must be provided.  See the default search path by running ``zeek --help``.

You might notice that a script you load from the command line uses the
``@load`` directive in the Zeek language to declare dependence on other scripts.
This directive is similar to the ``#include`` of C/C++, except the semantics
are, "load this script if it hasn't already been loaded."

Further, a directory of scripts can be specified as
an argument to be loaded as a "package" if it contains a ``__load__.zeek``
script that defines the scripts that are part of the package.

Local site customization
------------------------

There is one script that is installed which is considered "local site 
customization" and is not overwritten when upgrades take place. To use 
the site-specific ``local.zeek`` script, just add it to the command-line (can
also be loaded through scripts with @load):

.. sourcecode:: console

   zeek -i en0 local

This causes Zeek to load a script that prints a warning about lacking the
``Site::local_nets`` variable being configured. You can supply this
information at the command line like this (supply your "local" subnets
in place of the example subnets):

.. sourcecode:: console

   zeek -r mypackets.trace local "Site::local_nets += { 1.2.3.0/24, 5.6.7.0/24 }"

When running with Zeekctl, this value is set by configuring the ``networks.cfg``
file.

Running Zeek Without Installing
-------------------------------

For developers that wish to run Zeek directly from the ``build/``
directory (i.e., without performing ``make install``), they will have
to first adjust ``ZEEKPATH`` to look for scripts and
additional files inside the build directory.  Sourcing either
``build/zeek-path-dev.sh`` or ``build/zeek-path-dev.csh`` as appropriate
for the current shell accomplishes this and also augments your
``PATH`` so you can use the Zeek binary directly::

    ./configure
    make
    source build/zeek-path-dev.sh
    zeek <options>

