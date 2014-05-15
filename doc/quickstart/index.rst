
.. _FAQ: http://www.bro.org/documentation/faq.html

.. _quickstart:

=================
Quick Start Guide
=================

.. contents::

Bro works on most modern, Unix-based systems and requires no custom
hardware.  It can be downloaded in either pre-built binary package or
source code forms.  See :ref:`installing-bro` for instructions on how to
install Bro. 

In the examples below, ``$PREFIX`` is used to reference the Bro
installation root directory, which by default is ``/usr/local/bro`` if
you install from source. 

Managing Bro with BroControl
============================

BroControl is an interactive shell for easily operating/managing Bro
installations on a single system or even across multiple systems in a
traffic-monitoring cluster.  This section explains how to use BroControl
to manage a stand-alone Bro installation.  For instructions on how to
configure a Bro cluster, see the documentation for :doc:`BroControl
<../components/broctl/README>`.

A Minimal Starting Configuration
--------------------------------

These are the basic configuration changes to make for a minimal BroControl
installation that will manage a single Bro instance on the ``localhost``:

1) In ``$PREFIX/etc/node.cfg``, set the right interface to monitor.
2) In ``$PREFIX/etc/networks.cfg``, comment out the default settings and add
   the networks that Bro will consider local to the monitored environment.
3) In ``$PREFIX/etc/broctl.cfg``, change the ``MailTo`` email address to a
   desired recipient and the ``LogRotationInterval`` to a desired log
   archival frequency.

Now start the BroControl shell like:

.. console::

   broctl

Since this is the first-time use of the shell, perform an initial installation
of the BroControl configuration:

.. console::

   [BroControl] > install

Then start up a Bro instance:

.. console::

   [BroControl] > start

If there are errors while trying to start the Bro instance, you can
can view the details with the ``diag`` command.  If started successfully,
the Bro instance will begin analyzing traffic according to a default
policy and output the results in ``$PREFIX/logs``.

.. note:: The user starting BroControl needs permission to capture
   network traffic. If you are not root, you may need to grant further
   privileges to the account you're using; see the FAQ_.  Also, if it
   looks like Bro is not seeing any traffic, check out the FAQ entry on
   checksum offloading.

You can leave it running for now, but to stop this Bro instance you would do:

.. console::

   [BroControl] > stop

We also recommend to insert the following entry into the crontab of the user
running BroControl::

      0-59/5 * * * * $PREFIX/bin/broctl cron

This will perform a number of regular housekeeping tasks, including
verifying that the process is still running (and restarting if not in
case of any abnormal termination).

Browsing Log Files
------------------

By default, logs are written out in human-readable (ASCII) format and
data is organized into columns (tab-delimited). Logs that are part of
the current rotation interval are accumulated in
``$PREFIX/logs/current/`` (if Bro is not running, the directory will
be empty). For example, the ``http.log`` contains the results of Bro
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
columns (shortened for brevity) show a request to the root of Bro website::

    # method   host         uri  referrer  user_agent
    GET        bro.org  /    -         <...>Chrome/12.0.742.122<...>

Some logs are worth explicit mention:

    ``conn.log``
        Contains an entry for every connection seen on the wire, with
        basic properties such as time and duration, originator and
        responder IP addresses, services and ports, payload size, and
        much more. This log provides a comprehensive record of the
        network's activity.

    ``notice.log``
        Identifies specific activity that Bro recognizes as
        potentially interesting, odd, or bad. In Bro-speak, such
        activity is called a "notice".

By default, ``BroControl`` regularly takes all the logs from
``$PREFIX/logs/current`` and archives/compresses them to a directory
named by date, e.g. ``$PREFIX/logs/2011-10-06``.  The frequency at
which this is done can be configured via the ``LogRotationInterval``
option in ``$PREFIX/etc/broctl.cfg``.

Deployment Customization
------------------------

The goal of most Bro *deployments* may be to send email alarms when a network
event requires human intervention/investigation, but sometimes that conflicts
with Bro's goal as a *distribution* to remain policy and site neutral -- the
events on one network may be less noteworthy than the same events on another.
As a result, deploying Bro can be an iterative process of
updating its policy to take different actions for events that are noticed, and
using its scripting language to programmatically extend traffic analysis
in a precise way.

One of the first steps to take in customizing Bro might be to get familiar
with the notices it can generate by default and either tone down or escalate
the action that's taken when specific ones occur.

Let's say that we've been looking at the ``notice.log`` for a bit and see two
changes we want to make:

1) ``SSL::Invalid_Server_Cert`` (found in the ``note`` column) is one type of
   notice that means an SSL connection was established and the server's
   certificate couldn't be validated using Bro's default trust roots, but
   we want to ignore it.
2) ``SSH::Login`` is a notice type that is triggered when an SSH connection
   attempt looks like it may have been successful, and we want email when
   that happens, but only for certain servers.

We've defined *what* we want to do, but need to know *where* to do it.
The answer is to use a script written in the Bro programming language, so
let's do a quick intro to Bro scripting.

Bro Scripts
~~~~~~~~~~~

Bro ships with many pre-written scripts that are highly customizable
to support traffic analysis for your specific environment.  By
default, these will be installed into ``$PREFIX/share/bro`` and can be
identified by the use of a ``.bro`` file name extension.  These files
should **never** be edited directly as changes will be lost when
upgrading to newer versions of Bro.  The exception to this rule is the
directory ``$PREFIX/share/bro/site`` where local site-specific files
can be put without fear of being clobbered later. The other main
script directories under ``$PREFIX/share/bro`` are ``base`` and
``policy``.  By default, Bro automatically loads all scripts under
``base`` (unless the ``-b`` command line option is supplied), which
deal either with collecting basic/useful state about network
activities or providing frameworks/utilities that extend Bro's
functionality without any performance cost.  Scripts under the
``policy`` directory may be more situational or costly, and so users
must explicitly choose if they want to load them.

The main entry point for the default analysis configuration of a standalone
Bro instance managed by BroControl is the ``$PREFIX/share/bro/site/local.bro``
script.  We'll be adding to that in the following sections, but first
we have to figure out what to add.

Redefining Script Option Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Many simple customizations just require you to redefine a variable
from a standard Bro script with your own value, using Bro's ``redef``
operator.

The typical way a standard Bro script advertises tweak-able options to users
is by defining variables with the ``&redef`` attribute and ``const`` qualifier. 
A redefineable constant might seem strange, but what that really means is that
the variable's value may not change at run-time, but whose initial value can be
modified via the ``redef`` operator at parse-time.

Let's continue on our path to modify the behavior for the two SSL
and SSH notices.  Looking at :doc:`/scripts/base/frameworks/notice/main.bro`,
we see that it advertises:

.. code:: bro

    module Notice;

    export {
        ...
        ## Ignored notice types.
        const ignored_types: set[Notice::Type] = {} &redef;
    }

That's exactly what we want to do for the SSL notice.  Add to ``local.bro``:

.. code:: bro

    redef Notice::ignored_types += { SSL::Invalid_Server_Cert };

.. note:: The ``Notice`` namespace scoping is necessary here because the
   variable was declared and exported inside the ``Notice`` module, but is
   being referenced from outside of it.  Variables declared and exported
   inside a module do not have to be scoped if referring to them while still
   inside the module.

Then go into the BroControl shell to check whether the configuration change
is valid before installing it and then restarting the Bro instance:

.. console::

   [BroControl] > check
   bro is ok.
   [BroControl] > install
   removing old policies in /usr/local/bro/spool/policy/site ... done.
   removing old policies in /usr/local/bro/spool/policy/auto ... done.
   creating policy directories ... done.
   installing site policies ... done.
   generating standalone-layout.bro ... done.
   generating local-networks.bro ... done.
   generating broctl-config.bro ... done.
   updating nodes ... done.
   [BroControl] > restart
   stopping bro ...
   starting bro ...

Now that the SSL notice is ignored, let's look at how to send an email on
the SSH notice.  The notice framework has a similar option called
``emailed_types``, but that can't differentiate between SSH servers and we
only want email for logins to certain ones.  Then we come to the ``PolicyItem``
record and ``policy`` set and realize that those are actually what get used
to implement the simple functionality of ``ignored_types`` and
``emailed_types``, but it's extensible such that the condition and action taken
on notices can be user-defined.

In ``local.bro``, let's add a new ``PolicyItem`` record to the ``policy`` set
that only takes the email action for SSH logins to a defined set of servers:

.. code:: bro

    const watched_servers: set[addr] = {
        192.168.1.100,
        192.168.1.101,
        192.168.1.102,
    } &redef;

   hook Notice::policy(n: Notice::Info)
       {
       if ( n$note == SSH::SUCCESSFUL_LOGIN && n$id$resp_h in watched_servers )
            add n$actions[Notice::ACTION_EMAIL];
       }

You'll just have to trust the syntax for now, but what we've done is
first declare our own variable to hold a set of watched addresses,
``watched_servers``; then added a record to the policy that will generate
an email on the condition that the predicate function evaluates to true, which
is whenever the notice type is an SSH login and the responding host stored
inside the ``Info`` record's connection field is in the set of watched servers.

.. note:: Record field member access is done with the '$' character
   instead of a '.' as might be expected from other languages, in
   order to avoid ambiguity with the built-in address type's use of '.'
   in IPv4 dotted decimal representations.

Remember, to finalize that configuration change perform the ``check``,
``install``, ``restart`` commands in that order inside the BroControl shell.

Next Steps
----------

By this point, we've learned how to set up the most basic Bro instance and
tweak the most basic options.  Here's some suggestions on what to explore next:

* We only looked at how to change options declared in the notice framework,
  there's many more options to look at in other script packages.
* Continue reading with :ref:`Using Bro <using-bro>` chapter which goes
  into more depth on working with Bro; then look at
  :ref:`writing-scripts` for learning how to start writing your own
  scripts.
* Look at the scripts in ``$PREFIX/share/bro/policy`` for further ones
  you may want to load; you can browse their documentation at the
  :ref:`overview of script packages <script-packages>`.
* Reading the code of scripts that ship with Bro is also a great way to gain
  further understanding of the language and how scripts tend to be
  structured.
* Review the FAQ_.
* Continue reading below for another mini-tutorial on using Bro as a standalone
  command-line utility.

Bro as a Command-Line Utility
=============================

If you prefer not to use BroControl (e.g. don't need its automation
and management features), here's how to directly control Bro for your
analysis activities from the command line for both live traffic and
offline working from traces.

Monitoring Live Traffic
-----------------------

Analyzing live traffic from an interface is simple:

.. console::

   bro -i en0 <list of scripts to load>

``en0`` can be replaced by the interface of your choice and for the list of
scripts, you can just use "all" for now to perform all the default analysis
that's available.

Bro will output log files into the working directory.

.. note:: The FAQ_ entries about
   capturing as an unprivileged user and checksum offloading are
   particularly relevant at this point.

To use the site-specific ``local.bro`` script, just add it to the
command-line:

.. console::

   bro -i en0 local

This will cause Bro to print a warning about lacking the
``Site::local_nets`` variable being configured. You can supply this
information at the command line like this (supply your "local" subnets
in place of the example subnets):

.. console::

   bro -r mypackets.trace local "Site::local_nets += { 1.2.3.0/24, 5.6.7.0/24 }"


Reading Packet Capture (pcap) Files
-----------------------------------

Capturing packets from an interface and writing them to a file can be done
like this:

.. console::

   sudo tcpdump -i en0 -s 0 -w mypackets.trace

Where ``en0`` can be replaced by the correct interface for your system as
shown by e.g. ``ifconfig``. (The ``-s 0`` argument tells it to capture
whole packets; in cases where it's not supported use ``-s 65535`` instead).

After a while of capturing traffic, kill the ``tcpdump`` (with ctrl-c),
and tell Bro to perform all the default analysis on the capture which primarily includes :

.. console::

   bro -r mypackets.trace

Bro will output log files into the working directory.

If you are interested in more detection, you can again load the ``local``
script that we include as a suggested configuration:

.. console::

  bro -r mypackets.trace local


Telling Bro Which Scripts to Load
---------------------------------

A command-line invocation of Bro typically looks like:

.. console::

   bro <options> <policies...>

Where the last arguments are the specific policy scripts that this Bro
instance will load.  These arguments don't have to include the ``.bro``
file extension, and if the corresponding script resides under the default
installation path, ``$PREFIX/share/bro``, then it requires no path
qualification.  Further, a directory of scripts can be specified as
an argument to be loaded as a "package" if it contains a ``__load__.bro``
script that defines the scripts that are part of the package.

This example does all of the base analysis (primarily protocol
logging) and adds SSL certificate validation.

.. console::

   bro -r mypackets.trace protocols/ssl/validate-certs

You might notice that a script you load from the command line uses the
``@load`` directive in the Bro language to declare dependence on other scripts.
This directive is similar to the ``#include`` of C/C++, except the semantics
are, "load this script if it hasn't already been loaded."

.. note:: If one wants Bro to be able to load scripts that live outside the
   default directories in Bro's installation root, the ``BROPATH`` environment
   variable will need to be extended to include all the directories that need
   to be searched for scripts.  See the default search path by doing
   ``bro --help``.

Running Bro Without Installing
------------------------------

For developers that wish to run Bro directly from the ``build/``
directory (i.e., without performing ``make install``), they will have
to first adjust ``BROPATH`` and ``BROMAGIC`` to look for scripts and
additional files inside the build directory.  Sourcing either
``build/bro-path-dev.sh`` or ``build/bro-path-dev.csh`` as appropriate
for the current shell accomplishes this and also augments your
``PATH`` so you can use the Bro binary directly::

    ./configure
    make
    source build/bro-path-dev.sh
    bro <options>

