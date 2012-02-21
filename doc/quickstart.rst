.. _CMake: http://www.cmake.org
.. _SWIG: http://www.swig.org
.. _MacPorts: http://www.macports.org
.. _Fink: http://www.finkproject.org
.. _Homebrew: http://mxcl.github.com/homebrew
.. _bro downloads page: http://bro-ids.org/download/index.html

=================
Quick Start Guide
=================

.. rst-class:: opening

   The short story for getting Bro up and running in a simple configuration
   for analysis of either live traffic from a network interface or a packet
   capture trace file.

.. contents::

Installation
============

Bro works on most modern, Unix-based systems and requires no custom
hardware.  It can be downloaded in either pre-built binary package or
source code forms.

Pre-Built Binary Release Packages
---------------------------------

See the `bro downloads page`_ for currently supported/targeted platforms.

* RPM

  .. console::

      sudo yum localinstall Bro-*.rpm

* DEB

  .. console::

      sudo gdebi Bro-*.deb

* MacOS Disk Image with Installer

  Just open the ``Bro-*.dmg`` and then run the ``.pkg`` installer.
  Everything installed by the package will go into ``/opt/bro``.

The primary install prefix for binary packages is ``/opt/bro``.
Non-MacOS packages that include BroControl also put variable/runtime
data (e.g. Bro logs) in ``/var/opt/bro``.

Building From Source
--------------------

Required Dependencies
~~~~~~~~~~~~~~~~~~~~~

The following dependencies are required to build Bro:

* RPM/RedHat-based Linux:

  .. console::

     sudo yum install cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python-devel swig zlib-devel file-devel

* DEB/Debian-based Linux:

  .. console::

     sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev libmagic-dev

* FreeBSD

  Most required dependencies should come with a minimal FreeBSD install
  except for the following.

  .. console::

      sudo pkg_add -r bash cmake swig bison python

  Note that ``bash`` needs to be in ``PATH``, which by default it is
  not. The FreeBSD package installs the binary into
  ``/usr/local/bin``.

* Mac OS X

  Snow Leopard (10.6) comes with all required dependencies except for CMake_.

  Lion (10.7) comes with all required dependencies except for CMake_ and SWIG_.

  Distributions of these dependencies can be obtained from the project websites
  linked above, but they're also likely available from your preferred Mac OS X
  package management system (e.g. MacPorts_, Fink_, or Homebrew_).

  Note that the MacPorts ``swig`` package may not include any specific
  language support so you may need to also install ``swig-ruby`` and
  ``swig-python``.

Optional Dependencies
~~~~~~~~~~~~~~~~~~~~~

Bro can use libGeoIP for geo-locating IP addresses, and sendmail for
sending emails.

* RedHat Enterprise Linux:

  .. console::

      sudo yum install geoip-devel sendmail

* CentOS Linux:

  .. console::
  
      sudo yum install GeoIP-devel sendmail

* DEB/Debian-based Linux:

  .. console::

      sudo apt-get install libgeoip-dev sendmail

* Ports-based FreeBSD

  .. console::

      sudo pkg_add -r GeoIP

  sendmail is typically already available.

* Mac OS X

  Vanilla OS X installations don't ship with libmagic or libGeoIP, but
  if installed from your preferred package management system (e.g. MacPorts,
  Fink, or Homebrew), they should be automatically detected and Bro will compile
  against them.

Additional steps may be needed to :doc:`get the right GeoIP database <geoip>`

Compiling Bro Source Code
~~~~~~~~~~~~~~~~~~~~~~~~~

Bro releases are bundled into source packages for convenience and
available from the `bro downloads page`_.

The latest Bro development versions are obtainable through git
repositories hosted at `git.bro-ids.org <http://git.bro-ids.org>`_.  See
our `git development documentation
<http://bro-ids.org/development/process.html>`_ for comprehensive
information on Bro's use of git revision control, but the short story
for downloading the full source code experience for Bro via git is:

.. console::

    git clone --recursive git://git.bro-ids.org/bro

.. note:: If you choose to clone the ``bro`` repository non-recursively for
   a "minimal Bro experience", be aware that compiling it depends on
   BinPAC, which has its own ``binpac`` repository.  Either install it
   first or initialize/update the cloned ``bro`` repository's
   ``aux/binpac`` submodule.

See the ``INSTALL`` file included with the source code for more information
on compiling, but this is the typical way to build and install from source
(of course, changing the value of the ``--prefix`` option to point to the
desired root install path):

.. console::

    ./configure --prefix=/desired/install/path
    make
    make install

The default installation prefix is ``/usr/local/bro``, which would typically
require root privileges when doing the ``make install``.

Configure the Run-Time Environment
----------------------------------

Just remember that you may need to adjust your ``PATH`` environment variable
according to the platform/shell/package you're using.  For example:

Bourne-Shell Syntax:

.. console::

   export PATH=/usr/local/bro/bin:$PATH

C-Shell Syntax:

.. console::

   setenv PATH /usr/local/bro/bin:$PATH

Or substitute ``/opt/bro/bin`` instead if you installed from a binary package.

Using BroControl
================

BroControl is an interactive shell for easily operating/managing Bro
installations on a single system or even across multiple systems in a
traffic-monitoring cluster.

.. note:: Below, ``$PREFIX`` is used to reference the Bro installation
   root directory.

A Minimal Starting Configuration
--------------------------------

These are the basic configuration changes to make for a minimal BroControl installation
that will manage a single Bro instance on the ``localhost``:

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
   privileges to the account you're using; see the :doc:`FAQ <faq>`.
   Also, if it looks like Bro is not seeing any traffic, check out
   the FAQ entry on checksum offloading.

You can leave it running for now, but to stop this Bro instance you would do:

.. console::

   [BroControl] > stop

We also recommend to insert the following entry into `crontab`::

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
    GET        bro-ids.org  /    -         <...>Chrome/12.0.742.122<...>

Some logs are worth explicit mention:

    ``weird.log``
        Contains unusual/exceptional activity that can indicate
        malformed connections, traffic that doesn't conform to a particular
        protocol, malfunctioning/misconfigured hardware, or even an attacker
        attempting to avoid/confuse a sensor.  Without context, it's hard to
        judge whether this category of activity is interesting and so that is
        left up to the user to configure.

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

So we've defined *what* we want to do, but need to know *where* to do it.
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
script.  So we'll be adding to that in the following sections, but first
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

So let's continue on our path to modify the behavior for the two SSL
and SSH notices.  Looking at :doc:`scripts/base/frameworks/notice/main`,
we see that it advertises:

.. code:: bro

    module Notice;

    export {
        ...
        ## Ignored notice types.
        const ignored_types: set[Notice::Type] = {} &redef;
    }

That's exactly what we want to do for the SSL notice.  So add to ``local.bro``:

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

    redef Notice::policy += {
        [$action = Notice::ACTION_EMAIL,
         $pred(n: Notice::Info) =
            {
            return n$note == SSH::Login && n$id$resp_h in watched_servers;
            }
        ]
    };

You'll just have to trust the syntax for now, but what we've done is
first declare our own variable to hold a set of watched addresses,
``watched_servers``; then added a record to the policy that will generate
an email on the condition that the predicate function evaluates to true, which
is whenever the notice type is an SSH login and the responding host stored
inside the ``Info`` record's connection field is in the set of watched servers.

.. note:: record field member access is done with the '$' character
   instead of a '.' as might be expected from other languages, in
   order to avoid ambiguity with the builtin address type's use of '.'
   in IPv4 dotted decimal representations.

Remember, to finalize that configuration change perform the ``check``,
``install``, ``restart`` commands in that order inside the BroControl shell.

Next Steps
----------

By this point, we've learned how to set up the most basic Bro instance and
tweak the most basic options.  Here's some suggestions on what to explore next:

* We only looked at how to change options declared in the notice framework,
  there's many more options to look at in other script packages.
* Look at the scripts in ``$PREFIX/share/bro/policy`` for further ones
  you may want to load.
* Reading the code of scripts that ship with Bro is also a great way to gain
  understanding of the language and how you can start writing your own custom
  analysis.
* Review the :doc:`FAQ <faq>`.
* Continue reading below for another mini-tutorial on using Bro as a standalone
  command-line utility.

Bro, the Command-Line Utility
=============================

If you prefer not to use BroControl (e.g. don't need its automation and
management features), here's how to directly control Bro for your analysis
activities.

Monitoring Live Traffic
-----------------------

Analyzing live traffic from an interface is simple:

.. console::

   bro -i en0 <list of scripts to load>

``en0`` can be replaced by the interface of your choice and for the list of
scripts, you can just use "all" for now to perform all the default analysis
that's available.

Bro will output log files into the working directory.

.. note:: The :doc:`FAQ <faq>` entries about
   capturing as an unprivileged user and checksum offloading are particularly
   relevant at this point.

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
are "load this script if it hasn't already been loaded".

.. note:: If one wants Bro to be able to load scripts that live outside the
   default directories in Bro's installation root, the ``BROPATH`` environment
   variable will need to be extended to include all the directories that need
   to be searched for scripts.  See the default search path by doing
   ``bro --help``.

