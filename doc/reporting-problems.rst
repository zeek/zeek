
Reporting Problems
==================

.. rst-class:: opening

    Here we summarize some steps to follow when you see Bro doing
    something it shouldn't. To provide help, it is often crucial for
    us to have a way of reliably reproducing the effect you're seeing.
    Unfortunately, reproducing problems can be rather tricky with Bro
    because more often than not, they occur only in either very rare
    situations or only after Bro has been running for some time. In
    particular, getting a small trace showing a specific effect can be
    a real problem. In the following, we'll summarize some strategies
    to this end.

Reporting Problems
------------------

Generally, when you encounter a problem with Bro, the best thing to do
is opening a new ticket in `Bro's issue tracker
<http://tracker.bro-ids.org/>`__ and include information on how to
reproduce the issue. Ideally, your ticket should come with the
following:

* The Bro version you're using (if working directly from the git
  repository, the branch and revision number.)

* The output you're seeing along with a description of what you'd expect
  Bro to do instead.

* A *small* trace in `libpcap format <http://www.tcpdump.org>`__
  demonstrating the effect (assuming the problem doesn't happen right
  at startup already).

* The exact command-line you're using to run Bro with that trace. If
  you can, please try to run the Bro binary directly from the command
  line rather than using BroControl.

* Any non-standard scripts you're using (but please only those really
  necessary; just a small code snippet triggering the problem would
  be perfect).

* If you encounter a crash, information from the core dump, such as
  the stack backtrace, can be very helpful. See below for more on
  this.


How Do I Get a Trace File?
--------------------------

As Bro is usually running live, coming up with a small trace file that
reproduces a problem can turn out to be quite a challenge. Often it
works best to start with a large trace that triggers the problem,
and then successively thin it out as much as possible.

To get to the initial large trace, here are a few things you can try:

* Capture a trace with `tcpdump <http://www.tcpdump.org/>`__, either
  on the same interface Bro is running on, or on another host where
  you can generate traffic of the kind likely triggering the problem
  (e.g., if you're seeing problems with the HTTP analyzer, record some
  of your Web browsing on your desktop.) When using tcpdump, don't
  forget to record *complete* packets (``tcpdump -s 0 ...``). You can
  reduce the amount of traffic captured by using a suitable BPF filter
  (e.g., for HTTP only, try ``port 80``). 

* Bro's command-line option ``-w <trace>`` records all packets it
  processes into the given file. You can then later run Bro
  offline on this trace and it will process the packets in the same
  way as it did live. This is particularly helpful with problems that
  only occur after Bro has already been running for some time. For
  example, sometimes a crash may be triggered by a particular kind of
  traffic only occurring rarely. Running Bro live with ``-w`` and
  then, after the crash, offline on the recorded trace might, with a
  little bit of luck, reproduce the problem reliably. However, be
  careful with ``-w``: it can result in huge trace files, quickly
  filling up your disk. (One way to mitigate the space issues is to
  periodically delete the trace file by configuring
  ``rotate-logs.bro`` accordingly. BroControl does that for you if you
  set its ``SaveTraces`` option.)

* Finally, you can try running Bro on a publically available trace
  file, such as `anonymized FTP traffic <http://www-nrg.ee.lbl.gov
  /anonymized-traces.html>`__, `headers-only enterprise traffic
  <http://www.icir.org/enterprise-tracing/Overview.html>`__, or
  `Defcon traffic <http://cctf.shmoo.com/>`__. Some of these
  particularly stress certain components of Bro (e.g., the Defcon
  traces contain tons of scans).

Once you have a trace that demonstrates the effect, you will often
notice that it's pretty big, in particular if recorded from the link
you're monitoring. Therefore, the next step is to shrink its size as
much as possible. Here are a few things you can try to this end:

* Very often, a single connection is able to demonstrate the problem.
  If you can identify which one it is (e.g., from one of Bro's
  ``*.log`` files) you can extract the connection's packets from the
  trace using tcpdump by filtering for the corresponding 4-tuple of
  addresses and ports:

  .. console::
    
    > tcpdump -r large.trace -w small.trace host <ip1> and port <port1> and host <ip2> and port <port2>

* If you can't reduce the problem to a connection, try to identify
  either a host pair or a single host triggering it, and filter down
  the trace accordingly.

* You can try to extract a smaller time slice from the trace using 
  `TCPslice <http://www.tcpdump.org/related.html>`__. For example, to
  extract the first 100 seconds from the trace:

  .. console::

    # Test comment
    > tcpslice +100 <in >out
    
Alternatively, tcpdump extracts the first ``n`` packets with its
option ``-c <n>``.


Getting More Information After a Crash
--------------------------------------

If Bro crashes, a *core dump* can be very helpful to nail down the
problem. Examining a core is not for the faint of heart but can reveal
extremely useful information.

First, you should configure Bro with the option ``--enable-debug`` and
recompile; this will disable all compiler optimizations and thus make
the core dump more useful (don't expect great performance with this
version though; compiling Bro without optimization has a noticeable
impact on its CPU usage.). Then enable core dumps if you haven't
already (e.g., ``ulimit -c unlimited`` if you're using bash).

Once Bro has crashed, start gdb with the Bro binary and the file
containing the core dump. (Alternatively, you can also run Bro
directly inside gdb instead of working from a core file.) The first
helpful information to include with your tracker ticket is a stack
backtrace, which you get with gdb's ``bt`` command:

.. console::
    
    > gdb bro core
    [...]
    > bt
    

If the crash occurs inside Bro's script interpreter, the next thing to
do is identifying the line of script code processed just before the
abnormal termination. Look for methods in the stack backtrace which
belong to any of the script interpreter's classes. Roughly speaking,
these are all classes with names ending in ``Expr``, ``Stmt``, or
``Val``. Then climb up the stack with ``up`` until you reach the first
of these methods. The object to which ``this`` is pointing will have a
``Location`` object, which in turn contains the file name and line
number of the corresponding piece of script code. Continuing the
example from above, here's how to get that information:

.. console::

    [in gdb]
    > up
    > ...
    > up
    > print this->location->filename
    > print this->location->first_line
    

If the crash occurs while processing input packets but you cannot
directly tell which connection is responsible (and thus not extract
its packets from the trace as suggested above), try getting the
4-tuple of the connection currently being processed from the core dump
by again examining the stack backtrace, this time looking for methods
belonging to the ``Connection`` class. That class has members
``orig_addr``/``resp_addr`` and ``orig_port``/``resp_port`` storing
(pointers to) the IP addresses and ports respectively:

.. console::

    [in gdb]
    > up
    > ...
    > up
    > printf "%08x:%04x %08x:%04x\n", *this->orig_addr, this->orig_port, *this->resp_addr, this->resp_port


Note that these values are stored in `network byte order
<http://en.wikipedia.org/wiki/Endianness#Endianness_in_networking>`__
so you will need to flip the bytes around if you are on a low-endian
machine (which is why the above example prints them in hex). For
example, if an IP address prints as ``0100007f`` , that's 127.0.0.1 .

