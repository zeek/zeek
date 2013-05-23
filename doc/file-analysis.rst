=============
File Analysis
=============

.. rst-class:: opening

    In the past, writing Bro scripts with the intent of analyzing file
    content could be cumbersome because of the fact that the content
    would be presented in different ways, via events, at the
    script-layer depending on which network protocol was involved in the
    file transfer.  Scripts written to analyze files over one protocol
    would have to be copied and modified to fit other protocols.  The
    file analysis framework (FAF) is an attempt to provide a generalized
    presentation of file-related information.  The information regarding
    the protocol involved in transporting a file over the network is
    still available, but it no longer has to dictate how one organizes
    their scripting logic to handle it.  A goal of the FAF is to
    provide analysis specifically for files that is analogous to the
    analysis Bro provides for network connections.

.. contents::

File Lifecycle Events
=====================

The key events that may occur during the lifetime of a file are:
:bro:see:`file_new`, :bro:see:`file_over_new_connection`,
:bro:see:`file_timeout`, :bro:see:`file_gap`, and
:bro:see:`file_state_remove`.  Handling any of these events provides
some information about the file such as which network
:bro:see:`connection` and protocol are transporting the file, how many
bytes have been transferred so far, and its MIME type.

.. code:: bro

    event connection_state_remove(c: connection)
        {
        print "connection_state_remove";
        print c$uid;
        print c$id;
        for ( s in c$service )
            print s;
        }

    event file_state_remove(f: fa_file)
        {
        print "file_state_remove";
        print f$id;
        for ( cid in f$conns )
            {
            print f$conns[cid]$uid;
            print cid;
            }
        print f$source;
        }

might give output like::

    file_state_remove
    Cx92a0ym5R8
    REs2LQfVW2j
    [orig_h=10.0.0.7, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp]
    HTTP
    connection_state_remove
    REs2LQfVW2j
    [orig_h=10.0.0.7, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp]
    HTTP

This doesn't perform any interesting analysis yet, but does highlight
the similarity between analysis of connections and files.  Connections
are identified by the usual 5-tuple or a convenient UID string while
files are identified just by a string of the same format as the
connection UID.  So there's unique ways to identify both files and
connections and files hold references to a connection (or connections)
that transported it.

Adding Analysis
===============

There are builtin file analyzers which can be attached to files.  Once
attached, they start receiving the contents of the file as Bro extracts
it from an ongoing network connection.  What they do with the file
contents is up to the particular file analyzer implementation, but
they'll typically either report further information about the file via
events (e.g. :bro:see:`FileAnalysis::ANALYZER_MD5` will report the
file's MD5 checksum via :bro:see:`file_hash` once calculated) or they'll
have some side effect (e.g. :bro:see:`FileAnalysis::ANALYZER_EXTRACT`
will write the contents of the file out to the local file system).

In the future there may be file analyzers that automatically attach to
files based on heuristics, similar to the Dynamic Protocol Detection
(DPD) framework for connections, but many will always require an
explicit attachment decision:

.. code:: bro

    event file_new(f: fa_file)
        {
        print "new file", f$id;
        if ( f?$mime_type && f$mime_type == "text/plain" )
            FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_MD5]);
        }

    event file_hash(f: fa_file, kind: string, hash: string)
        {
        print "file_hash", f$id, kind, hash;
        }

this script calculates MD5s for all plain text files and might give
output::

    new file, Cx92a0ym5R8
    file_hash, Cx92a0ym5R8, md5, 397168fd09991a0e712254df7bc639ac

Some file analyzers might have tunable parameters that need to be
specified in the call to :bro:see:`FileAnalysis::add_analyzer`:

.. code:: bro

    event file_new(f: fa_file)
        {
        FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_EXTRACT,
                                       $extract_filename="./myfile"]);
        }

In this case, the file extraction analyzer doesn't generate any further
events, but does have the side effect of writing out the file contents
to the local file system at the specified location of ``./myfile``.  Of
course, for a network with more than a single file being transferred,
it's probably preferable to specify a different extraction path for each
file, unlike this example.

Regardless of which file analyzers end up acting on a file, general
information about the file (e.g. size, time of last data transferred,
MIME type, etc.) are logged in ``file_analysis.log``.

Input Framework Integration
===========================

The FAF comes with a simple way to integrate with the :doc:`Input
Framework <input>`, so that Bro can analyze files from external sources
in the same way it analyzes files that it sees coming over traffic from
a network interface it's monitoring.  It only requires a call to
:bro:see:`Input::add_analysis`:

.. code:: bro

    redef exit_only_after_terminate = T;

    event file_new(f: fa_file)
        {
        print "new file", f$id;
        FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_MD5]);
        }

    event file_state_remove(f: fa_file)
        {
        Input::remove(f$source);
        terminate();
        }

    event file_hash(f: fa_file, kind: string, hash: string)
        {
        print "file_hash", f$id, kind, hash;
        }

    event bro_init()
        {
        local source: string = "./myfile";
        Input::add_analysis([$source=source, $name=source]);
        }

Note that the "source" field of :bro:see:`fa_file` corresponds to the
"name" field of :bro:see:`Input::AnalysisDescription` since that is what
the input framework uses to uniquely identify an input stream.

The output of the above script may be::

    new file, G1fS2xthS4l
    file_hash, G1fS2xthS4l, md5, 54098b367d2e87b078671fad4afb9dbb

Nothing that special, but it at least verifies the MD5 file analyzer
saw all the bytes of the input file and calculated the checksum
correctly!
