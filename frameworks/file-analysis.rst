
.. _file-analysis-framework:

=============
File Analysis
=============

.. rst-class:: opening

    In the past, writing Zeek scripts with the intent of analyzing file
    content could be cumbersome because of the fact that the content
    would be presented in different ways, via events, at the
    script-layer depending on which network protocol was involved in the
    file transfer.  Scripts written to analyze files over one protocol
    would have to be copied and modified to fit other protocols.  The
    file analysis framework (FAF) instead provides a generalized
    presentation of file-related information.  The information regarding
    the protocol involved in transporting a file over the network is
    still available, but it no longer has to dictate how one organizes
    their scripting logic to handle it.  A goal of the FAF is to
    provide analysis specifically for files that is analogous to the
    analysis Zeek provides for network connections.

File Lifecycle Events
=====================

The key events that may occur during the lifetime of a file are:
:zeek:see:`file_new`, :zeek:see:`file_over_new_connection`,
:zeek:see:`file_timeout`, :zeek:see:`file_gap`, and
:zeek:see:`file_state_remove`.  Handling any of these events provides
some information about the file such as which network
:zeek:see:`connection` and protocol are transporting the file, how many
bytes have been transferred so far, and its MIME type.

Here's a simple example:

.. literalinclude:: file_analysis_01.zeek
   :caption:
   :language: zeek
   :linenos:

.. sourcecode:: console

   $ zeek -r http/get.trace file_analysis_01.zeek
   file_state_remove
   FakNcS1Jfe01uljb3
   CHhAvVGS1DHFjwGM9
   [orig_h=141.142.228.5, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp]
   HTTP
   connection_state_remove
   CHhAvVGS1DHFjwGM9
   [orig_h=141.142.228.5, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp]
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
attached, they start receiving the contents of the file as Zeek extracts
it from an ongoing network connection.  What they do with the file
contents is up to the particular file analyzer implementation, but
they'll typically either report further information about the file via
events (e.g. :zeek:see:`Files::ANALYZER_MD5` will report the
file's MD5 checksum via :zeek:see:`file_hash` once calculated) or they'll
have some side effect (e.g. :zeek:see:`Files::ANALYZER_EXTRACT`
will write the contents of the file out to the local file system).

In the future there may be file analyzers that automatically attach to
files based on heuristics, similar to the Dynamic Protocol Detection
(DPD) framework for connections, but many will always require an
explicit attachment decision.

Here's a simple example of how to use the MD5 file analyzer to
calculate the MD5 of plain text files:

.. literalinclude:: file_analysis_02.zeek
   :caption:
   :language: zeek
   :linenos:

.. sourcecode:: console

   $ zeek -r http/get.trace file_analysis_02.zeek
   new file, FakNcS1Jfe01uljb3
   file_hash, FakNcS1Jfe01uljb3, md5, 397168fd09991a0e712254df7bc639ac

Some file analyzers might have tunable parameters that need to be
specified in the call to :zeek:see:`Files::add_analyzer`:

.. sourcecode:: zeek

    event file_new(f: fa_file)
        {
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
                            [$extract_filename="myfile"]);
        }

In this case, the file extraction analyzer doesn't generate any further
events, but does have the effect of writing out the file contents to the
local file system at the location resulting from the concatenation of
the path specified by :zeek:see:`FileExtract::prefix` and the string,
``myfile``.  Of course, for a network with more than a single file being
transferred, it's probably preferable to specify a different extraction
path for each file, unlike this example.

Regardless of which file analyzers end up acting on a file, general
information about the file (e.g. size, time of last data transferred,
MIME type, etc.) are logged in ``files.log``.

Input Framework Integration
===========================

The FAF comes with a simple way to integrate with the :doc:`Input
Framework <input>`, so that Zeek can analyze files from external sources
in the same way it analyzes files that it sees coming over traffic from
a network interface it's monitoring.  It only requires a call to
:zeek:see:`Input::add_analysis`:

.. literalinclude:: file_analysis_03.zeek
   :caption:
   :language: zeek
   :linenos:

Note that the "source" field of :zeek:see:`fa_file` corresponds to the
"name" field of :zeek:see:`Input::AnalysisDescription` since that is what
the input framework uses to uniquely identify an input stream.

Example output of the above script may be:

.. sourcecode:: console

   $ echo "Hello world" > myfile
   $ zeek file_analysis_03.zeek
   new file, FZedLu4Ajcvge02jA8
   file_hash, FZedLu4Ajcvge02jA8, md5, f0ef7081e1539ac00ef5b761b4fb01b3
   file_state_remove

Nothing that special, but it at least verifies the MD5 file analyzer
saw all the bytes of the input file and calculated the checksum
correctly!
