
.. _file-analysis-framework:

=======================
File Analysis Framework
=======================

.. TODO: integrate BoZ revisions

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

Supported Protocols
===================

Zeek ships with file analysis for the following protocols:
:ref:`FTP <plugin-zeek-ftp>`,
:ref:`HTTP <plugin-zeek-http>`,
:ref:`IRC <plugin-zeek-irc>`,
:ref:`Kerberos <plugin-zeek-krb>`,
:ref:`MIME <plugin-zeek-mime>`,
:ref:`RDP <plugin-zeek-rdp>`,
:ref:`SMTP <plugin-zeek-smtp>`, and
:ref:`SSL/TLS/DTLS <plugin-zeek-ssl>`.
Protocol analyzers are regular :ref:`Zeek plugins <writing-plugins>`, so users
are welcome to provide additional ones in separate Zeek packages.

File Lifecycle Events
=====================

The key events that may occur during the lifetime of a file are:
:zeek:see:`file_new`, :zeek:see:`file_over_new_connection`,
:zeek:see:`file_sniff`, :zeek:see:`file_timeout`, :zeek:see:`file_gap`, and
:zeek:see:`file_state_remove`.  Handling any of these events provides
some information about the file such as which network
:zeek:see:`connection` and protocol are transporting the file, how many
bytes have been transferred so far, and its MIME type.

Here's a simple example:

.. literalinclude:: file_analysis_01.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

.. code-block:: console

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

File Type Identification
========================

Zeek ships with its own library of content signatures to determine the type of a
file, conveyed as MIME types in the :zeek:see:`file_sniff` event. You can find
those signatures in the Zeek distribution's ``scripts/base/frameworks/files/magic/``
directory. (Despite the name, Zeek does `not` rely on libmagic for content analysis.)

Adding Analysis
===============

Zeek supports customized file analysis via `file analyzers` that users can
attach to observed files. You can attach analyzers selectively to individual
files, or register them for auto-attachment under certain conditions. Once
attached, file analyzers start receiving the contents of files as Zeek parses
them from ongoing network connections.

Zeek comes with the following built-in analyzers:

    * :ref:`plugin-zeek-filedataevent` to access file content via
      events (as data streams or content chunks),
    * :ref:`plugin-zeek-fileentropy` to compute various entropy for a file,
    * :ref:`plugin-zeek-fileextract` to extract files to disk,
    * :ref:`plugin-zeek-filehash` to produce common hash values for files,
    * :ref:`plugin-zeek-pe` to parse executables in PE format, and
    * :ref:`plugin-zeek-x509` to extract information about x509 certificates.

Like protocol parsers, file analyzers are regular :ref:`Zeek plugins
<writing-plugins>`. Users are free to contribute additional ones via Zeek
packages.

Per-file analyzer registration
------------------------------

To attach an analyzer to a specific file, call :zeek:see:`Files::add_analyzer`
with the analyzer's component tag (such as :zeek:see:`Files::ANALYZER_MD5`;
consult the above analyzers for details). Some file analyzers support parameters
that you can provide to this function via a :zeek:see:`Files::AnalyzerArgs`
record, while others introduce additional event types and tunable script-layer
settings.

You can add multiple analyzers to a file, and add the same analyzer type
multiple times, assuming you use varying :zeek:see:`Files::AnalyzerArgs`
parameterization. You may remove these selectively from files via calls to
:zeek:see:`Files::remove_analyzer`. You may also enable and disable file
analyzers globally by calling :zeek:see:`Files::enable_analyzer` and
:zeek:see:`Files::disable_analyzer`, respectively.

Generic analyzer registration
-----------------------------

The framework provides mechanisms for automatically attaching analyzers to
files. For example, the :zeek:see:`Files::register_for_mime_types` function
ensures that Zeek automatically attaches a given analyzer to all files of a
given MIME type. For fully customized  auto-attachment logic take a look at
:zeek:see:`Files::register_analyzer_add_callback`, and refer to
:doc:`base/frameworks/files/main.zeek </scripts/base/frameworks/files/main.zeek>`
for additional APIs and data structures.

Regardless of which file analyzers end up acting on a file, general
information about the file (e.g. size, time of last data transferred,
MIME type, etc.) is logged in ``files.log``.

Protocol-specific state
-----------------------

Some protocol analyzers redefine the ``fa_file`` record to add additional
state. For example, ``base/protocols/http/entities.zeek``, which Zeek loads by
default as part of the HTTP analyzer, makes the transaction's
:zeek:see:`HTTP::Info` record available via ``f$http`` to provide HTTP
context. As always, make sure to test the presence of optional fields via the
``a?$b`` :ref:`record field operator <record-field-operators>` before accessing
them.

Examples
--------

File hashing
^^^^^^^^^^^^

The following script uses the MD5 file analyzer to calculate the hashes of plain
text files:

.. literalinclude:: file_analysis_02.zeek
   :caption:
   :language: zeek
   :tab-width: 4

.. code-block:: console

   $ zeek -r http/get.trace file_analysis_02.zeek
   new file, FakNcS1Jfe01uljb3
   file_hash, FakNcS1Jfe01uljb3, md5, 397168fd09991a0e712254df7bc639ac

File extraction
^^^^^^^^^^^^^^^

The following example sets up extraction of observed files to disk:

.. code-block:: zeek

    global idx: count = 0;

    event file_new(f: fa_file)
        {
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
                            [$extract_filename=fmt("file-%04d", ++idx)]);
        }

The file extraction analyzer now writes the content of each observed file to a
separate file on disk. The output file name results from concatenating the
:zeek:see:`FileExtract::prefix` (normally ``./extract_files/``) and the
enumerated ``file-NNNN`` strings.

In a production setting you'll likely want to include additional information in
the output, for example from state attached to the provided file record. The
Zeek distribution ships with a starting point for such approaches: the
``policy/frameworks/files/extract-all-files.zeek`` script. For additional
configurability, take a look at the `file-extraction
<https://github.com/hosom/file-extraction>`_ Zeek package.

Script-level content analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``FileDataEvent`` analyzer provides script-layer access to file content for
customized analysis. Since observed files can be very large, Zeek cannot buffer
these files and provide their entire content to the script layer once
complete. Instead, the ``FileDataEvent`` analyzer reflects the incremental
nature of file content as Zeek observes it, and supports two types of events to
allow you to process it: user-provided `stream events` receive new file content
as supplied by connection-oriented protocols, while `chunk events` receive
observed data as provided by protocols that do not feature stream semantics.

The following example manually computes the SHA256 hash of each observed file by
building up hash state and feeding streamed file content into the hash
computation. When Zeek removes a file's state (because it has fully observed it,
or perhaps because its state is timing out), it prints the resulting hash to the
console:

.. code-block:: zeek

    global hashstate: table[string] of opaque of sha256;

    event file_stream(f: fa_file, data: string)
        {
        if ( f$id !in hashstate )
            hashstate[f$id] = sha256_hash_init();

        sha256_hash_update(hashstate[f$id], data);
        }

    event file_new(f: fa_file)
        {
        Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=file_stream]);
        }

    event file_state_remove(f: fa_file)
        {
        if ( f$id in hashstate )
            {
            print(sha256_hash_finish(hashstate[f$id]));
            delete hashstate[f$id];
            }
        }

Be careful with this approach, as it can quickly prove expensive to route all
file content through the script layer. Make sure to add the analyzer only for
relevant files, and consider removing it via :zeek:see:`Files::remove_analyzer`
when you no longer require content analysis. For performance-critical
applications a new file analyzer plugin could be a better approach.

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
   :tab-width: 4

Note that the "source" field of :zeek:see:`fa_file` corresponds to the
"name" field of :zeek:see:`Input::AnalysisDescription` since that is what
the input framework uses to uniquely identify an input stream.

Example output of the above script may be:

.. code-block:: console

   $ echo "Hello world" > myfile
   $ zeek file_analysis_03.zeek
   new file, FZedLu4Ajcvge02jA8
   file_hash, FZedLu4Ajcvge02jA8, md5, f0ef7081e1539ac00ef5b761b4fb01b3
   file_state_remove

Nothing that special, but it at least verifies the MD5 file analyzer
saw all the bytes of the input file and calculated the checksum
correctly!
