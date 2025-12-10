:tocdepth: 3

base/frameworks/files/main.zeek
===============================
.. zeek:namespace:: Files

An interface for driving the analysis of files, possibly independent of
any network protocol over which they're transported.

:Namespace: Files
:Imports: :doc:`base/bif/file_analysis.bif.zeek </scripts/base/bif/file_analysis.bif.zeek>`, :doc:`base/frameworks/analyzer </scripts/base/frameworks/analyzer/index>`, :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`, :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================== ========================================
:zeek:id:`Files::enable_reassembler`: :zeek:type:`bool` :zeek:attr:`&redef` The default setting for file reassembly.
=========================================================================== ========================================

Redefinable Options
###################
=========================================================================================== ================================================================
:zeek:id:`Files::analyze_by_mime_type_automatically`: :zeek:type:`bool` :zeek:attr:`&redef` Decide if you want to automatically attached analyzers to
                                                                                            files based on the detected mime type of the file.
:zeek:id:`Files::disable`: :zeek:type:`table` :zeek:attr:`&redef`                           A table that can be used to disable file analysis completely for
                                                                                            any files transferred over given network protocol analyzers.
:zeek:id:`Files::reassembly_buffer_size`: :zeek:type:`count` :zeek:attr:`&redef`            The default per-file reassembly buffer size.
=========================================================================================== ================================================================

Types
#####
========================================================================= ==============================================================
:zeek:type:`Files::AnalyzerArgs`: :zeek:type:`record` :zeek:attr:`&redef` A structure which parameterizes a type of file analysis.
:zeek:type:`Files::Info`: :zeek:type:`record` :zeek:attr:`&redef`         Contains all metadata related to the analysis of a given file.
:zeek:type:`Files::ProtoRegistration`: :zeek:type:`record`                
========================================================================= ==============================================================

Redefinitions
#############
============================================================= =======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                       
                                                              
                                                              * :zeek:enum:`Files::LOG`:
                                                                Logging stream for file analysis.
:zeek:type:`fa_file`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                              
                                                              :New Fields: :zeek:type:`fa_file`
                                                              
                                                                info: :zeek:type:`Files::Info` :zeek:attr:`&optional`
============================================================= =======================================================

Events
######
=============================================== ====================================================================
:zeek:id:`Files::log_files`: :zeek:type:`event` Event that can be handled to access the Info record as it is sent on
                                                to the logging framework.
=============================================== ====================================================================

Hooks
#####
========================================================== =============================================
:zeek:id:`Files::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
========================================================== =============================================

Functions
#########
======================================================================= =============================================================================
:zeek:id:`Files::add_analyzer`: :zeek:type:`function`                   Adds an analyzer to the analysis of a given file.
:zeek:id:`Files::all_registered_mime_types`: :zeek:type:`function`      Returns a table of all MIME-type-to-analyzer mappings currently registered.
:zeek:id:`Files::analyzer_enabled`: :zeek:type:`function`               Checks whether a file analyzer is generally enabled.
:zeek:id:`Files::analyzer_name`: :zeek:type:`function`                  Translates a file analyzer enum value to a string with the
                                                                        analyzer's name.
:zeek:id:`Files::describe`: :zeek:type:`function`                       Provides a text description regarding metadata of the file.
:zeek:id:`Files::disable_analyzer`: :zeek:type:`function`               Disables a file analyzer.
:zeek:id:`Files::disable_reassembly`: :zeek:type:`function`             Disables the file reassembler on this file.
:zeek:id:`Files::enable_analyzer`: :zeek:type:`function`                Enables a file analyzer.
:zeek:id:`Files::enable_reassembly`: :zeek:type:`function`              Allows the file reassembler to be used if it's necessary because the
                                                                        file is transferred out of order.
:zeek:id:`Files::file_exists`: :zeek:type:`function`                    Lookup to see if a particular file id exists and is still valid.
:zeek:id:`Files::lookup_file`: :zeek:type:`function`                    Lookup an :zeek:see:`fa_file` record with the file id.
:zeek:id:`Files::register_analyzer_add_callback`: :zeek:type:`function` Register a callback for file analyzers to use if they need to do some
                                                                        manipulation when they are being added to a file before the core code
                                                                        takes over.
:zeek:id:`Files::register_for_mime_type`: :zeek:type:`function`         Registers a MIME type for an analyzer.
:zeek:id:`Files::register_for_mime_types`: :zeek:type:`function`        Registers a set of MIME types for an analyzer.
:zeek:id:`Files::register_protocol`: :zeek:type:`function`              Register callbacks for protocols that work with the Files framework.
:zeek:id:`Files::registered_mime_types`: :zeek:type:`function`          Returns a set of all MIME types currently registered for a specific analyzer.
:zeek:id:`Files::remove_analyzer`: :zeek:type:`function`                Removes an analyzer from the analysis of a given file.
:zeek:id:`Files::set_reassembly_buffer_size`: :zeek:type:`function`     Set the maximum size the reassembly buffer is allowed to grow
                                                                        for the given file.
:zeek:id:`Files::set_timeout_interval`: :zeek:type:`function`           Sets the *timeout_interval* field of :zeek:see:`fa_file`, which is
                                                                        used to determine the length of inactivity that is allowed for a file
                                                                        before internal state related to it is cleaned up.
:zeek:id:`Files::stop`: :zeek:type:`function`                           Stops/ignores any further analysis of a given file.
======================================================================= =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Files::enable_reassembler
   :source-code: base/frameworks/files/main.zeek 127 127

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   The default setting for file reassembly.

Redefinable Options
###################
.. zeek:id:: Files::analyze_by_mime_type_automatically
   :source-code: base/frameworks/files/main.zeek 124 124

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Decide if you want to automatically attached analyzers to
   files based on the detected mime type of the file.

.. zeek:id:: Files::disable
   :source-code: base/frameworks/files/main.zeek 120 120

   :Type: :zeek:type:`table` [:zeek:type:`Files::Tag`] of :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   A table that can be used to disable file analysis completely for
   any files transferred over given network protocol analyzers.

.. zeek:id:: Files::reassembly_buffer_size
   :source-code: base/frameworks/files/main.zeek 130 130

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``524288``

   The default per-file reassembly buffer size.

Types
#####
.. zeek:type:: Files::AnalyzerArgs
   :source-code: base/frameworks/files/main.zeek 21 32

   :Type: :zeek:type:`record`


   .. zeek:field:: chunk_event :zeek:type:`event` (f: :zeek:type:`fa_file`, data: :zeek:type:`string`, off: :zeek:type:`count`) :zeek:attr:`&optional`

      An event which will be generated for all new file contents,
      chunk-wise.  Used when *tag* (in the
      :zeek:see:`Files::add_analyzer` function) is
      :zeek:see:`Files::ANALYZER_DATA_EVENT`.


   .. zeek:field:: stream_event :zeek:type:`event` (f: :zeek:type:`fa_file`, data: :zeek:type:`string`) :zeek:attr:`&optional`

      An event which will be generated for all new file contents,
      stream-wise.  Used when *tag* is
      :zeek:see:`Files::ANALYZER_DATA_EVENT`.


   .. zeek:field:: extract_filename :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/files/extract/main.zeek` is loaded)

      The local filename to which to write an extracted file.
      This field is used in the core by the extraction plugin
      to know where to write the file to.  If not specified, then
      a filename in the format "extract-<source>-<id>" is
      automatically assigned (using the *source* and *id*
      fields of :zeek:see:`fa_file`).


   .. zeek:field:: extract_limit :zeek:type:`count` :zeek:attr:`&default` = :zeek:see:`FileExtract::default_limit` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/files/extract/main.zeek` is loaded)

      The maximum allowed file size in bytes of *extract_filename*.
      Once reached, a :zeek:see:`file_extraction_limit` event is
      raised and the analyzer will be removed unless
      :zeek:see:`FileExtract::set_limit` is called to increase the
      limit.  A value of zero means "no limit".


   .. zeek:field:: extract_limit_includes_missing :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`FileExtract::default_limit_includes_missing` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/files/extract/main.zeek` is loaded)

      By default, missing bytes in files count towards the extract file size.
      Missing bytes can, e.g., occur due to missed traffic, or offsets
      used when downloading files.
      Setting this option to false changes this behavior so that holes
      in files do no longer count towards these limits. Files with
      holes are created as sparse files on disk. Their apparent size
      can exceed this file size limit.

   :Attributes: :zeek:attr:`&redef`

   A structure which parameterizes a type of file analysis.

.. zeek:type:: Files::Info
   :source-code: base/frameworks/files/main.zeek 37 116

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The time when the file was first seen.


   .. zeek:field:: fuid :zeek:type:`string` :zeek:attr:`&log`

      An identifier associated with a single file.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      If this file, or parts of it, were transferred over a
      network connection, this is the uid for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log` :zeek:attr:`&optional`

      If this file, or parts of it, were transferred over a
      network connection, this shows the connection.


   .. zeek:field:: source :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      An identification of the source of the file data.  E.g. it
      may be a network protocol over which it was transferred, or a
      local file path which was read, or some other input source.


   .. zeek:field:: depth :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`

      A value to represent the depth of this file in relation
      to its source.  In SMTP, it is the depth of the MIME
      attachment on the message.  In HTTP, it is the depth of the
      request within the TCP connection.


   .. zeek:field:: analyzers :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional` :zeek:attr:`&log`

      A set of analysis types done during the file analysis.


   .. zeek:field:: mime_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A mime type provided by the strongest file magic signature
      match against the *bof_buffer* field of :zeek:see:`fa_file`,
      or in the cases where no buffering of the beginning of file
      occurs, an initial guess of the mime type based on the first
      data seen.


   .. zeek:field:: filename :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A filename for the file if one is available from the source
      for the file.  These will frequently come from
      "Content-Disposition" headers in network protocols.


   .. zeek:field:: duration :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`

      The duration the file was analyzed for.


   .. zeek:field:: local_orig :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      If the source of this file is a network connection, this field
      indicates if the data originated from the local network or not as
      determined by the configured :zeek:see:`Site::local_nets`.


   .. zeek:field:: is_orig :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      If the source of this file is a network connection, this field
      indicates if the file is being sent by the originator of the
      connection or the responder.


   .. zeek:field:: seen_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Number of bytes provided to the file analysis engine for the file.
      The value refers to the total number of bytes processed for this
      file across all connections seen by the current Zeek instance.


   .. zeek:field:: total_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Total number of bytes that are supposed to comprise the full file.


   .. zeek:field:: missing_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      The number of bytes in the file stream that were completely missed
      during the process of analysis e.g. due to dropped packets.
      The value refers to number of bytes missed for this file
      across all connections seen by the current Zeek instance.


   .. zeek:field:: overflow_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      The number of bytes in the file stream that were not delivered to
      stream file analyzers.  This could be overlapping bytes or
      bytes that couldn't be reassembled.


   .. zeek:field:: timedout :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Whether the file analysis timed out at least once for the file.


   .. zeek:field:: parent_fuid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Identifier associated with a container file from which this one was
      extracted as part of the file analysis.


   .. zeek:field:: md5 :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/files/hash/main.zeek` is loaded)

      An MD5 digest of the file contents.


   .. zeek:field:: sha1 :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/files/hash/main.zeek` is loaded)

      A SHA1 digest of the file contents.


   .. zeek:field:: sha256 :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/files/hash/main.zeek` is loaded)

      A SHA256 digest of the file contents.


   .. zeek:field:: x509 :zeek:type:`X509::Info` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/files/x509/main.zeek` is loaded)

      Information about X509 certificates. This is used to keep
      certificate information until all events have been received.


   .. zeek:field:: extracted :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/base/files/extract/main.zeek` is loaded)

      Local filename of extracted file.


   .. zeek:field:: extracted_cutoff :zeek:type:`bool` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/base/files/extract/main.zeek` is loaded)

      Set to true if the file being extracted was cut off
      so the whole file was not logged.


   .. zeek:field:: extracted_size :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/base/files/extract/main.zeek` is loaded)

      The number of bytes extracted to disk.


   .. zeek:field:: entropy :zeek:type:`double` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/frameworks/files/entropy-test-all-files.zeek` is loaded)

      The information density of the contents of the file,
      expressed as a number of bits per character.

   :Attributes: :zeek:attr:`&redef`

   Contains all metadata related to the analysis of a given file.
   For the most part, fields here are derived from ones of the same name
   in :zeek:see:`fa_file`.

.. zeek:type:: Files::ProtoRegistration
   :source-code: base/frameworks/files/main.zeek 255 265

   :Type: :zeek:type:`record`


   .. zeek:field:: get_file_handle :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

      A callback to generate a file handle on demand when
      one is needed by the core.


   .. zeek:field:: describe :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`

      A callback to "describe" a file.  In the case of an HTTP
      transfer the most obvious description would be the URL.
      It's like an extremely compressed version of the normal log.



Events
######
.. zeek:id:: Files::log_files
   :source-code: base/frameworks/files/main.zeek 326 326

   :Type: :zeek:type:`event` (rec: :zeek:type:`Files::Info`)

   Event that can be handled to access the Info record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: Files::log_policy
   :source-code: base/files/x509/main.zeek 199 203

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: Files::add_analyzer
   :source-code: base/frameworks/files/main.zeek 415 431

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`, tag: :zeek:type:`Files::Tag`, args: :zeek:type:`Files::AnalyzerArgs` :zeek:attr:`&default` = *[chunk_event=<uninitialized>, stream_event=<uninitialized>, extract_filename=<uninitialized>, extract_limit=104857600, extract_limit_includes_missing=T]* :zeek:attr:`&optional`) : :zeek:type:`bool`

   Adds an analyzer to the analysis of a given file.
   

   :param f: the file.
   

   :param tag: the analyzer type.
   

   :param args: any parameters the analyzer takes.
   

   :returns: true if the analyzer will be added, or false if analysis
            for the file isn't currently active or the *args*
            were invalid for the analyzer type.

.. zeek:id:: Files::all_registered_mime_types
   :source-code: base/frameworks/files/main.zeek 495 498

   :Type: :zeek:type:`function` () : :zeek:type:`table` [:zeek:type:`Files::Tag`] of :zeek:type:`set` [:zeek:type:`string`]

   Returns a table of all MIME-type-to-analyzer mappings currently registered.
   

   :returns: A table mapping each analyzer to the set of MIME types
            registered for it.

.. zeek:id:: Files::analyzer_enabled
   :source-code: base/frameworks/files/main.zeek 410 413

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   Checks whether a file analyzer is generally enabled.
   

   :param tag: the analyzer type to check.
   

   :returns: true if the analyzer is generally enabled, else false.

.. zeek:id:: Files::analyzer_name
   :source-code: base/frameworks/files/main.zeek 448 451

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`string`

   Translates a file analyzer enum value to a string with the
   analyzer's name.
   

   :param tag: The analyzer tag.
   

   :returns: The analyzer name corresponding to the tag.

.. zeek:id:: Files::describe
   :source-code: base/frameworks/files/main.zeek 500 511

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Provides a text description regarding metadata of the file.
   For example, with HTTP it would return a URL.
   

   :param f: The file to be described.
   

   :returns: a text description regarding metadata of the file.

.. zeek:id:: Files::disable_analyzer
   :source-code: base/frameworks/files/main.zeek 405 408

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   Disables a file analyzer.
   

   :param tag: the analyzer type to disable.
   

   :returns: false if the analyzer tag could not be found, else true.

.. zeek:id:: Files::disable_reassembly
   :source-code: base/frameworks/files/main.zeek 390 393

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`void`

   Disables the file reassembler on this file.  If the file is not
   transferred out of order this will have no effect.
   

   :param f: the file.

.. zeek:id:: Files::enable_analyzer
   :source-code: base/frameworks/files/main.zeek 400 403

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   Enables a file analyzer.
   

   :param tag: the analyzer type to enable.
   

   :returns: false if the analyzer tag could not be found, else true.

.. zeek:id:: Files::enable_reassembly
   :source-code: base/frameworks/files/main.zeek 385 388

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`void`

   Allows the file reassembler to be used if it's necessary because the
   file is transferred out of order.
   

   :param f: the file.

.. zeek:id:: Files::file_exists
   :source-code: base/frameworks/files/main.zeek 370 373

   :Type: :zeek:type:`function` (fuid: :zeek:type:`string`) : :zeek:type:`bool`

   Lookup to see if a particular file id exists and is still valid.
   

   :param fuid: the file id.
   

   :returns: T if the file uid is known.

.. zeek:id:: Files::lookup_file
   :source-code: base/frameworks/files/main.zeek 375 378

   :Type: :zeek:type:`function` (fuid: :zeek:type:`string`) : :zeek:type:`fa_file`

   Lookup an :zeek:see:`fa_file` record with the file id.
   

   :param fuid: the file id.
   

   :returns: the associated :zeek:see:`fa_file` record.

.. zeek:id:: Files::register_analyzer_add_callback
   :source-code: base/frameworks/files/main.zeek 433 436

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`, callback: :zeek:type:`function` (f: :zeek:type:`fa_file`, args: :zeek:type:`Files::AnalyzerArgs`) : :zeek:type:`void`) : :zeek:type:`void`

   Register a callback for file analyzers to use if they need to do some
   manipulation when they are being added to a file before the core code
   takes over.  This is unlikely to be interesting for users and should
   only be called by file analyzer authors but is *not required*.
   

   :param tag: Tag for the file analyzer.
   

   :param callback: Function to execute when the given file analyzer is being added.

.. zeek:id:: Files::register_for_mime_type
   :source-code: base/frameworks/files/main.zeek 473 488

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`, mt: :zeek:type:`string`) : :zeek:type:`bool`

   Registers a MIME type for an analyzer. If a future file with this type is seen,
   the analyzer will be automatically assigned to parsing it. The function *adds*
   to all MIME types already registered, it doesn't replace them.
   

   :param tag: The tag of the analyzer.
   

   :param mt: The MIME type in the form "foo/bar" (case-insensitive).
   

   :returns: True if the MIME type was successfully registered.

.. zeek:id:: Files::register_for_mime_types
   :source-code: base/frameworks/files/main.zeek 460 471

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`, mime_types: :zeek:type:`set` [:zeek:type:`string`]) : :zeek:type:`bool`

   Registers a set of MIME types for an analyzer. If a future connection on one of
   these types is seen, the analyzer will be automatically assigned to parsing it.
   The function *adds* to all MIME types already registered, it doesn't replace
   them.
   

   :param tag: The tag of the analyzer.
   

   :param mts: The set of MIME types, each in the form "foo/bar" (case-insensitive).
   

   :returns: True if the MIME types were successfully registered.

.. zeek:id:: Files::register_protocol
   :source-code: base/frameworks/files/main.zeek 453 458

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`, reg: :zeek:type:`Files::ProtoRegistration`) : :zeek:type:`bool`

   Register callbacks for protocols that work with the Files framework.
   The callbacks must uniquely identify a file and each protocol can
   only have a single callback registered for it.
   

   :param tag: Tag for the protocol analyzer having a callback being registered.
   

   :param reg: A :zeek:see:`Files::ProtoRegistration` record.
   

   :returns: true if the protocol being registered was not previously registered.

.. zeek:id:: Files::registered_mime_types
   :source-code: base/frameworks/files/main.zeek 490 493

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`set` [:zeek:type:`string`]

   Returns a set of all MIME types currently registered for a specific analyzer.
   

   :param tag: The tag of the analyzer.
   

   :returns: The set of MIME types.

.. zeek:id:: Files::remove_analyzer
   :source-code: base/frameworks/files/main.zeek 438 441

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`, tag: :zeek:type:`Files::Tag`, args: :zeek:type:`Files::AnalyzerArgs` :zeek:attr:`&default` = *[chunk_event=<uninitialized>, stream_event=<uninitialized>, extract_filename=<uninitialized>, extract_limit=104857600, extract_limit_includes_missing=T]* :zeek:attr:`&optional`) : :zeek:type:`bool`

   Removes an analyzer from the analysis of a given file.
   

   :param f: the file.
   

   :param tag: the analyzer type.
   

   :param args: the analyzer (type and args) to remove.
   

   :returns: true if the analyzer will be removed, or false if analysis
            for the file isn't currently active.

.. zeek:id:: Files::set_reassembly_buffer_size
   :source-code: base/frameworks/files/main.zeek 395 398

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`, max: :zeek:type:`count`) : :zeek:type:`void`

   Set the maximum size the reassembly buffer is allowed to grow
   for the given file.
   

   :param f: the file.
   

   :param max: Maximum allowed size of the reassembly buffer.

.. zeek:id:: Files::set_timeout_interval
   :source-code: base/frameworks/files/main.zeek 380 383

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`, t: :zeek:type:`interval`) : :zeek:type:`bool`

   Sets the *timeout_interval* field of :zeek:see:`fa_file`, which is
   used to determine the length of inactivity that is allowed for a file
   before internal state related to it is cleaned up.  When used within
   a :zeek:see:`file_timeout` handler, the analysis will delay timing out
   again for the period specified by *t*.
   

   :param f: the file.
   

   :param t: the amount of time the file can remain inactive before discarding.
   

   :returns: true if the timeout interval was set, or false if analysis
            for the file isn't currently active.

.. zeek:id:: Files::stop
   :source-code: base/frameworks/files/main.zeek 443 446

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`bool`

   Stops/ignores any further analysis of a given file.
   

   :param f: the file.
   

   :returns: true if analysis for the given file will be ignored for the
            rest of its contents, or false if analysis for the file
            isn't currently active.


