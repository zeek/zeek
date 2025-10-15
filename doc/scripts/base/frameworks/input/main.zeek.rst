:tocdepth: 3

base/frameworks/input/main.zeek
===============================
.. zeek:namespace:: Input

The input framework provides a way to read previously stored data either
as an event stream or into a Zeek table.

:Namespace: Input
:Imports: :doc:`base/bif/input.bif.zeek </scripts/base/bif/input.bif.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================ ==============================
:zeek:id:`Input::default_mode`: :zeek:type:`Input::Mode` :zeek:attr:`&redef`     The default reader mode used.
:zeek:id:`Input::default_reader`: :zeek:type:`Input::Reader` :zeek:attr:`&redef` The default input reader used.
================================================================================ ==============================

Redefinable Options
###################
================================================================================= =========================================================
:zeek:id:`Input::accept_unsupported_types`: :zeek:type:`bool` :zeek:attr:`&redef` Flag that controls if the input framework accepts records
                                                                                  that contain types that are not supported (at the moment
                                                                                  file and function).
:zeek:id:`Input::empty_field`: :zeek:type:`string` :zeek:attr:`&redef`            String to use for empty fields.
:zeek:id:`Input::separator`: :zeek:type:`string` :zeek:attr:`&redef`              Separator between fields.
:zeek:id:`Input::set_separator`: :zeek:type:`string` :zeek:attr:`&redef`          Separator between set elements.
:zeek:id:`Input::unset_field`: :zeek:type:`string` :zeek:attr:`&redef`            String to use for an unset &optional field.
================================================================================= =========================================================

Types
#####
============================================================ ===================================================================
:zeek:type:`Input::AnalysisDescription`: :zeek:type:`record` A file analysis input stream type used to forward input data to the
                                                             file analysis framework.
:zeek:type:`Input::Event`: :zeek:type:`enum`                 Type that describes what kind of change occurred.
:zeek:type:`Input::EventDescription`: :zeek:type:`record`    An event input stream type used to send input data to a Zeek event.
:zeek:type:`Input::Mode`: :zeek:type:`enum`                  Type that defines the input stream read mode.
:zeek:type:`Input::TableDescription`: :zeek:type:`record`    A table input stream type used to send data to a Zeek table.
:zeek:type:`Input::Reader`: :zeek:type:`enum`                
============================================================ ===================================================================

Events
######
================================================= ====================================================================
:zeek:id:`Input::end_of_data`: :zeek:type:`event` Event that is called when the end of a data source has been reached,
                                                  including after an update.
================================================= ====================================================================

Functions
#########
===================================================== ============================================================
:zeek:id:`Input::add_analysis`: :zeek:type:`function` Create a new file analysis input stream from a given source.
:zeek:id:`Input::add_event`: :zeek:type:`function`    Create a new event input stream from a given source.
:zeek:id:`Input::add_table`: :zeek:type:`function`    Create a new table input stream from a given source.
:zeek:id:`Input::force_update`: :zeek:type:`function` Forces the current input to be checked for changes.
:zeek:id:`Input::remove`: :zeek:type:`function`       Remove an input stream.
===================================================== ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Input::default_mode
   :source-code: base/frameworks/input/main.zeek 31 31

   :Type: :zeek:type:`Input::Mode`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Input::MANUAL``

   The default reader mode used. Defaults to `MANUAL`.

.. zeek:id:: Input::default_reader
   :source-code: base/frameworks/input/main.zeek 28 28

   :Type: :zeek:type:`Input::Reader`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Input::READER_ASCII``

   The default input reader used. Defaults to `READER_ASCII`.

Redefinable Options
###################
.. zeek:id:: Input::accept_unsupported_types
   :source-code: base/frameworks/input/main.zeek 56 56

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Flag that controls if the input framework accepts records
   that contain types that are not supported (at the moment
   file and function). If true, the input framework will
   warn in these cases, but continue. If false, it will
   abort. Defaults to false (abort).

.. zeek:id:: Input::empty_field
   :source-code: base/frameworks/input/main.zeek 45 45

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields.
   Individual readers can use a different value.

.. zeek:id:: Input::separator
   :source-code: base/frameworks/input/main.zeek 36 36

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"\x09"``

   Separator between fields.
   Please note that the separator has to be exactly one character long.
   Individual readers can use a different value.

.. zeek:id:: Input::set_separator
   :source-code: base/frameworks/input/main.zeek 41 41

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Separator between set elements.
   Please note that the separator has to be exactly one character long.
   Individual readers can use a different value.

.. zeek:id:: Input::unset_field
   :source-code: base/frameworks/input/main.zeek 49 49

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.
   Individual readers can use a different value.

Types
#####
.. zeek:type:: Input::AnalysisDescription
   :source-code: base/frameworks/input/main.zeek 180 204

   :Type: :zeek:type:`record`

      source: :zeek:type:`string`
         String that allows the reader to find the source.
         For `READER_ASCII`, this is the filename.

      reader: :zeek:type:`Input::Reader` :zeek:attr:`&default` = ``Input::READER_BINARY`` :zeek:attr:`&optional`
         Reader to use for this stream.  Compatible readers must be
         able to accept a filter of a single string type (i.e.
         they read a byte stream).

      mode: :zeek:type:`Input::Mode` :zeek:attr:`&default` = :zeek:see:`Input::default_mode` :zeek:attr:`&optional`
         Read mode to use for this stream.

      name: :zeek:type:`string`
         Descriptive name that uniquely identifies the input source.
         Can be used to remove a stream at a later time.
         This will also be used for the unique *source* field of
         :zeek:see:`fa_file`.  Most of the time, the best choice for this
         field will be the same value as the *source* field.

      config: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         A key/value table that will be passed to the reader.
         Interpretation of the values is left to the reader, but
         usually they will be used for configuration purposes.

   A file analysis input stream type used to forward input data to the
   file analysis framework.

.. zeek:type:: Input::Event
   :source-code: base/frameworks/input/main.zeek 8 8

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Input::EVENT_NEW Input::Event

         New data has been imported.

      .. zeek:enum:: Input::EVENT_CHANGED Input::Event

         Existing data has been changed.

      .. zeek:enum:: Input::EVENT_REMOVED Input::Event

         Previously existing data has been removed.

   Type that describes what kind of change occurred.

.. zeek:type:: Input::EventDescription
   :source-code: base/frameworks/input/main.zeek 125 176

   :Type: :zeek:type:`record`

      source: :zeek:type:`string`
         String that allows the reader to find the source.
         For `READER_ASCII`, this is the filename.

      reader: :zeek:type:`Input::Reader` :zeek:attr:`&default` = :zeek:see:`Input::default_reader` :zeek:attr:`&optional`
         Reader to use for this stream.

      mode: :zeek:type:`Input::Mode` :zeek:attr:`&default` = :zeek:see:`Input::default_mode` :zeek:attr:`&optional`
         Read mode to use for this stream.

      name: :zeek:type:`string`
         Descriptive name. Used to remove a stream at a later time.

      fields: :zeek:type:`any`
         Record type describing the fields to be retrieved from the input
         source.

      want_record: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         If this is false, the event receives each value in *fields* as a
         separate argument.
         If this is set to true (default), the event receives all fields in
         a single record value.

      ev: :zeek:type:`any`
         The event that is raised each time a new line is received from the
         reader. The event will receive an Input::EventDescription record
         as the first argument, an Input::Event enum as the second
         argument, and the fields (as specified in *fields*) as the following
         arguments (this will either be a single record value containing
         all fields, or each field value as a separate argument).

      error_ev: :zeek:type:`any` :zeek:attr:`&optional`
         Error event that is raised when an information, warning or error
         is raised by the input stream. If the level is error, the stream will automatically
         be closed.
         The event receives the Input::EventDescription as the first argument, the
         message as the second argument and the Reporter::Level as the third argument.
         
         The event is raised like it had been declared as follows:
         error_ev: function(desc: EventDescription, message: string, level: Reporter::Level) &optional;
         The actual declaration uses the ``any`` type because of deficiencies of the Zeek type system.

      config: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         A key/value table that will be passed to the reader.
         Interpretation of the values is left to the reader, but
         usually they will be used for configuration purposes.

   An event input stream type used to send input data to a Zeek event.

.. zeek:type:: Input::Mode
   :source-code: base/frameworks/input/main.zeek 18 26

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Input::MANUAL Input::Mode

         Do not automatically reread the file after it has been read.

      .. zeek:enum:: Input::REREAD Input::Mode

         Reread the entire file each time a change is found.

      .. zeek:enum:: Input::STREAM Input::Mode

         Read data from end of file each time new data is appended.

   Type that defines the input stream read mode.

.. zeek:type:: Input::TableDescription
   :source-code: base/frameworks/input/main.zeek 59 122

   :Type: :zeek:type:`record`

      source: :zeek:type:`string`
         String that allows the reader to find the source of the data.
         For `READER_ASCII`, this is the filename.

      reader: :zeek:type:`Input::Reader` :zeek:attr:`&default` = :zeek:see:`Input::default_reader` :zeek:attr:`&optional`
         Reader to use for this stream.

      mode: :zeek:type:`Input::Mode` :zeek:attr:`&default` = :zeek:see:`Input::default_mode` :zeek:attr:`&optional`
         Read mode to use for this stream.

      name: :zeek:type:`string`
         Name of the input stream.  This is used by some functions to
         manipulate the stream.

      destination: :zeek:type:`any`
         Table which will receive the data read by the input framework.

      idx: :zeek:type:`any`
         Record that defines the values used as the index of the table.

      val: :zeek:type:`any` :zeek:attr:`&optional`
         Record that defines the values used as the elements of the table.
         If this is undefined, then *destination* must be a set.

      want_record: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Defines if the value of the table is a record (default), or a single
         value. When this is set to false, then *val* can only contain one
         element.

      ev: :zeek:type:`any` :zeek:attr:`&optional`
         The event that is raised each time a value is added to, changed in,
         or removed from the table. The event will receive an
         Input::TableDescription as the first argument, an Input::Event
         enum as the second argument, the *idx* record as the third argument
         and the value (record) as the fourth argument.

      pred: :zeek:type:`function` (typ: :zeek:type:`Input::Event`, left: :zeek:type:`any`, right: :zeek:type:`any`) : :zeek:type:`bool` :zeek:attr:`&optional`
         Predicate function that can decide if an insertion, update or removal
         should really be executed. Parameters have same meaning as for the
         event.
         If true is returned, the update is performed. If false is returned,
         it is skipped.

      error_ev: :zeek:type:`any` :zeek:attr:`&optional`
         Error event that is raised when an information, warning or error
         is raised by the input stream. If the level is error, the stream will automatically
         be closed.
         The event receives the Input::TableDescription as the first argument, the
         message as the second argument and the Reporter::Level as the third argument.
         
         The event is raised like if it had been declared as follows:
         error_ev: function(desc: TableDescription, message: string, level: Reporter::Level) &optional;
         The actual declaration uses the ``any`` type because of deficiencies of the Zeek type system.

      config: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         A key/value table that will be passed to the reader.
         Interpretation of the values is left to the reader, but
         usually they will be used for configuration purposes.

   A table input stream type used to send data to a Zeek table.

.. zeek:type:: Input::Reader

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Input::READER_ASCII Input::Reader

      .. zeek:enum:: Input::READER_BENCHMARK Input::Reader

      .. zeek:enum:: Input::READER_BINARY Input::Reader

      .. zeek:enum:: Input::READER_CONFIG Input::Reader

      .. zeek:enum:: Input::READER_RAW Input::Reader

      .. zeek:enum:: Input::READER_SQLITE Input::Reader


Events
######
.. zeek:id:: Input::end_of_data
   :source-code: base/utils/exec.zeek 96 127

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, source: :zeek:type:`string`)

   Event that is called when the end of a data source has been reached,
   including after an update.
   

   :param name: Name of the input stream.
   

   :param source: String that identifies the data source (such as the filename).

Functions
#########
.. zeek:id:: Input::add_analysis
   :source-code: base/frameworks/input/main.zeek 267 270

   :Type: :zeek:type:`function` (description: :zeek:type:`Input::AnalysisDescription`) : :zeek:type:`bool`

   Create a new file analysis input stream from a given source.  Data read
   from the source is automatically forwarded to the file analysis
   framework.
   

   :param description: A record describing the source.
   

   :returns: true on success.

.. zeek:id:: Input::add_event
   :source-code: base/frameworks/input/main.zeek 262 265

   :Type: :zeek:type:`function` (description: :zeek:type:`Input::EventDescription`) : :zeek:type:`bool`

   Create a new event input stream from a given source.
   

   :param description: `EventDescription` record describing the source.
   

   :returns: true on success.

.. zeek:id:: Input::add_table
   :source-code: base/frameworks/input/main.zeek 257 260

   :Type: :zeek:type:`function` (description: :zeek:type:`Input::TableDescription`) : :zeek:type:`bool`

   Create a new table input stream from a given source.
   

   :param description: `TableDescription` record describing the source.
   

   :returns: true on success.

.. zeek:id:: Input::force_update
   :source-code: base/frameworks/input/main.zeek 277 280

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`bool`

   Forces the current input to be checked for changes.
   

   :param id: string value identifying the stream.
   

   :returns: true on success and false if the named stream was not found.

.. zeek:id:: Input::remove
   :source-code: base/frameworks/input/main.zeek 272 275

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`bool`

   Remove an input stream.
   

   :param id: string value identifying the stream to be removed.
   

   :returns: true on success and false if the named stream was not found.


