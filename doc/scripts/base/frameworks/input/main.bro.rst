:tocdepth: 3

base/frameworks/input/main.bro
==============================
.. bro:namespace:: Input

The input framework provides a way to read previously stored data either
as an event stream or into a Bro table.

:Namespace: Input
:Imports: :doc:`base/bif/input.bif.bro </scripts/base/bif/input.bif.bro>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================= ==============================
:bro:id:`Input::default_mode`: :bro:type:`Input::Mode` :bro:attr:`&redef`     The default reader mode used.
:bro:id:`Input::default_reader`: :bro:type:`Input::Reader` :bro:attr:`&redef` The default input reader used.
============================================================================= ==============================

Redefinable Options
###################
============================================================================== =========================================================
:bro:id:`Input::accept_unsupported_types`: :bro:type:`bool` :bro:attr:`&redef` Flag that controls if the input framework accepts records
                                                                               that contain types that are not supported (at the moment
                                                                               file and function).
:bro:id:`Input::empty_field`: :bro:type:`string` :bro:attr:`&redef`            String to use for empty fields.
:bro:id:`Input::separator`: :bro:type:`string` :bro:attr:`&redef`              Separator between fields.
:bro:id:`Input::set_separator`: :bro:type:`string` :bro:attr:`&redef`          Separator between set elements.
:bro:id:`Input::unset_field`: :bro:type:`string` :bro:attr:`&redef`            String to use for an unset &optional field.
============================================================================== =========================================================

Types
#####
========================================================== ===================================================================
:bro:type:`Input::AnalysisDescription`: :bro:type:`record` A file analysis input stream type used to forward input data to the
                                                           file analysis framework.
:bro:type:`Input::Event`: :bro:type:`enum`                 Type that describes what kind of change occurred.
:bro:type:`Input::EventDescription`: :bro:type:`record`    An event input stream type used to send input data to a Bro event.
:bro:type:`Input::Mode`: :bro:type:`enum`                  Type that defines the input stream read mode.
:bro:type:`Input::TableDescription`: :bro:type:`record`    A table input stream type used to send data to a Bro table.
:bro:type:`Input::Reader`: :bro:type:`enum`                
========================================================== ===================================================================

Events
######
=============================================== ====================================================================
:bro:id:`Input::end_of_data`: :bro:type:`event` Event that is called when the end of a data source has been reached,
                                                including after an update.
=============================================== ====================================================================

Functions
#########
=================================================== ============================================================
:bro:id:`Input::add_analysis`: :bro:type:`function` Create a new file analysis input stream from a given source.
:bro:id:`Input::add_event`: :bro:type:`function`    Create a new event input stream from a given source.
:bro:id:`Input::add_table`: :bro:type:`function`    Create a new table input stream from a given source.
:bro:id:`Input::force_update`: :bro:type:`function` Forces the current input to be checked for changes.
:bro:id:`Input::remove`: :bro:type:`function`       Remove an input stream.
=================================================== ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Input::default_mode

   :Type: :bro:type:`Input::Mode`
   :Attributes: :bro:attr:`&redef`
   :Default: ``Input::MANUAL``

   The default reader mode used. Defaults to `MANUAL`.

.. bro:id:: Input::default_reader

   :Type: :bro:type:`Input::Reader`
   :Attributes: :bro:attr:`&redef`
   :Default: ``Input::READER_ASCII``

   The default input reader used. Defaults to `READER_ASCII`.

Redefinable Options
###################
.. bro:id:: Input::accept_unsupported_types

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Flag that controls if the input framework accepts records
   that contain types that are not supported (at the moment
   file and function). If true, the input framework will
   warn in these cases, but continue. If false, it will
   abort. Defaults to false (abort).

.. bro:id:: Input::empty_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields.
   Individual readers can use a different value.

.. bro:id:: Input::separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"\x09"``

   Separator between fields.
   Please note that the separator has to be exactly one character long.
   Individual readers can use a different value.

.. bro:id:: Input::set_separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``","``

   Separator between set elements.
   Please note that the separator has to be exactly one character long.
   Individual readers can use a different value.

.. bro:id:: Input::unset_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.
   Individual readers can use a different value.

Types
#####
.. bro:type:: Input::AnalysisDescription

   :Type: :bro:type:`record`

      source: :bro:type:`string`
         String that allows the reader to find the source.
         For `READER_ASCII`, this is the filename.

      reader: :bro:type:`Input::Reader` :bro:attr:`&default` = ``Input::READER_BINARY`` :bro:attr:`&optional`
         Reader to use for this stream.  Compatible readers must be
         able to accept a filter of a single string type (i.e.
         they read a byte stream).

      mode: :bro:type:`Input::Mode` :bro:attr:`&default` = :bro:see:`Input::default_mode` :bro:attr:`&optional`
         Read mode to use for this stream.

      name: :bro:type:`string`
         Descriptive name that uniquely identifies the input source.
         Can be used to remove a stream at a later time.
         This will also be used for the unique *source* field of
         :bro:see:`fa_file`.  Most of the time, the best choice for this
         field will be the same value as the *source* field.

      config: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         A key/value table that will be passed to the reader.
         Interpretation of the values is left to the reader, but
         usually they will be used for configuration purposes.

   A file analysis input stream type used to forward input data to the
   file analysis framework.

.. bro:type:: Input::Event

   :Type: :bro:type:`enum`

      .. bro:enum:: Input::EVENT_NEW Input::Event

         New data has been imported.

      .. bro:enum:: Input::EVENT_CHANGED Input::Event

         Existing data has been changed.

      .. bro:enum:: Input::EVENT_REMOVED Input::Event

         Previously existing data has been removed.

   Type that describes what kind of change occurred.

.. bro:type:: Input::EventDescription

   :Type: :bro:type:`record`

      source: :bro:type:`string`
         String that allows the reader to find the source.
         For `READER_ASCII`, this is the filename.

      reader: :bro:type:`Input::Reader` :bro:attr:`&default` = :bro:see:`Input::default_reader` :bro:attr:`&optional`
         Reader to use for this stream.

      mode: :bro:type:`Input::Mode` :bro:attr:`&default` = :bro:see:`Input::default_mode` :bro:attr:`&optional`
         Read mode to use for this stream.

      name: :bro:type:`string`
         Descriptive name. Used to remove a stream at a later time.

      fields: :bro:type:`any`
         Record type describing the fields to be retrieved from the input
         source.

      want_record: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         If this is false, the event receives each value in *fields* as a
         separate argument.
         If this is set to true (default), the event receives all fields in
         a single record value.

      ev: :bro:type:`any`
         The event that is raised each time a new line is received from the
         reader. The event will receive an Input::EventDescription record
         as the first argument, an Input::Event enum as the second
         argument, and the fields (as specified in *fields*) as the following
         arguments (this will either be a single record value containing
         all fields, or each field value as a separate argument).

      error_ev: :bro:type:`any` :bro:attr:`&optional`
         Error event that is raised when an information, warning or error
         is raised by the input stream. If the level is error, the stream will automatically
         be closed.
         The event receives the Input::EventDescription as the first argument, the
         message as the second argument and the Reporter::Level as the third argument.
         
         The event is raised like it had been declared as follows:
         error_ev: function(desc: EventDescription, message: string, level: Reporter::Level) &optional;
         The actual declaration uses the ``any`` type because of deficiencies of the Bro type system.

      config: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         A key/value table that will be passed to the reader.
         Interpretation of the values is left to the reader, but
         usually they will be used for configuration purposes.

   An event input stream type used to send input data to a Bro event.

.. bro:type:: Input::Mode

   :Type: :bro:type:`enum`

      .. bro:enum:: Input::MANUAL Input::Mode

         Do not automatically reread the file after it has been read.

      .. bro:enum:: Input::REREAD Input::Mode

         Reread the entire file each time a change is found.

      .. bro:enum:: Input::STREAM Input::Mode

         Read data from end of file each time new data is appended.

   Type that defines the input stream read mode.

.. bro:type:: Input::TableDescription

   :Type: :bro:type:`record`

      source: :bro:type:`string`
         String that allows the reader to find the source of the data.
         For `READER_ASCII`, this is the filename.

      reader: :bro:type:`Input::Reader` :bro:attr:`&default` = :bro:see:`Input::default_reader` :bro:attr:`&optional`
         Reader to use for this stream.

      mode: :bro:type:`Input::Mode` :bro:attr:`&default` = :bro:see:`Input::default_mode` :bro:attr:`&optional`
         Read mode to use for this stream.

      name: :bro:type:`string`
         Name of the input stream.  This is used by some functions to
         manipulate the stream.

      destination: :bro:type:`any`
         Table which will receive the data read by the input framework.

      idx: :bro:type:`any`
         Record that defines the values used as the index of the table.

      val: :bro:type:`any` :bro:attr:`&optional`
         Record that defines the values used as the elements of the table.
         If this is undefined, then *destination* must be a set.

      want_record: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Defines if the value of the table is a record (default), or a single
         value. When this is set to false, then *val* can only contain one
         element.

      ev: :bro:type:`any` :bro:attr:`&optional`
         The event that is raised each time a value is added to, changed in,
         or removed from the table. The event will receive an
         Input::TableDescription as the first argument, an Input::Event
         enum as the second argument, the *idx* record as the third argument
         and the value (record) as the fourth argument.

      pred: :bro:type:`function` (typ: :bro:type:`Input::Event`, left: :bro:type:`any`, right: :bro:type:`any`) : :bro:type:`bool` :bro:attr:`&optional`
         Predicate function that can decide if an insertion, update or removal
         should really be executed. Parameters have same meaning as for the
         event.
         If true is returned, the update is performed. If false is returned,
         it is skipped.

      error_ev: :bro:type:`any` :bro:attr:`&optional`
         Error event that is raised when an information, warning or error
         is raised by the input stream. If the level is error, the stream will automatically
         be closed.
         The event receives the Input::TableDescription as the first argument, the
         message as the second argument and the Reporter::Level as the third argument.
         
         The event is raised like if it had been declared as follows:
         error_ev: function(desc: TableDescription, message: string, level: Reporter::Level) &optional;
         The actual declaration uses the ``any`` type because of deficiencies of the Bro type system.

      config: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         A key/value table that will be passed to the reader.
         Interpretation of the values is left to the reader, but
         usually they will be used for configuration purposes.

   A table input stream type used to send data to a Bro table.

.. bro:type:: Input::Reader

   :Type: :bro:type:`enum`

      .. bro:enum:: Input::READER_ASCII Input::Reader

      .. bro:enum:: Input::READER_BENCHMARK Input::Reader

      .. bro:enum:: Input::READER_BINARY Input::Reader

      .. bro:enum:: Input::READER_CONFIG Input::Reader

      .. bro:enum:: Input::READER_RAW Input::Reader

      .. bro:enum:: Input::READER_SQLITE Input::Reader


Events
######
.. bro:id:: Input::end_of_data

   :Type: :bro:type:`event` (name: :bro:type:`string`, source: :bro:type:`string`)

   Event that is called when the end of a data source has been reached,
   including after an update.
   

   :name: Name of the input stream.
   

   :source: String that identifies the data source (such as the filename).

Functions
#########
.. bro:id:: Input::add_analysis

   :Type: :bro:type:`function` (description: :bro:type:`Input::AnalysisDescription`) : :bro:type:`bool`

   Create a new file analysis input stream from a given source.  Data read
   from the source is automatically forwarded to the file analysis
   framework.
   

   :description: A record describing the source.
   

   :returns: true on success.

.. bro:id:: Input::add_event

   :Type: :bro:type:`function` (description: :bro:type:`Input::EventDescription`) : :bro:type:`bool`

   Create a new event input stream from a given source.
   

   :description: `EventDescription` record describing the source.
   

   :returns: true on success.

.. bro:id:: Input::add_table

   :Type: :bro:type:`function` (description: :bro:type:`Input::TableDescription`) : :bro:type:`bool`

   Create a new table input stream from a given source.
   

   :description: `TableDescription` record describing the source.
   

   :returns: true on success.

.. bro:id:: Input::force_update

   :Type: :bro:type:`function` (id: :bro:type:`string`) : :bro:type:`bool`

   Forces the current input to be checked for changes.
   

   :id: string value identifying the stream.
   

   :returns: true on success and false if the named stream was not found.

.. bro:id:: Input::remove

   :Type: :bro:type:`function` (id: :bro:type:`string`) : :bro:type:`bool`

   Remove an input stream.
   

   :id: string value identifying the stream to be removed.
   

   :returns: true on success and false if the named stream was not found.


