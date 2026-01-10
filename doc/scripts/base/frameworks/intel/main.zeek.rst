:tocdepth: 3

base/frameworks/intel/main.zeek
===============================
.. zeek:namespace:: Intel

The intelligence framework provides a way to store and query intelligence
data (e.g. IP addresses, URLs and hashes). The intelligence items can be
associated with metadata to allow informed decisions about matching and
handling.

:Namespace: Intel
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ ==============================================
:zeek:id:`Intel::item_expiration`: :zeek:type:`interval` :zeek:attr:`&redef` The expiration timeout for intelligence items.
============================================================================ ==============================================

Types
#####
================================================= ==============================================================
:zeek:type:`Intel::Info`: :zeek:type:`record`     Record used for the logging framework representing a positive
                                                  hit within the intelligence framework.
:zeek:type:`Intel::Item`: :zeek:type:`record`     Represents a piece of intelligence.
:zeek:type:`Intel::MetaData`: :zeek:type:`record` Data about an :zeek:type:`Intel::Item`.
:zeek:type:`Intel::Seen`: :zeek:type:`record`     Information about a piece of "seen" data.
:zeek:type:`Intel::Type`: :zeek:type:`enum`       Enum type to represent various types of intelligence data.
:zeek:type:`Intel::TypeSet`: :zeek:type:`set`     Set of intelligence data types.
:zeek:type:`Intel::Where`: :zeek:type:`enum`      Enum to represent where data came from when it was discovered.
================================================= ==============================================================

Redefinitions
#############
======================================= =========================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                        * :zeek:enum:`Intel::LOG`
======================================= =========================

Events
######
=============================================== ==================================================================
:zeek:id:`Intel::log_intel`: :zeek:type:`event`
:zeek:id:`Intel::match`: :zeek:type:`event`     Event to represent a match in the intelligence data from data that
                                                was seen.
=============================================== ==================================================================

Hooks
#####
========================================================== =======================================================================
:zeek:id:`Intel::extend_match`: :zeek:type:`hook`          This hook can be used to influence the logging of intelligence hits
                                                           (e.g.
:zeek:id:`Intel::filter_item`: :zeek:type:`hook`           This hook can be used to filter intelligence items that are about to be
                                                           inserted into the internal data store.
:zeek:id:`Intel::indicator_inserted`: :zeek:type:`hook`    This hook is invoked when a new indicator has been inserted into
                                                           the min data store for the first time.
:zeek:id:`Intel::indicator_removed`: :zeek:type:`hook`     This hook is invoked when an indicator has been removed from
                                                           the min data store.
:zeek:id:`Intel::item_expired`: :zeek:type:`hook`          This hook can be used to handle expiration of intelligence items.
:zeek:id:`Intel::log_policy`: :zeek:type:`Log::PolicyHook`
:zeek:id:`Intel::seen_policy`: :zeek:type:`hook`           Hook to modify and intercept :zeek:see:`Intel::seen` behavior.
========================================================== =======================================================================

Functions
#########
=============================================== ==================================================================
:zeek:id:`Intel::insert`: :zeek:type:`function` Function to insert intelligence data.
:zeek:id:`Intel::remove`: :zeek:type:`function` Function to remove intelligence data.
:zeek:id:`Intel::seen`: :zeek:type:`function`   Function to declare discovery of a piece of data in order to check
                                                it against known intelligence for matches.
=============================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Intel::item_expiration
   :source-code: base/frameworks/intel/main.zeek 187 187

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``-1.0 min``
   :Redefinition: from :doc:`/scripts/policy/frameworks/intel/do_expire.zeek`

      ``=``::

         ``10.0 mins``


   The expiration timeout for intelligence items. Once an item expires, the
   :zeek:id:`Intel::item_expired` hook is called. Reinsertion of an item
   resets the timeout. A negative value disables expiration of intelligence
   items.

Types
#####
.. zeek:type:: Intel::Info
   :source-code: base/frameworks/intel/main.zeek 104 121

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp when the data was discovered.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      If a connection was associated with this intelligence hit,
      this is the uid for the connection


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log` :zeek:attr:`&optional`

      If a connection was associated with this intelligence hit,
      this is the conn_id for the connection.


   .. zeek:field:: seen :zeek:type:`Intel::Seen` :zeek:attr:`&log`

      Where the data was seen.


   .. zeek:field:: matched :zeek:type:`Intel::TypeSet` :zeek:attr:`&log`

      Which indicator types matched.


   .. zeek:field:: sources :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`

      Sources which supplied data that resulted in this match.


   .. zeek:field:: fuid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

      If a file was associated with this intelligence hit,
      this is the uid for the file.


   .. zeek:field:: file_mime_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

      A mime type if the intelligence hit is related to a file.
      If the $f field is provided this will be automatically filled
      out.


   .. zeek:field:: file_desc :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

      Frequently files can be "described" to give a bit more context.
      If the $f field is provided this field will be automatically
      filled out.


   .. zeek:field:: cif :zeek:type:`Intel::CIF` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)


   Record used for the logging framework representing a positive
   hit within the intelligence framework.

.. zeek:type:: Intel::Item
   :source-code: base/frameworks/intel/main.zeek 54 64

   :Type: :zeek:type:`record`


   .. zeek:field:: indicator :zeek:type:`string`

      The intelligence indicator.


   .. zeek:field:: indicator_type :zeek:type:`Intel::Type`

      The type of data that the indicator field represents.


   .. zeek:field:: meta :zeek:type:`Intel::MetaData`

      Metadata for the item. Typically represents more deeply
      descriptive data for a piece of intelligence.


   Represents a piece of intelligence.

.. zeek:type:: Intel::MetaData
   :source-code: base/frameworks/intel/main.zeek 42 51

   :Type: :zeek:type:`record`


   .. zeek:field:: source :zeek:type:`string`

      An arbitrary string value representing the data source. This
      value is used as unique key to identify a metadata record in
      the scope of a single intelligence item.


   .. zeek:field:: desc :zeek:type:`string` :zeek:attr:`&optional`

      A freeform description for the data.


   .. zeek:field:: url :zeek:type:`string` :zeek:attr:`&optional`

      A URL for more information about the data.


   .. zeek:field:: do_notice :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/frameworks/intel/do_notice.zeek` is loaded)

      A boolean value to allow the data itself to represent
      if the indicator that this metadata is attached to
      is notice worthy.


   .. zeek:field:: if_in :zeek:type:`Intel::Where` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/frameworks/intel/do_notice.zeek` is loaded)

      Restrictions on when notices are created to only create
      them if the *do_notice* field is T and the notice was
      seen in the indicated location.


   .. zeek:field:: whitelist :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/frameworks/intel/whitelist.zeek` is loaded)

      A boolean value to indicate whether the item is whitelisted.


   .. zeek:field:: remove :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/frameworks/intel/removal.zeek` is loaded)

      A boolean value to indicate whether the item should be removed.


   .. zeek:field:: cif_tags :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

      Maps to the 'tags' fields in CIF


   .. zeek:field:: cif_confidence :zeek:type:`double` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

      Maps to the 'confidence' field in CIF


   .. zeek:field:: cif_source :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

      Maps to the 'source' field in CIF


   .. zeek:field:: cif_description :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

      Maps to the 'description' field in CIF


   .. zeek:field:: cif_firstseen :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

      Maps to the 'firstseen' field in CIF


   .. zeek:field:: cif_lastseen :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

      Maps to the 'lastseen' field in CIF


   Data about an :zeek:type:`Intel::Item`.

.. zeek:type:: Intel::Seen
   :source-code: base/frameworks/intel/main.zeek 74 100

   :Type: :zeek:type:`record`


   .. zeek:field:: indicator :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The string if the data is about a string.


   .. zeek:field:: indicator_type :zeek:type:`Intel::Type` :zeek:attr:`&log` :zeek:attr:`&optional`

      The type of data that the indicator represents.


   .. zeek:field:: host :zeek:type:`addr` :zeek:attr:`&optional`

      If the indicator type was :zeek:enum:`Intel::ADDR`, then this
      field will be present.


   .. zeek:field:: where :zeek:type:`Intel::Where` :zeek:attr:`&log`

      Where the data was discovered.


   .. zeek:field:: node :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      The name of the node where the match was discovered.


   .. zeek:field:: conn :zeek:type:`connection` :zeek:attr:`&optional`

      If the data was discovered within a connection, the
      connection record should go here to give context to the data.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&optional`

      If the data was discovered within a connection, the
      connection uid should go here to give context to the data.
      If the *conn* field is provided, this will be automatically
      filled out.


   .. zeek:field:: f :zeek:type:`fa_file` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

      If the data was discovered within a file, the file record
      should go here to provide context to the data.


   .. zeek:field:: fuid :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

      If the data was discovered within a file, the file uid should
      go here to provide context to the data. If the file record *f*
      is provided, this will be automatically filled out.


   Information about a piece of "seen" data.

.. zeek:type:: Intel::Type
   :source-code: base/frameworks/intel/main.zeek 16 37

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Intel::ADDR Intel::Type

         An IP address.

      .. zeek:enum:: Intel::SUBNET Intel::Type

         A subnet in CIDR notation.

      .. zeek:enum:: Intel::URL Intel::Type

         A complete URL without the prefix ``"http://"``.

      .. zeek:enum:: Intel::SOFTWARE Intel::Type

         Software name.

      .. zeek:enum:: Intel::EMAIL Intel::Type

         Email address.

      .. zeek:enum:: Intel::DOMAIN Intel::Type

         DNS domain name.

      .. zeek:enum:: Intel::USER_NAME Intel::Type

         A user name.

      .. zeek:enum:: Intel::CERT_HASH Intel::Type

         Certificate SHA-1 hash.

      .. zeek:enum:: Intel::PUBKEY_HASH Intel::Type

         Public key MD5 hash, formatted as hexadecimal digits delimited by colons.
         (SSH server host keys are a good example.)

      .. zeek:enum:: Intel::FILE_HASH Intel::Type

         (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)


         File hash which is non-hash type specific.  It's up to the
         user to query for any relevant hash types.

      .. zeek:enum:: Intel::FILE_NAME Intel::Type

         (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)


         File name.  Typically with protocols with definite
         indications of a file name.

   Enum type to represent various types of intelligence data.

.. zeek:type:: Intel::TypeSet
   :source-code: base/frameworks/intel/main.zeek 39 39

   :Type: :zeek:type:`set` [:zeek:type:`Intel::Type`]

   Set of intelligence data types.

.. zeek:type:: Intel::Where
   :source-code: base/frameworks/intel/main.zeek 68 72

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Intel::IN_ANYWHERE Intel::Where

         A catchall value to represent data of unknown provenance.

      .. zeek:enum:: Conn::IN_ORIG Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: Conn::IN_RESP Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: Files::IN_HASH Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: Files::IN_NAME Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: DNS::IN_REQUEST Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: DNS::IN_RESPONSE Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: HTTP::IN_HOST_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: HTTP::IN_REFERRER_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: HTTP::IN_USER_AGENT_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: HTTP::IN_X_FORWARDED_FOR_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: HTTP::IN_URL Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_MAIL_FROM Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_RCPT_TO Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_FROM Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_TO Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_CC Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_RECEIVED_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_REPLY_TO Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_X_ORIGINATING_IP_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_MESSAGE Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SSH::IN_SERVER_HOST_KEY Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SSL::IN_SERVER_NAME Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMTP::IN_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: X509::IN_CERT Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SMB::IN_FILE_NAME Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.zeek` is loaded)


      .. zeek:enum:: SSH::SUCCESSFUL_LOGIN Intel::Where

         (present if :doc:`/scripts/policy/protocols/ssh/detect-bruteforcing.zeek` is loaded)


         An indicator of the login for the intel framework.

   Enum to represent where data came from when it was discovered.
   The convention is to prefix the name with ``IN_``.

Events
######
.. zeek:id:: Intel::log_intel
   :source-code: base/frameworks/intel/main.zeek 239 239

   :Type: :zeek:type:`event` (rec: :zeek:type:`Intel::Info`)


.. zeek:id:: Intel::match
   :source-code: base/frameworks/intel/main.zeek 146 146

   :Type: :zeek:type:`event` (s: :zeek:type:`Intel::Seen`, items: :zeek:type:`set` [:zeek:type:`Intel::Item`])

   Event to represent a match in the intelligence data from data that
   was seen. On clusters there is no assurance as to when this event
   will be generated so do not assume that arbitrary global state beyond
   the given data will be available.

   This is the primary mechanism where a user may take actions based on
   data provided by the intelligence framework.

   .. zeek::see:: Intel::seen_policy

Hooks
#####
.. zeek:id:: Intel::extend_match
   :source-code: base/frameworks/intel/main.zeek 160 160

   :Type: :zeek:type:`hook` (info: :zeek:type:`Intel::Info`, s: :zeek:type:`Intel::Seen`, items: :zeek:type:`set` [:zeek:type:`Intel::Item`]) : :zeek:type:`bool`

   This hook can be used to influence the logging of intelligence hits
   (e.g. by adding data to the Info record). The default information is
   added with a priority of 5.


   :param info: The Info record that will be logged.


   :param s: Information about the data seen.


   :param items: The intel items that match the seen data.

   In case the hook execution is terminated using break, the match will
   not be logged.

.. zeek:id:: Intel::filter_item
   :source-code: policy/frameworks/intel/removal.zeek 14 22

   :Type: :zeek:type:`hook` (item: :zeek:type:`Intel::Item`) : :zeek:type:`bool`

   This hook can be used to filter intelligence items that are about to be
   inserted into the internal data store. In case the hook execution is
   terminated using break, the item will not be (re)added to the internal
   data store.


   :param item: The intel item that should be inserted.

.. zeek:id:: Intel::indicator_inserted
   :source-code: policy/frameworks/intel/seen/manage-event-groups.zeek 42 57

   :Type: :zeek:type:`hook` (indicator: :zeek:type:`string`, indiator_type: :zeek:type:`Intel::Type`) : :zeek:type:`bool`

   This hook is invoked when a new indicator has been inserted into
   the min data store for the first time.

   Calls to :zeek:see:`Intel::seen` with a matching indicator value
   and type will result in matches.

   Subsequent inserts of the same indicator type and value do not
   invoke this hook. Breaking from this hook has no effect.


   :param indicator: The indicator value.


   :param indicator_type: The indicator type.

   .. zeek::see:: Intel::indicator_removed

.. zeek:id:: Intel::indicator_removed
   :source-code: policy/frameworks/intel/seen/manage-event-groups.zeek 59 74

   :Type: :zeek:type:`hook` (indicator: :zeek:type:`string`, indiator_type: :zeek:type:`Intel::Type`) : :zeek:type:`bool`

   This hook is invoked when an indicator has been removed from
   the min data store.

   After this hooks runs, :zeek:see:`Intel::seen` for the indicator
   will not return any matches. Breaking from this hook has no effect.


   :param indicator: The indicator value.


   :param indicator_type: The indicator type.

   .. zeek::see:: Intel::indicator_inserted

.. zeek:id:: Intel::item_expired
   :source-code: policy/frameworks/intel/do_expire.zeek 10 14

   :Type: :zeek:type:`hook` (indicator: :zeek:type:`string`, indicator_type: :zeek:type:`Intel::Type`, metas: :zeek:type:`set` [:zeek:type:`Intel::MetaData`]) : :zeek:type:`bool`

   This hook can be used to handle expiration of intelligence items.


   :param indicator: The indicator of the expired item.


   :param indicator_type: The indicator type of the expired item.


   :param metas: The set of metadata describing the expired item.

   If all hook handlers are executed, the expiration timeout will be reset.
   Otherwise, if one of the handlers terminates using break, the item will
   be removed.

.. zeek:id:: Intel::log_policy
   :source-code: base/frameworks/intel/main.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`


.. zeek:id:: Intel::seen_policy
   :source-code: base/frameworks/intel/main.zeek 181 181

   :Type: :zeek:type:`hook` (s: :zeek:type:`Intel::Seen`, found: :zeek:type:`bool`) : :zeek:type:`bool`

   Hook to modify and intercept :zeek:see:`Intel::seen` behavior.

   This hook is invoked after the Intel datastore was searched for
   a given :zeek:see:`Intel::Seen` instance. If a matching entry was
   found, the *found* argument is set to ``T``, else ``F``.

   Breaking from this hook suppresses :zeek:see:`Intel::match`
   event generation and any subsequent logging.

   Note that this hook only runs on the Zeek node where :zeek:see:`Intel::seen`
   is invoked. In a cluster configuration that is usually on the worker nodes.
   This is in contrast to :zeek:see:`Intel::match` that usually runs
   centrally on the the manager node instead.


   :param s: The :zeek:see:`Intel::Seen` instance passed to the :zeek:see:`Intel::seen` function.


   :param found: ``T`` if Intel datastore contained *s*, else ``F``.

   .. zeek::see:: Intel::match

Functions
#########
.. zeek:id:: Intel::insert
   :source-code: base/frameworks/intel/main.zeek 596 603

   :Type: :zeek:type:`function` (item: :zeek:type:`Intel::Item`) : :zeek:type:`void`

   Function to insert intelligence data. If the indicator is already
   present, the associated metadata will be added to the indicator. If
   the indicator already contains a metadata record from the same source,
   the existing metadata record will be updated.

.. zeek:id:: Intel::remove
   :source-code: base/frameworks/intel/main.zeek 649 688

   :Type: :zeek:type:`function` (item: :zeek:type:`Intel::Item`, purge_indicator: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`void`

   Function to remove intelligence data. If purge_indicator is set, the
   given metadata is ignored and the indicator is removed completely.

.. zeek:id:: Intel::seen
   :source-code: base/frameworks/intel/main.zeek 405 433

   :Type: :zeek:type:`function` (s: :zeek:type:`Intel::Seen`) : :zeek:type:`void`

   Function to declare discovery of a piece of data in order to check
   it against known intelligence for matches.


