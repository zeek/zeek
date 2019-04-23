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
======================================= =
:zeek:type:`Log::ID`: :zeek:type:`enum` 
======================================= =

Events
######
=============================================== ==================================================================
:zeek:id:`Intel::log_intel`: :zeek:type:`event` 
:zeek:id:`Intel::match`: :zeek:type:`event`     Event to represent a match in the intelligence data from data that
                                                was seen.
=============================================== ==================================================================

Hooks
#####
================================================= =======================================================================
:zeek:id:`Intel::extend_match`: :zeek:type:`hook` This hook can be used to influence the logging of intelligence hits
                                                  (e.g.
:zeek:id:`Intel::filter_item`: :zeek:type:`hook`  This hook can be used to filter intelligence items that are about to be
                                                  inserted into the internal data store.
:zeek:id:`Intel::item_expired`: :zeek:type:`hook` This hook can be used to handle expiration of intelligence items.
================================================= =======================================================================

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

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 mins``

   The expiration timeout for intelligence items. Once an item expires, the
   :zeek:id:`Intel::item_expired` hook is called. Reinsertion of an item 
   resets the timeout. A negative value disables expiration of intelligence 
   items.

Types
#####
.. zeek:type:: Intel::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp when the data was discovered.

      uid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         If a connection was associated with this intelligence hit,
         this is the uid for the connection

      id: :zeek:type:`conn_id` :zeek:attr:`&log` :zeek:attr:`&optional`
         If a connection was associated with this intelligence hit,
         this is the conn_id for the connection.

      seen: :zeek:type:`Intel::Seen` :zeek:attr:`&log`
         Where the data was seen.

      matched: :zeek:type:`Intel::TypeSet` :zeek:attr:`&log`
         Which indicator types matched.

      sources: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Sources which supplied data that resulted in this match.

      fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

         If a file was associated with this intelligence hit,
         this is the uid for the file.

      file_mime_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

         A mime type if the intelligence hit is related to a file.
         If the $f field is provided this will be automatically filled
         out.

      file_desc: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

         Frequently files can be "described" to give a bit more context.
         If the $f field is provided this field will be automatically
         filled out.

   Record used for the logging framework representing a positive
   hit within the intelligence framework.

.. zeek:type:: Intel::Item

   :Type: :zeek:type:`record`

      indicator: :zeek:type:`string`
         The intelligence indicator.

      indicator_type: :zeek:type:`Intel::Type`
         The type of data that the indicator field represents.

      meta: :zeek:type:`Intel::MetaData`
         Metadata for the item. Typically represents more deeply
         descriptive data for a piece of intelligence.

   Represents a piece of intelligence.

.. zeek:type:: Intel::MetaData

   :Type: :zeek:type:`record`

      source: :zeek:type:`string`
         An arbitrary string value representing the data source. This
         value is used as unique key to identify a metadata record in
         the scope of a single intelligence item.

      desc: :zeek:type:`string` :zeek:attr:`&optional`
         A freeform description for the data.

      url: :zeek:type:`string` :zeek:attr:`&optional`
         A URL for more information about the data.

      do_notice: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/intel/do_notice.zeek` is loaded)

         A boolean value to allow the data itself to represent
         if the indicator that this metadata is attached to
         is notice worthy.

      if_in: :zeek:type:`Intel::Where` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/intel/do_notice.zeek` is loaded)

         Restrictions on when notices are created to only create
         them if the *do_notice* field is T and the notice was
         seen in the indicated location.

      whitelist: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/intel/whitelist.zeek` is loaded)

         A boolean value to indicate whether the item is whitelisted.

      remove: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/intel/removal.zeek` is loaded)

         A boolean value to indicate whether the item should be removed.

      cif_impact: :zeek:type:`string` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

         Maps to the Impact field in the Collective Intelligence Framework.

      cif_severity: :zeek:type:`string` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

         Maps to the Severity field in the Collective Intelligence Framework.

      cif_confidence: :zeek:type:`double` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/integration/collective-intel/main.zeek` is loaded)

         Maps to the Confidence field in the Collective Intelligence Framework.

   Data about an :zeek:type:`Intel::Item`.

.. zeek:type:: Intel::Seen

   :Type: :zeek:type:`record`

      indicator: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The string if the data is about a string.

      indicator_type: :zeek:type:`Intel::Type` :zeek:attr:`&log` :zeek:attr:`&optional`
         The type of data that the indicator represents.

      host: :zeek:type:`addr` :zeek:attr:`&optional`
         If the indicator type was :zeek:enum:`Intel::ADDR`, then this
         field will be present.

      where: :zeek:type:`Intel::Where` :zeek:attr:`&log`
         Where the data was discovered.

      node: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         The name of the node where the match was discovered.

      conn: :zeek:type:`connection` :zeek:attr:`&optional`
         If the data was discovered within a connection, the
         connection record should go here to give context to the data.

      uid: :zeek:type:`string` :zeek:attr:`&optional`
         If the data was discovered within a connection, the
         connection uid should go here to give context to the data.
         If the *conn* field is provided, this will be automatically
         filled out.

      f: :zeek:type:`fa_file` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

         If the data was discovered within a file, the file record
         should go here to provide context to the data.

      fuid: :zeek:type:`string` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.zeek` is loaded)

         If the data was discovered within a file, the file uid should
         go here to provide context to the data. If the file record *f*
         is provided, this will be automatically filled out.

   Information about a piece of "seen" data.

.. zeek:type:: Intel::Type

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

         Public key MD5 hash. (SSH server host keys are a good example.)

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

   :Type: :zeek:type:`set` [:zeek:type:`Intel::Type`]

   Set of intelligence data types.

.. zeek:type:: Intel::Where

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

   :Type: :zeek:type:`event` (rec: :zeek:type:`Intel::Info`)


.. zeek:id:: Intel::match

   :Type: :zeek:type:`event` (s: :zeek:type:`Intel::Seen`, items: :zeek:type:`set` [:zeek:type:`Intel::Item`])

   Event to represent a match in the intelligence data from data that
   was seen. On clusters there is no assurance as to when this event
   will be generated so do not assume that arbitrary global state beyond
   the given data will be available.
   
   This is the primary mechanism where a user may take actions based on
   data provided by the intelligence framework.

Hooks
#####
.. zeek:id:: Intel::extend_match

   :Type: :zeek:type:`hook` (info: :zeek:type:`Intel::Info`, s: :zeek:type:`Intel::Seen`, items: :zeek:type:`set` [:zeek:type:`Intel::Item`]) : :zeek:type:`bool`

   This hook can be used to influence the logging of intelligence hits
   (e.g. by adding data to the Info record). The default information is
   added with a priority of 5.
   

   :info: The Info record that will be logged.
   

   :s: Information about the data seen.
   

   :items: The intel items that match the seen data.
   
   In case the hook execution is terminated using break, the match will
   not be logged.

.. zeek:id:: Intel::filter_item

   :Type: :zeek:type:`hook` (item: :zeek:type:`Intel::Item`) : :zeek:type:`bool`

   This hook can be used to filter intelligence items that are about to be
   inserted into the internal data store. In case the hook execution is
   terminated using break, the item will not be (re)added to the internal
   data store.
   

   :item: The intel item that should be inserted.

.. zeek:id:: Intel::item_expired

   :Type: :zeek:type:`hook` (indicator: :zeek:type:`string`, indicator_type: :zeek:type:`Intel::Type`, metas: :zeek:type:`set` [:zeek:type:`Intel::MetaData`]) : :zeek:type:`bool`

   This hook can be used to handle expiration of intelligence items.
   

   :indicator: The indicator of the expired item.
   

   :indicator_type: The indicator type of the expired item.
   

   :metas: The set of metadata describing the expired item.
   
   If all hook handlers are executed, the expiration timeout will be reset.
   Otherwise, if one of the handlers terminates using break, the item will
   be removed.

Functions
#########
.. zeek:id:: Intel::insert

   :Type: :zeek:type:`function` (item: :zeek:type:`Intel::Item`) : :zeek:type:`void`

   Function to insert intelligence data. If the indicator is already
   present, the associated metadata will be added to the indicator. If
   the indicator already contains a metadata record from the same source,
   the existing metadata record will be updated.

.. zeek:id:: Intel::remove

   :Type: :zeek:type:`function` (item: :zeek:type:`Intel::Item`, purge_indicator: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`void`

   Function to remove intelligence data. If purge_indicator is set, the
   given metadata is ignored and the indicator is removed completely.

.. zeek:id:: Intel::seen

   :Type: :zeek:type:`function` (s: :zeek:type:`Intel::Seen`) : :zeek:type:`void`

   Function to declare discovery of a piece of data in order to check
   it against known intelligence for matches.


