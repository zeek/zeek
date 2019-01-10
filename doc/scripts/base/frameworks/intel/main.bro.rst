:tocdepth: 3

base/frameworks/intel/main.bro
==============================
.. bro:namespace:: Intel

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
========================================================================= ==============================================
:bro:id:`Intel::item_expiration`: :bro:type:`interval` :bro:attr:`&redef` The expiration timeout for intelligence items.
========================================================================= ==============================================

Types
#####
=============================================== ==============================================================
:bro:type:`Intel::Info`: :bro:type:`record`     Record used for the logging framework representing a positive
                                                hit within the intelligence framework.
:bro:type:`Intel::Item`: :bro:type:`record`     Represents a piece of intelligence.
:bro:type:`Intel::MetaData`: :bro:type:`record` Data about an :bro:type:`Intel::Item`.
:bro:type:`Intel::Seen`: :bro:type:`record`     Information about a piece of "seen" data.
:bro:type:`Intel::Type`: :bro:type:`enum`       Enum type to represent various types of intelligence data.
:bro:type:`Intel::TypeSet`: :bro:type:`set`     Set of intelligence data types.
:bro:type:`Intel::Where`: :bro:type:`enum`      Enum to represent where data came from when it was discovered.
=============================================== ==============================================================

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
============================================= ==================================================================
:bro:id:`Intel::log_intel`: :bro:type:`event` 
:bro:id:`Intel::match`: :bro:type:`event`     Event to represent a match in the intelligence data from data that
                                              was seen.
============================================= ==================================================================

Hooks
#####
=============================================== ===================================================================
:bro:id:`Intel::extend_match`: :bro:type:`hook` This hook can be used to influence the logging of intelligence hits
                                                (e.g.
:bro:id:`Intel::item_expired`: :bro:type:`hook` This hook can be used to handle expiration of intelligence items.
=============================================== ===================================================================

Functions
#########
============================================= ==================================================================
:bro:id:`Intel::insert`: :bro:type:`function` Function to insert intelligence data.
:bro:id:`Intel::remove`: :bro:type:`function` Function to remove intelligence data.
:bro:id:`Intel::seen`: :bro:type:`function`   Function to declare discovery of a piece of data in order to check
                                              it against known intelligence for matches.
============================================= ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Intel::item_expiration

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 mins``

   The expiration timeout for intelligence items. Once an item expires, the
   :bro:id:`Intel::item_expired` hook is called. Reinsertion of an item 
   resets the timeout. A negative value disables expiration of intelligence 
   items.

Types
#####
.. bro:type:: Intel::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp when the data was discovered.

      uid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         If a connection was associated with this intelligence hit,
         this is the uid for the connection

      id: :bro:type:`conn_id` :bro:attr:`&log` :bro:attr:`&optional`
         If a connection was associated with this intelligence hit,
         this is the conn_id for the connection.

      seen: :bro:type:`Intel::Seen` :bro:attr:`&log`
         Where the data was seen.

      matched: :bro:type:`Intel::TypeSet` :bro:attr:`&log`
         Which indicator types matched.

      sources: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         Sources which supplied data that resulted in this match.

      fuid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.bro` is loaded)

         If a file was associated with this intelligence hit,
         this is the uid for the file.

      file_mime_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.bro` is loaded)

         A mime type if the intelligence hit is related to a file.
         If the $f field is provided this will be automatically filled
         out.

      file_desc: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.bro` is loaded)

         Frequently files can be "described" to give a bit more context.
         If the $f field is provided this field will be automatically
         filled out.

   Record used for the logging framework representing a positive
   hit within the intelligence framework.

.. bro:type:: Intel::Item

   :Type: :bro:type:`record`

      indicator: :bro:type:`string`
         The intelligence indicator.

      indicator_type: :bro:type:`Intel::Type`
         The type of data that the indicator field represents.

      meta: :bro:type:`Intel::MetaData`
         Metadata for the item. Typically represents more deeply
         descriptive data for a piece of intelligence.

   Represents a piece of intelligence.

.. bro:type:: Intel::MetaData

   :Type: :bro:type:`record`

      source: :bro:type:`string`
         An arbitrary string value representing the data source. This
         value is used as unique key to identify a metadata record in
         the scope of a single intelligence item.

      desc: :bro:type:`string` :bro:attr:`&optional`
         A freeform description for the data.

      url: :bro:type:`string` :bro:attr:`&optional`
         A URL for more information about the data.

      do_notice: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/intel/do_notice.bro` is loaded)

         A boolean value to allow the data itself to represent
         if the indicator that this metadata is attached to
         is notice worthy.

      if_in: :bro:type:`Intel::Where` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/intel/do_notice.bro` is loaded)

         Restrictions on when notices are created to only create
         them if the *do_notice* field is T and the notice was
         seen in the indicated location.

      whitelist: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/intel/whitelist.bro` is loaded)

         A boolean value to indicate whether the item is whitelisted.

      cif_impact: :bro:type:`string` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/integration/collective-intel/main.bro` is loaded)

         Maps to the Impact field in the Collective Intelligence Framework.

      cif_severity: :bro:type:`string` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/integration/collective-intel/main.bro` is loaded)

         Maps to the Severity field in the Collective Intelligence Framework.

      cif_confidence: :bro:type:`double` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/integration/collective-intel/main.bro` is loaded)

         Maps to the Confidence field in the Collective Intelligence Framework.

   Data about an :bro:type:`Intel::Item`.

.. bro:type:: Intel::Seen

   :Type: :bro:type:`record`

      indicator: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The string if the data is about a string.

      indicator_type: :bro:type:`Intel::Type` :bro:attr:`&log` :bro:attr:`&optional`
         The type of data that the indicator represents.

      host: :bro:type:`addr` :bro:attr:`&optional`
         If the indicator type was :bro:enum:`Intel::ADDR`, then this
         field will be present.

      where: :bro:type:`Intel::Where` :bro:attr:`&log`
         Where the data was discovered.

      node: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         The name of the node where the match was discovered.

      conn: :bro:type:`connection` :bro:attr:`&optional`
         If the data was discovered within a connection, the
         connection record should go here to give context to the data.

      uid: :bro:type:`string` :bro:attr:`&optional`
         If the data was discovered within a connection, the
         connection uid should go here to give context to the data.
         If the *conn* field is provided, this will be automatically
         filled out.

      f: :bro:type:`fa_file` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.bro` is loaded)

         If the data was discovered within a file, the file record
         should go here to provide context to the data.

      fuid: :bro:type:`string` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/intel/files.bro` is loaded)

         If the data was discovered within a file, the file uid should
         go here to provide context to the data. If the file record *f*
         is provided, this will be automatically filled out.

   Information about a piece of "seen" data.

.. bro:type:: Intel::Type

   :Type: :bro:type:`enum`

      .. bro:enum:: Intel::ADDR Intel::Type

         An IP address.

      .. bro:enum:: Intel::SUBNET Intel::Type

         A subnet in CIDR notation.

      .. bro:enum:: Intel::URL Intel::Type

         A complete URL without the prefix ``"http://"``.

      .. bro:enum:: Intel::SOFTWARE Intel::Type

         Software name.

      .. bro:enum:: Intel::EMAIL Intel::Type

         Email address.

      .. bro:enum:: Intel::DOMAIN Intel::Type

         DNS domain name.

      .. bro:enum:: Intel::USER_NAME Intel::Type

         A user name.

      .. bro:enum:: Intel::CERT_HASH Intel::Type

         Certificate SHA-1 hash.

      .. bro:enum:: Intel::PUBKEY_HASH Intel::Type

         Public key MD5 hash. (SSH server host keys are a good example.)

      .. bro:enum:: Intel::FILE_HASH Intel::Type

         (present if :doc:`/scripts/base/frameworks/intel/files.bro` is loaded)


         File hash which is non-hash type specific.  It's up to the
         user to query for any relevant hash types.

      .. bro:enum:: Intel::FILE_NAME Intel::Type

         (present if :doc:`/scripts/base/frameworks/intel/files.bro` is loaded)


         File name.  Typically with protocols with definite
         indications of a file name.

   Enum type to represent various types of intelligence data.

.. bro:type:: Intel::TypeSet

   :Type: :bro:type:`set` [:bro:type:`Intel::Type`]

   Set of intelligence data types.

.. bro:type:: Intel::Where

   :Type: :bro:type:`enum`

      .. bro:enum:: Intel::IN_ANYWHERE Intel::Where

         A catchall value to represent data of unknown provenance.

      .. bro:enum:: Conn::IN_ORIG Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: Conn::IN_RESP Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: Files::IN_HASH Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: Files::IN_NAME Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: DNS::IN_REQUEST Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: DNS::IN_RESPONSE Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: HTTP::IN_HOST_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: HTTP::IN_REFERRER_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: HTTP::IN_USER_AGENT_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: HTTP::IN_X_FORWARDED_FOR_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: HTTP::IN_URL Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_MAIL_FROM Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_RCPT_TO Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_FROM Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_TO Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_CC Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_RECEIVED_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_REPLY_TO Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_X_ORIGINATING_IP_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_MESSAGE Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SSH::IN_SERVER_HOST_KEY Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SSL::IN_SERVER_NAME Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SMTP::IN_HEADER Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: X509::IN_CERT Intel::Where

         (present if :doc:`/scripts/policy/frameworks/intel/seen/where-locations.bro` is loaded)


      .. bro:enum:: SSH::SUCCESSFUL_LOGIN Intel::Where

         (present if :doc:`/scripts/policy/protocols/ssh/detect-bruteforcing.bro` is loaded)


         An indicator of the login for the intel framework.

   Enum to represent where data came from when it was discovered.
   The convention is to prefix the name with ``IN_``.

Events
######
.. bro:id:: Intel::log_intel

   :Type: :bro:type:`event` (rec: :bro:type:`Intel::Info`)


.. bro:id:: Intel::match

   :Type: :bro:type:`event` (s: :bro:type:`Intel::Seen`, items: :bro:type:`set` [:bro:type:`Intel::Item`])

   Event to represent a match in the intelligence data from data that
   was seen. On clusters there is no assurance as to when this event
   will be generated so do not assume that arbitrary global state beyond
   the given data will be available.
   
   This is the primary mechanism where a user may take actions based on
   data provided by the intelligence framework.

Hooks
#####
.. bro:id:: Intel::extend_match

   :Type: :bro:type:`hook` (info: :bro:type:`Intel::Info`, s: :bro:type:`Intel::Seen`, items: :bro:type:`set` [:bro:type:`Intel::Item`]) : :bro:type:`bool`

   This hook can be used to influence the logging of intelligence hits
   (e.g. by adding data to the Info record). The default information is
   added with a priority of 5.
   

   :info: The Info record that will be logged.
   

   :s: Information about the data seen.
   

   :items: The intel items that match the seen data.
   
   In case the hook execution is terminated using break, the match will
   not be logged.

.. bro:id:: Intel::item_expired

   :Type: :bro:type:`hook` (indicator: :bro:type:`string`, indicator_type: :bro:type:`Intel::Type`, metas: :bro:type:`set` [:bro:type:`Intel::MetaData`]) : :bro:type:`bool`

   This hook can be used to handle expiration of intelligence items.
   

   :indicator: The indicator of the expired item.
   

   :indicator_type: The indicator type of the expired item.
   

   :metas: The set of metadata describing the expired item.
   
   If all hook handlers are executed, the expiration timeout will be reset.
   Otherwise, if one of the handlers terminates using break, the item will
   be removed.

Functions
#########
.. bro:id:: Intel::insert

   :Type: :bro:type:`function` (item: :bro:type:`Intel::Item`) : :bro:type:`void`

   Function to insert intelligence data. If the indicator is already
   present, the associated metadata will be added to the indicator. If
   the indicator already contains a metadata record from the same source,
   the existing metadata record will be updated.

.. bro:id:: Intel::remove

   :Type: :bro:type:`function` (item: :bro:type:`Intel::Item`, purge_indicator: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`) : :bro:type:`void`

   Function to remove intelligence data. If purge_indicator is set, the
   given metadata is ignored and the indicator is removed completely.

.. bro:id:: Intel::seen

   :Type: :bro:type:`function` (s: :bro:type:`Intel::Seen`) : :bro:type:`void`

   Function to declare discovery of a piece of data in order to check
   it against known intelligence for matches.


