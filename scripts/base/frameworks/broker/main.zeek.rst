:tocdepth: 3

base/frameworks/broker/main.zeek
================================
.. bro:namespace:: Broker

The Broker-based communication API and its various options.

:Namespace: Broker
:Imports: :doc:`base/bif/comm.bif.zeek </scripts/base/bif/comm.bif.zeek>`, :doc:`base/bif/messaging.bif.zeek </scripts/base/bif/messaging.bif.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== =================================================================
:bro:id:`Broker::peer_counts_as_iosource`: :bro:type:`bool` :bro:attr:`&redef` Whether calling :bro:see:`Broker::peer` will register the Broker
                                                                               system as an I/O source that will block the process from shutting
                                                                               down.
============================================================================== =================================================================

Redefinable Options
###################
================================================================================= ======================================================================
:bro:id:`Broker::aggressive_interval`: :bro:type:`count` :bro:attr:`&redef`       Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                  in "aggressive" mode.
:bro:id:`Broker::aggressive_polls`: :bro:type:`count` :bro:attr:`&redef`          Number of work-stealing polling attempts for Broker/CAF threads
                                                                                  in "aggressive" mode.
:bro:id:`Broker::congestion_queue_size`: :bro:type:`count` :bro:attr:`&redef`     The number of buffered messages at the Broker/CAF layer after which
                                                                                  a subscriber considers themselves congested (i.e.
:bro:id:`Broker::default_connect_retry`: :bro:type:`interval` :bro:attr:`&redef`  Default interval to retry connecting to a peer if it cannot be made to
                                                                                  work initially, or if it ever becomes disconnected.
:bro:id:`Broker::default_listen_address`: :bro:type:`string` :bro:attr:`&redef`   Default address on which to listen.
:bro:id:`Broker::default_listen_retry`: :bro:type:`interval` :bro:attr:`&redef`   Default interval to retry listening on a port if it's currently in
                                                                                  use already.
:bro:id:`Broker::default_log_topic_prefix`: :bro:type:`string` :bro:attr:`&redef` The default topic prefix where logs will be published.
:bro:id:`Broker::default_port`: :bro:type:`port` :bro:attr:`&redef`               Default port for Broker communication.
:bro:id:`Broker::disable_ssl`: :bro:type:`bool` :bro:attr:`&redef`                If true, do not use SSL for network connections.
:bro:id:`Broker::forward_messages`: :bro:type:`bool` :bro:attr:`&redef`           Forward all received messages to subscribing peers.
:bro:id:`Broker::max_threads`: :bro:type:`count` :bro:attr:`&redef`               Max number of threads to use for Broker/CAF functionality.
:bro:id:`Broker::moderate_interval`: :bro:type:`count` :bro:attr:`&redef`         Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                  in "moderate" mode.
:bro:id:`Broker::moderate_polls`: :bro:type:`count` :bro:attr:`&redef`            Number of work-stealing polling attempts for Broker/CAF threads
                                                                                  in "moderate" mode.
:bro:id:`Broker::moderate_sleep`: :bro:type:`interval` :bro:attr:`&redef`         Interval of time for under-utilized Broker/CAF threads to sleep
                                                                                  when in "moderate" mode.
:bro:id:`Broker::relaxed_interval`: :bro:type:`count` :bro:attr:`&redef`          Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                  in "relaxed" mode.
:bro:id:`Broker::relaxed_sleep`: :bro:type:`interval` :bro:attr:`&redef`          Interval of time for under-utilized Broker/CAF threads to sleep
                                                                                  when in "relaxed" mode.
:bro:id:`Broker::ssl_cafile`: :bro:type:`string` :bro:attr:`&redef`               Path to a file containing concatenated trusted certificates 
                                                                                  in PEM format.
:bro:id:`Broker::ssl_capath`: :bro:type:`string` :bro:attr:`&redef`               Path to an OpenSSL-style directory of trusted certificates.
:bro:id:`Broker::ssl_certificate`: :bro:type:`string` :bro:attr:`&redef`          Path to a file containing a X.509 certificate for this
                                                                                  node in PEM format.
:bro:id:`Broker::ssl_keyfile`: :bro:type:`string` :bro:attr:`&redef`              Path to the file containing the private key for this node's
                                                                                  certificate.
:bro:id:`Broker::ssl_passphrase`: :bro:type:`string` :bro:attr:`&redef`           Passphrase to decrypt the private key specified by
                                                                                  :bro:see:`Broker::ssl_keyfile`.
================================================================================= ======================================================================

Types
#####
==================================================== ====================================================================
:bro:type:`Broker::Data`: :bro:type:`record`         Opaque communication data.
:bro:type:`Broker::DataVector`: :bro:type:`vector`   Opaque communication data sequence.
:bro:type:`Broker::EndpointInfo`: :bro:type:`record` 
:bro:type:`Broker::ErrorCode`: :bro:type:`enum`      Enumerates the possible error types.
:bro:type:`Broker::Event`: :bro:type:`record`        Opaque event communication data.
:bro:type:`Broker::NetworkInfo`: :bro:type:`record`  
:bro:type:`Broker::PeerInfo`: :bro:type:`record`     
:bro:type:`Broker::PeerInfos`: :bro:type:`vector`    
:bro:type:`Broker::PeerStatus`: :bro:type:`enum`     The possible states of a peer endpoint.
:bro:type:`Broker::TableItem`: :bro:type:`record`    Opaque communication data used as a convenient way to wrap key-value
                                                     pairs that comprise table entries.
==================================================== ====================================================================

Functions
#########
==================================================================== =======================================================================
:bro:id:`Broker::auto_publish`: :bro:type:`function`                 Automatically send an event to any interested peers whenever it is
                                                                     locally dispatched.
:bro:id:`Broker::auto_unpublish`: :bro:type:`function`               Stop automatically sending an event to peers upon local dispatch.
:bro:id:`Broker::default_log_topic`: :bro:type:`function`            The default implementation for :bro:see:`Broker::log_topic`.
:bro:id:`Broker::flush_logs`: :bro:type:`function`                   Sends all pending log messages to remote peers.
:bro:id:`Broker::forward`: :bro:type:`function`                      Register a topic prefix subscription for events that should only be
                                                                     forwarded to any subscribing peers and not raise any event handlers
                                                                     on the receiving/forwarding node.
:bro:id:`Broker::listen`: :bro:type:`function`                       Listen for remote connections.
:bro:id:`Broker::log_topic`: :bro:type:`function` :bro:attr:`&redef` A function that will be called for each log entry to determine what
                                                                     broker topic string will be used for sending it to peers.
:bro:id:`Broker::node_id`: :bro:type:`function`                      Get a unique identifier for the local broker endpoint.
:bro:id:`Broker::peer`: :bro:type:`function`                         Initiate a remote connection.
:bro:id:`Broker::peers`: :bro:type:`function`                        Get a list of all peer connections.
:bro:id:`Broker::publish_id`: :bro:type:`function`                   Publishes the value of an identifier to a given topic.
:bro:id:`Broker::subscribe`: :bro:type:`function`                    Register interest in all peer event messages that use a certain topic
                                                                     prefix.
:bro:id:`Broker::unpeer`: :bro:type:`function`                       Remove a remote connection.
:bro:id:`Broker::unsubscribe`: :bro:type:`function`                  Unregister interest in all peer event messages that use a topic prefix.
==================================================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Broker::peer_counts_as_iosource

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Whether calling :bro:see:`Broker::peer` will register the Broker
   system as an I/O source that will block the process from shutting
   down.  For example, set this to false when you are reading pcaps,
   but also want to initaiate a Broker peering and still shutdown after
   done reading the pcap.

Redefinable Options
###################
.. bro:id:: Broker::aggressive_interval

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``4``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "aggressive" mode.

.. bro:id:: Broker::aggressive_polls

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5``

   Number of work-stealing polling attempts for Broker/CAF threads
   in "aggressive" mode.

.. bro:id:: Broker::congestion_queue_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``200``

   The number of buffered messages at the Broker/CAF layer after which
   a subscriber considers themselves congested (i.e. tune the congestion
   control mechanisms).

.. bro:id:: Broker::default_connect_retry

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30.0 secs``

   Default interval to retry connecting to a peer if it cannot be made to
   work initially, or if it ever becomes disconnected.  Use of the
   BRO_DEFAULT_CONNECT_RETRY environment variable (set as number of
   seconds) will override this option and also any values given to
   :bro:see:`Broker::peer`.

.. bro:id:: Broker::default_listen_address

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Default address on which to listen.
   
   .. bro:see:: Broker::listen

.. bro:id:: Broker::default_listen_retry

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30.0 secs``

   Default interval to retry listening on a port if it's currently in
   use already.  Use of the BRO_DEFAULT_LISTEN_RETRY environment variable
   (set as a number of seconds) will override this option and also
   any values given to :bro:see:`Broker::listen`.

.. bro:id:: Broker::default_log_topic_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/logs/"``

   The default topic prefix where logs will be published.  The log's stream
   id is appended when writing to a particular stream.

.. bro:id:: Broker::default_port

   :Type: :bro:type:`port`
   :Attributes: :bro:attr:`&redef`
   :Default: ``9999/tcp``

   Default port for Broker communication. Where not specified
   otherwise, this is the port to connect to and listen on.

.. bro:id:: Broker::disable_ssl

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, do not use SSL for network connections. By default, SSL will
   even be used if no certificates / CAs have been configured. In that case
   (which is the default) the communication will be encrypted, but not
   authenticated.

.. bro:id:: Broker::forward_messages

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Forward all received messages to subscribing peers.

.. bro:id:: Broker::max_threads

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1``

   Max number of threads to use for Broker/CAF functionality.  The
   BRO_BROKER_MAX_THREADS environment variable overrides this setting.

.. bro:id:: Broker::moderate_interval

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``2``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "moderate" mode.

.. bro:id:: Broker::moderate_polls

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5``

   Number of work-stealing polling attempts for Broker/CAF threads
   in "moderate" mode.

.. bro:id:: Broker::moderate_sleep

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``16.0 msecs``

   Interval of time for under-utilized Broker/CAF threads to sleep
   when in "moderate" mode.

.. bro:id:: Broker::relaxed_interval

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "relaxed" mode.

.. bro:id:: Broker::relaxed_sleep

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``64.0 msecs``

   Interval of time for under-utilized Broker/CAF threads to sleep
   when in "relaxed" mode.

.. bro:id:: Broker::ssl_cafile

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Path to a file containing concatenated trusted certificates 
   in PEM format. If set, Bro will require valid certificates for
   all peers.

.. bro:id:: Broker::ssl_capath

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Path to an OpenSSL-style directory of trusted certificates.
   If set, Bro will require valid certificates for
   all peers.

.. bro:id:: Broker::ssl_certificate

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Path to a file containing a X.509 certificate for this
   node in PEM format. If set, Bro will require valid certificates for
   all peers.

.. bro:id:: Broker::ssl_keyfile

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Path to the file containing the private key for this node's
   certificate. If set, Bro will require valid certificates for
   all peers.

.. bro:id:: Broker::ssl_passphrase

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Passphrase to decrypt the private key specified by
   :bro:see:`Broker::ssl_keyfile`. If set, Bro will require valid
   certificates for all peers.

Types
#####
.. bro:type:: Broker::Data

   :Type: :bro:type:`record`

      data: :bro:type:`opaque` of Broker::Data :bro:attr:`&optional`

   Opaque communication data.

.. bro:type:: Broker::DataVector

   :Type: :bro:type:`vector` of :bro:type:`Broker::Data`

   Opaque communication data sequence.

.. bro:type:: Broker::EndpointInfo

   :Type: :bro:type:`record`

      id: :bro:type:`string`
         A unique identifier of the node.

      network: :bro:type:`Broker::NetworkInfo` :bro:attr:`&optional`
         Network-level information.


.. bro:type:: Broker::ErrorCode

   :Type: :bro:type:`enum`

      .. bro:enum:: Broker::UNSPECIFIED Broker::ErrorCode

         The unspecified default error code.

      .. bro:enum:: Broker::PEER_INCOMPATIBLE Broker::ErrorCode

         Version incompatibility.

      .. bro:enum:: Broker::PEER_INVALID Broker::ErrorCode

         Referenced peer does not exist.

      .. bro:enum:: Broker::PEER_UNAVAILABLE Broker::ErrorCode

         Remote peer not listening.

      .. bro:enum:: Broker::PEER_TIMEOUT Broker::ErrorCode

         A peering request timed out.

      .. bro:enum:: Broker::MASTER_EXISTS Broker::ErrorCode

         Master with given name already exists.

      .. bro:enum:: Broker::NO_SUCH_MASTER Broker::ErrorCode

         Master with given name does not exist.

      .. bro:enum:: Broker::NO_SUCH_KEY Broker::ErrorCode

         The given data store key does not exist.

      .. bro:enum:: Broker::REQUEST_TIMEOUT Broker::ErrorCode

         The store operation timed out.

      .. bro:enum:: Broker::TYPE_CLASH Broker::ErrorCode

         The operation expected a different type than provided.

      .. bro:enum:: Broker::INVALID_DATA Broker::ErrorCode

         The data value cannot be used to carry out the desired operation.

      .. bro:enum:: Broker::BACKEND_FAILURE Broker::ErrorCode

         The storage backend failed to execute the operation.

      .. bro:enum:: Broker::STALE_DATA Broker::ErrorCode

         The storage backend failed to execute the operation.

      .. bro:enum:: Broker::CAF_ERROR Broker::ErrorCode

         Catch-all for a CAF-level problem.

   Enumerates the possible error types. 

.. bro:type:: Broker::Event

   :Type: :bro:type:`record`

      name: :bro:type:`string` :bro:attr:`&optional`
         The name of the event.  Not set if invalid event or arguments.

      args: :bro:type:`Broker::DataVector`
         The arguments to the event.

   Opaque event communication data.

.. bro:type:: Broker::NetworkInfo

   :Type: :bro:type:`record`

      address: :bro:type:`string` :bro:attr:`&log`
         The IP address or hostname where the endpoint listens.

      bound_port: :bro:type:`port` :bro:attr:`&log`
         The port where the endpoint is bound to.


.. bro:type:: Broker::PeerInfo

   :Type: :bro:type:`record`

      peer: :bro:type:`Broker::EndpointInfo`

      status: :bro:type:`Broker::PeerStatus`


.. bro:type:: Broker::PeerInfos

   :Type: :bro:type:`vector` of :bro:type:`Broker::PeerInfo`


.. bro:type:: Broker::PeerStatus

   :Type: :bro:type:`enum`

      .. bro:enum:: Broker::INITIALIZING Broker::PeerStatus

         The peering process is initiated.

      .. bro:enum:: Broker::CONNECTING Broker::PeerStatus

         Connection establishment in process.

      .. bro:enum:: Broker::CONNECTED Broker::PeerStatus

         Connection established, peering pending.

      .. bro:enum:: Broker::PEERED Broker::PeerStatus

         Successfully peered.

      .. bro:enum:: Broker::DISCONNECTED Broker::PeerStatus

         Connection to remote peer lost.

      .. bro:enum:: Broker::RECONNECTING Broker::PeerStatus

         Reconnecting to peer after a lost connection.

   The possible states of a peer endpoint.

.. bro:type:: Broker::TableItem

   :Type: :bro:type:`record`

      key: :bro:type:`Broker::Data`

      val: :bro:type:`Broker::Data`

   Opaque communication data used as a convenient way to wrap key-value
   pairs that comprise table entries.

Functions
#########
.. bro:id:: Broker::auto_publish

   :Type: :bro:type:`function` (topic: :bro:type:`string`, ev: :bro:type:`any`) : :bro:type:`bool`

   Automatically send an event to any interested peers whenever it is
   locally dispatched. (For example, using "event my_event(...);" in a
   script.)
   

   :topic: a topic string associated with the event message.
          Peers advertise interest by registering a subscription to some
          prefix of this topic name.
   

   :ev: a Bro event value.
   

   :returns: true if automatic event sending is now enabled.

.. bro:id:: Broker::auto_unpublish

   :Type: :bro:type:`function` (topic: :bro:type:`string`, ev: :bro:type:`any`) : :bro:type:`bool`

   Stop automatically sending an event to peers upon local dispatch.
   

   :topic: a topic originally given to :bro:see:`Broker::auto_publish`.
   

   :ev: an event originally given to :bro:see:`Broker::auto_publish`.
   

   :returns: true if automatic events will not occur for the topic/event
            pair.

.. bro:id:: Broker::default_log_topic

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, path: :bro:type:`string`) : :bro:type:`string`

   The default implementation for :bro:see:`Broker::log_topic`.

.. bro:id:: Broker::flush_logs

   :Type: :bro:type:`function` () : :bro:type:`count`

   Sends all pending log messages to remote peers.  This normally
   doesn't need to be used except for test cases that are time-sensitive.

.. bro:id:: Broker::forward

   :Type: :bro:type:`function` (topic_prefix: :bro:type:`string`) : :bro:type:`bool`

   Register a topic prefix subscription for events that should only be
   forwarded to any subscribing peers and not raise any event handlers
   on the receiving/forwarding node.  i.e. it's the same as
   :bro:see:`Broker::subscribe` except matching events are not raised
   on the receiver, just forwarded.  Use :bro:see:`Broker::unsubscribe`
   with the same argument to undo this operation.
   

   :topic_prefix: a prefix to match against remote message topics.
                 e.g. an empty prefix matches everything and "a" matches
                 "alice" and "amy" but not "bob".
   

   :returns: true if a new event forwarding/subscription is now registered.

.. bro:id:: Broker::listen

   :Type: :bro:type:`function` (a: :bro:type:`string` :bro:attr:`&default` = :bro:see:`Broker::default_listen_address` :bro:attr:`&optional`, p: :bro:type:`port` :bro:attr:`&default` = :bro:see:`Broker::default_port` :bro:attr:`&optional`, retry: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Broker::default_listen_retry` :bro:attr:`&optional`) : :bro:type:`port`

   Listen for remote connections.
   

   :a: an address string on which to accept connections, e.g.
      "127.0.0.1".  An empty string refers to INADDR_ANY.
   

   :p: the TCP port to listen on. The value 0 means that the OS should choose
      the next available free port.
   

   :retry: If non-zero, retries listening in regular intervals if the port cannot be
          acquired immediately. 0 disables retries.  If the
          BRO_DEFAULT_LISTEN_RETRY environment variable is set (as number
          of seconds), it overrides any value given here.
   

   :returns: the bound port or 0/? on failure.
   
   .. bro:see:: Broker::status

.. bro:id:: Broker::log_topic

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, path: :bro:type:`string`) : :bro:type:`string`
   :Attributes: :bro:attr:`&redef`

   A function that will be called for each log entry to determine what
   broker topic string will be used for sending it to peers.  The
   default implementation will return a value based on
   :bro:see:`Broker::default_log_topic_prefix`.
   

   :id: the ID associated with the log stream entry that will be sent.
   

   :path: the path to which the log stream entry will be output.
   

   :returns: a string representing the broker topic to which the log
            will be sent.

.. bro:id:: Broker::node_id

   :Type: :bro:type:`function` () : :bro:type:`string`

   Get a unique identifier for the local broker endpoint.
   

   :returns: a unique identifier for the local broker endpoint.

.. bro:id:: Broker::peer

   :Type: :bro:type:`function` (a: :bro:type:`string`, p: :bro:type:`port` :bro:attr:`&default` = :bro:see:`Broker::default_port` :bro:attr:`&optional`, retry: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Broker::default_connect_retry` :bro:attr:`&optional`) : :bro:type:`bool`

   Initiate a remote connection.
   

   :a: an address to connect to, e.g. "localhost" or "127.0.0.1".
   

   :p: the TCP port on which the remote side is listening.
   

   :retry: an interval at which to retry establishing the
          connection with the remote peer if it cannot be made initially, or
          if it ever becomes disconnected.  If the
          BRO_DEFAULT_CONNECT_RETRY environment variable is set (as number
          of seconds), it overrides any value given here.
   

   :returns: true if it's possible to try connecting with the peer and
            it's a new peer. The actual connection may not be established
            until a later point in time.
   
   .. bro:see:: Broker::status

.. bro:id:: Broker::peers

   :Type: :bro:type:`function` () : :bro:type:`vector` of :bro:type:`Broker::PeerInfo`

   Get a list of all peer connections.
   

   :returns: a list of all peer connections.

.. bro:id:: Broker::publish_id

   :Type: :bro:type:`function` (topic: :bro:type:`string`, id: :bro:type:`string`) : :bro:type:`bool`

   Publishes the value of an identifier to a given topic.  The subscribers
   will update their local value for that identifier on receipt.
   

   :topic: a topic associated with the message.
   

   :id: the identifier to publish.
   

   :returns: true if the message is sent.

.. bro:id:: Broker::subscribe

   :Type: :bro:type:`function` (topic_prefix: :bro:type:`string`) : :bro:type:`bool`

   Register interest in all peer event messages that use a certain topic
   prefix.  Note that subscriptions may not be altered immediately after
   calling (except during :bro:see:`bro_init`).
   

   :topic_prefix: a prefix to match against remote message topics.
                 e.g. an empty prefix matches everything and "a" matches
                 "alice" and "amy" but not "bob".
   

   :returns: true if it's a new event subscription and it is now registered.

.. bro:id:: Broker::unpeer

   :Type: :bro:type:`function` (a: :bro:type:`string`, p: :bro:type:`port`) : :bro:type:`bool`

   Remove a remote connection.
   
   Note that this does not terminate the connection to the peer, it
   just means that we won't exchange any further information with it
   unless peering resumes later.
   

   :a: the address used in previous successful call to :bro:see:`Broker::peer`.
   

   :p: the port used in previous successful call to :bro:see:`Broker::peer`.
   

   :returns: true if the arguments match a previously successful call to
            :bro:see:`Broker::peer`.
   

   :TODO: We do not have a function yet to terminate a connection.

.. bro:id:: Broker::unsubscribe

   :Type: :bro:type:`function` (topic_prefix: :bro:type:`string`) : :bro:type:`bool`

   Unregister interest in all peer event messages that use a topic prefix.
   Note that subscriptions may not be altered immediately after calling
   (except during :bro:see:`bro_init`).
   

   :topic_prefix: a prefix previously supplied to a successful call to
                 :bro:see:`Broker::subscribe` or :bro:see:`Broker::forward`.
   

   :returns: true if interest in the topic prefix is no longer advertised.


