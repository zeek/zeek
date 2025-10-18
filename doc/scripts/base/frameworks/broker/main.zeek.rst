:tocdepth: 3

base/frameworks/broker/main.zeek
================================
.. zeek:namespace:: Broker

The Broker-based communication API and its various options.

:Namespace: Broker
:Imports: :doc:`base/bif/comm.bif.zeek </scripts/base/bif/comm.bif.zeek>`, :doc:`base/bif/messaging.bif.zeek </scripts/base/bif/messaging.bif.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================= =================================================================
:zeek:id:`Broker::peer_counts_as_iosource`: :zeek:type:`bool` :zeek:attr:`&redef` Whether calling :zeek:see:`Broker::peer` will register the Broker
                                                                                  system as an I/O source that will block the process from shutting
                                                                                  down.
================================================================================= =================================================================

Redefinable Options
###################
======================================================================================================= ===========================================================================
:zeek:id:`Broker::aggressive_interval`: :zeek:type:`count` :zeek:attr:`&redef`                          Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                                        in "aggressive" mode.
:zeek:id:`Broker::aggressive_polls`: :zeek:type:`count` :zeek:attr:`&redef`                             Number of work-stealing polling attempts for Broker/CAF threads
                                                                                                        in "aggressive" mode.
:zeek:id:`Broker::buffer_stats_reset_interval`: :zeek:type:`interval` :zeek:attr:`&redef`               How frequently Zeek resets some peering/client buffer statistics,
                                                                                                        such as ``max_queued_recently`` in :zeek:see:`BrokerPeeringStats`.
:zeek:id:`Broker::default_connect_retry`: :zeek:type:`interval` :zeek:attr:`&redef`                     Default interval to retry connecting to a peer if it cannot be made to
                                                                                                        work initially, or if it ever becomes disconnected.
:zeek:id:`Broker::default_listen_address`: :zeek:type:`string` :zeek:attr:`&redef`                      Default address on which to listen.
:zeek:id:`Broker::default_listen_address_websocket`: :zeek:type:`string` :zeek:attr:`&redef`            Default address on which to listen for WebSocket connections.
:zeek:id:`Broker::default_listen_retry`: :zeek:type:`interval` :zeek:attr:`&redef`                      Default interval to retry listening on a port if it's currently in
                                                                                                        use already.
:zeek:id:`Broker::default_log_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                    The default topic prefix where logs will be published.
:zeek:id:`Broker::default_port`: :zeek:type:`port` :zeek:attr:`&redef`                                  Default port for native Broker communication.
:zeek:id:`Broker::default_port_websocket`: :zeek:type:`port` :zeek:attr:`&redef`                        Default port for Broker WebSocket communication.
:zeek:id:`Broker::disable_ssl`: :zeek:type:`bool` :zeek:attr:`&redef`                                   If true, do not use SSL for network connections.
:zeek:id:`Broker::forward_messages`: :zeek:type:`bool` :zeek:attr:`&redef`                              Forward all received messages to subscribing peers.
:zeek:id:`Broker::log_batch_interval`: :zeek:type:`interval` :zeek:attr:`&redef`                        Max time to buffer log messages before sending the current set out as a
                                                                                                        batch.
:zeek:id:`Broker::log_batch_size`: :zeek:type:`count` :zeek:attr:`&redef`                               The max number of log entries per log stream to batch together when
                                                                                                        sending log messages to a remote logger.
:zeek:id:`Broker::log_severity_level`: :zeek:type:`Broker::LogSeverityLevel` :zeek:attr:`&redef`        The log event severity level for the Broker log output.
:zeek:id:`Broker::log_stderr_severity_level`: :zeek:type:`Broker::LogSeverityLevel` :zeek:attr:`&redef` Event severity level for also printing the Broker log output to stderr.
:zeek:id:`Broker::max_threads`: :zeek:type:`count` :zeek:attr:`&redef`                                  Max number of threads to use for Broker/CAF functionality.
:zeek:id:`Broker::moderate_interval`: :zeek:type:`count` :zeek:attr:`&redef`                            Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                                        in "moderate" mode.
:zeek:id:`Broker::moderate_polls`: :zeek:type:`count` :zeek:attr:`&redef`                               Number of work-stealing polling attempts for Broker/CAF threads
                                                                                                        in "moderate" mode.
:zeek:id:`Broker::moderate_sleep`: :zeek:type:`interval` :zeek:attr:`&redef`                            Interval of time for under-utilized Broker/CAF threads to sleep
                                                                                                        when in "moderate" mode.
:zeek:id:`Broker::peer_buffer_size`: :zeek:type:`count` :zeek:attr:`&redef`                             Max number of items we buffer at most per peer.
:zeek:id:`Broker::peer_overflow_policy`: :zeek:type:`string` :zeek:attr:`&redef`                        Configures how Broker responds to peers that cannot keep up with the
                                                                                                        incoming message rate.
:zeek:id:`Broker::relaxed_interval`: :zeek:type:`count` :zeek:attr:`&redef`                             Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                                        in "relaxed" mode.
:zeek:id:`Broker::relaxed_sleep`: :zeek:type:`interval` :zeek:attr:`&redef`                             Interval of time for under-utilized Broker/CAF threads to sleep
                                                                                                        when in "relaxed" mode.
:zeek:id:`Broker::scheduler_policy`: :zeek:type:`string` :zeek:attr:`&redef`                            The CAF scheduling policy to use.
:zeek:id:`Broker::ssl_cafile`: :zeek:type:`string` :zeek:attr:`&redef`                                  Path to a file containing concatenated trusted certificates
                                                                                                        in PEM format.
:zeek:id:`Broker::ssl_capath`: :zeek:type:`string` :zeek:attr:`&redef`                                  Path to an OpenSSL-style directory of trusted certificates.
:zeek:id:`Broker::ssl_certificate`: :zeek:type:`string` :zeek:attr:`&redef`                             Path to a file containing a X.509 certificate for this
                                                                                                        node in PEM format.
:zeek:id:`Broker::ssl_keyfile`: :zeek:type:`string` :zeek:attr:`&redef`                                 Path to the file containing the private key for this node's
                                                                                                        certificate.
:zeek:id:`Broker::ssl_passphrase`: :zeek:type:`string` :zeek:attr:`&redef`                              Passphrase to decrypt the private key specified by
                                                                                                        :zeek:see:`Broker::ssl_keyfile`.
:zeek:id:`Broker::web_socket_buffer_size`: :zeek:type:`count` :zeek:attr:`&redef`                       Same as :zeek:see:`Broker::peer_buffer_size` but for WebSocket clients.
:zeek:id:`Broker::web_socket_overflow_policy`: :zeek:type:`string` :zeek:attr:`&redef`                  Same as :zeek:see:`Broker::peer_overflow_policy` but for WebSocket clients.
======================================================================================================= ===========================================================================

Types
#####
======================================================== ====================================================================
:zeek:type:`Broker::Data`: :zeek:type:`record`           Opaque communication data.
:zeek:type:`Broker::DataVector`: :zeek:type:`vector`     Opaque communication data sequence.
:zeek:type:`Broker::EndpointInfo`: :zeek:type:`record`   
:zeek:type:`Broker::ErrorCode`: :zeek:type:`enum`        Enumerates the possible error types.
:zeek:type:`Broker::Event`: :zeek:type:`record`          Opaque event communication data.
:zeek:type:`Broker::LogSeverityLevel`: :zeek:type:`enum` The possible log event severity levels for Broker.
:zeek:type:`Broker::NetworkInfo`: :zeek:type:`record`    
:zeek:type:`Broker::PeerInfo`: :zeek:type:`record`       
:zeek:type:`Broker::PeerInfos`: :zeek:type:`vector`      
:zeek:type:`Broker::PeerStatus`: :zeek:type:`enum`       The possible states of a peer endpoint.
:zeek:type:`Broker::TableItem`: :zeek:type:`record`      Opaque communication data used as a convenient way to wrap key-value
                                                         pairs that comprise table entries.
======================================================== ====================================================================

Functions
#########
======================================================================= =======================================================================
:zeek:id:`Broker::default_log_topic`: :zeek:type:`function`             The default implementation for :zeek:see:`Broker::log_topic`.
:zeek:id:`Broker::flush_logs`: :zeek:type:`function`                    Sends all pending log messages to remote peers.
:zeek:id:`Broker::forward`: :zeek:type:`function`                       Register a topic prefix subscription for events that should only be
                                                                        forwarded to any subscribing peers and not raise any event handlers
                                                                        on the receiving/forwarding node.
:zeek:id:`Broker::is_outbound_peering`: :zeek:type:`function`           Whether the local node originally initiated the peering with the
                                                                        given endpoint.
:zeek:id:`Broker::listen`: :zeek:type:`function`                        Listen for remote connections using the native Broker protocol.
:zeek:id:`Broker::log_topic`: :zeek:type:`function` :zeek:attr:`&redef` A function that will be called for each log entry to determine what
                                                                        broker topic string will be used for sending it to peers.
:zeek:id:`Broker::node_id`: :zeek:type:`function`                       Get a unique identifier for the local broker endpoint.
:zeek:id:`Broker::peer`: :zeek:type:`function`                          Initiate a remote connection.
:zeek:id:`Broker::peering_stats`: :zeek:type:`function`                 Obtain each peering's send-buffer statistics.
:zeek:id:`Broker::peers`: :zeek:type:`function`                         Get a list of all peer connections.
:zeek:id:`Broker::publish_id`: :zeek:type:`function`                    Publishes the value of an identifier to a given topic.
:zeek:id:`Broker::subscribe`: :zeek:type:`function`                     Register interest in all peer event messages that use a certain topic
                                                                        prefix.
:zeek:id:`Broker::unpeer`: :zeek:type:`function`                        Remove a remote connection.
:zeek:id:`Broker::unsubscribe`: :zeek:type:`function`                   Unregister interest in all peer event messages that use a topic prefix.
======================================================================= =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Broker::peer_counts_as_iosource
   :source-code: base/frameworks/broker/main.zeek 153 153

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether calling :zeek:see:`Broker::peer` will register the Broker
   system as an I/O source that will block the process from shutting
   down.  For example, set this to false when you are reading pcaps,
   but also want to initiate a Broker peering and still shutdown after
   done reading the pcap.

Redefinable Options
###################
.. zeek:id:: Broker::aggressive_interval
   :source-code: base/frameworks/broker/main.zeek 135 135

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``4``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "aggressive" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::aggressive_polls
   :source-code: base/frameworks/broker/main.zeek 127 127

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5``

   Number of work-stealing polling attempts for Broker/CAF threads
   in "aggressive" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::buffer_stats_reset_interval
   :source-code: base/frameworks/broker/main.zeek 104 104

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   How frequently Zeek resets some peering/client buffer statistics,
   such as ``max_queued_recently`` in :zeek:see:`BrokerPeeringStats`.

.. zeek:id:: Broker::default_connect_retry
   :source-code: base/frameworks/broker/main.zeek 39 39

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   Default interval to retry connecting to a peer if it cannot be made to
   work initially, or if it ever becomes disconnected.  Use of the
   ZEEK_DEFAULT_CONNECT_RETRY environment variable (set as number of
   seconds) will override this option and also any values given to
   :zeek:see:`Broker::peer`.

.. zeek:id:: Broker::default_listen_address
   :source-code: base/frameworks/broker/main.zeek 27 27

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``
   :Redefinition: from :doc:`/scripts/policy/frameworks/management/agent/boot.zeek`

      ``=``::

         ``127.0.0.1``


   Default address on which to listen.
   
   .. zeek:see:: Broker::listen

.. zeek:id:: Broker::default_listen_address_websocket
   :source-code: base/frameworks/broker/main.zeek 32 32

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Default address on which to listen for WebSocket connections.
   
   .. zeek:see:: Cluster::listen_websocket

.. zeek:id:: Broker::default_listen_retry
   :source-code: base/frameworks/broker/main.zeek 22 22

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   Default interval to retry listening on a port if it's currently in
   use already.  Use of the ZEEK_DEFAULT_LISTEN_RETRY environment variable
   (set as a number of seconds) will override this option and also
   any values given to :zeek:see:`Broker::listen`.

.. zeek:id:: Broker::default_log_topic_prefix
   :source-code: base/frameworks/broker/main.zeek 157 157

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/logs/"``

   The default topic prefix where logs will be published.  The log's stream
   id is appended when writing to a particular stream.

.. zeek:id:: Broker::default_port
   :source-code: base/frameworks/broker/main.zeek 8 8

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``9999/tcp``

   Default port for native Broker communication. Where not specified
   otherwise, this is the port to connect to and listen on.

.. zeek:id:: Broker::default_port_websocket
   :source-code: base/frameworks/broker/main.zeek 16 16

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``9997/tcp``

   Default port for Broker WebSocket communication. Where not specified
   otherwise, this is the port to connect to and listen on for
   WebSocket connections.
   
   See the Broker documentation for a specification of the message
   format over WebSocket connections.

.. zeek:id:: Broker::disable_ssl
   :source-code: base/frameworks/broker/main.zeek 45 45

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, do not use SSL for network connections. By default, SSL will
   even be used if no certificates / CAs have been configured. In that case
   (which is the default) the communication will be encrypted, but not
   authenticated.

.. zeek:id:: Broker::forward_messages
   :source-code: base/frameworks/broker/main.zeek 146 146

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Forward all received messages to subscribing peers.

.. zeek:id:: Broker::log_batch_interval
   :source-code: base/frameworks/broker/main.zeek 78 78

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   Max time to buffer log messages before sending the current set out as a
   batch.

.. zeek:id:: Broker::log_batch_size
   :source-code: base/frameworks/broker/main.zeek 74 74

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``400``

   The max number of log entries per log stream to batch together when
   sending log messages to a remote logger.

.. zeek:id:: Broker::log_severity_level
   :source-code: base/frameworks/broker/main.zeek 195 195

   :Type: :zeek:type:`Broker::LogSeverityLevel`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Broker::LOG_WARNING``

   The log event severity level for the Broker log output.

.. zeek:id:: Broker::log_stderr_severity_level
   :source-code: base/frameworks/broker/main.zeek 198 198

   :Type: :zeek:type:`Broker::LogSeverityLevel`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Broker::LOG_CRITICAL``

   Event severity level for also printing the Broker log output to stderr.

.. zeek:id:: Broker::max_threads
   :source-code: base/frameworks/broker/main.zeek 82 82

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1``

   Max number of threads to use for Broker/CAF functionality.  The
   ``ZEEK_BROKER_MAX_THREADS`` environment variable overrides this setting.

.. zeek:id:: Broker::moderate_interval
   :source-code: base/frameworks/broker/main.zeek 139 139

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "moderate" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::moderate_polls
   :source-code: base/frameworks/broker/main.zeek 131 131

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5``

   Number of work-stealing polling attempts for Broker/CAF threads
   in "moderate" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::moderate_sleep
   :source-code: base/frameworks/broker/main.zeek 119 119

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``16.0 msecs``

   Interval of time for under-utilized Broker/CAF threads to sleep
   when in "moderate" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::peer_buffer_size
   :source-code: base/frameworks/broker/main.zeek 87 87

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``8192``

   Max number of items we buffer at most per peer. What action to take when
   the buffer reaches its maximum size is determined by
   :zeek:see:`Broker::peer_overflow_policy`.

.. zeek:id:: Broker::peer_overflow_policy
   :source-code: base/frameworks/broker/main.zeek 94 94

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"drop_oldest"``

   Configures how Broker responds to peers that cannot keep up with the
   incoming message rate. Available strategies:
   - disconnect: drop the connection to the unresponsive peer
   - drop_newest: replace the newest message in the buffer
   - drop_oldest: removed the olsted message from the buffer, then append

.. zeek:id:: Broker::relaxed_interval
   :source-code: base/frameworks/broker/main.zeek 143 143

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "relaxed" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::relaxed_sleep
   :source-code: base/frameworks/broker/main.zeek 123 123

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``64.0 msecs``

   Interval of time for under-utilized Broker/CAF threads to sleep
   when in "relaxed" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::scheduler_policy
   :source-code: base/frameworks/broker/main.zeek 115 115

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"sharing"``

   The CAF scheduling policy to use.  Available options are "sharing" and
   "stealing".  The "sharing" policy uses a single, global work queue along
   with mutex and condition variable used for accessing it, which may be
   better for cases that don't require much concurrency or need lower power
   consumption.  The "stealing" policy uses multiple work queues protected
   by spinlocks, which may be better for use-cases that have more
   concurrency needs.  E.g. may be worth testing the "stealing" policy
   along with dedicating more threads if a lot of data store processing is
   required.

.. zeek:id:: Broker::ssl_cafile
   :source-code: base/frameworks/broker/main.zeek 50 50

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Path to a file containing concatenated trusted certificates
   in PEM format. If set, Zeek will require valid certificates for
   all peers.

.. zeek:id:: Broker::ssl_capath
   :source-code: base/frameworks/broker/main.zeek 55 55

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Path to an OpenSSL-style directory of trusted certificates.
   If set, Zeek will require valid certificates for
   all peers.

.. zeek:id:: Broker::ssl_certificate
   :source-code: base/frameworks/broker/main.zeek 60 60

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Path to a file containing a X.509 certificate for this
   node in PEM format. If set, Zeek will require valid certificates for
   all peers.

.. zeek:id:: Broker::ssl_keyfile
   :source-code: base/frameworks/broker/main.zeek 70 70

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Path to the file containing the private key for this node's
   certificate. If set, Zeek will require valid certificates for
   all peers.

.. zeek:id:: Broker::ssl_passphrase
   :source-code: base/frameworks/broker/main.zeek 65 65

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Passphrase to decrypt the private key specified by
   :zeek:see:`Broker::ssl_keyfile`. If set, Zeek will require valid
   certificates for all peers.

.. zeek:id:: Broker::web_socket_buffer_size
   :source-code: base/frameworks/broker/main.zeek 97 97

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``8192``

   Same as :zeek:see:`Broker::peer_buffer_size` but for WebSocket clients.

.. zeek:id:: Broker::web_socket_overflow_policy
   :source-code: base/frameworks/broker/main.zeek 100 100

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"drop_oldest"``

   Same as :zeek:see:`Broker::peer_overflow_policy` but for WebSocket clients.

Types
#####
.. zeek:type:: Broker::Data
   :source-code: base/frameworks/broker/main.zeek 275 277

   :Type: :zeek:type:`record`


   .. zeek:field:: data :zeek:type:`opaque` of Broker::Data :zeek:attr:`&optional`


   Opaque communication data.

.. zeek:type:: Broker::DataVector
   :source-code: base/frameworks/broker/main.zeek 280 280

   :Type: :zeek:type:`vector` of :zeek:type:`Broker::Data`

   Opaque communication data sequence.

.. zeek:type:: Broker::EndpointInfo
   :source-code: base/frameworks/broker/main.zeek 256 261

   :Type: :zeek:type:`record`


   .. zeek:field:: id :zeek:type:`string`

      A unique identifier of the node.


   .. zeek:field:: network :zeek:type:`Broker::NetworkInfo` :zeek:attr:`&optional`

      Network-level information.



.. zeek:type:: Broker::ErrorCode
   :source-code: base/frameworks/broker/main.zeek 200 200

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::NO_ERROR Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::UNSPECIFIED Broker::ErrorCode

         The unspecified default error code.

      .. zeek:enum:: Broker::PEER_INCOMPATIBLE Broker::ErrorCode

         Version incompatibility.

      .. zeek:enum:: Broker::PEER_INVALID Broker::ErrorCode

         Referenced peer does not exist.

      .. zeek:enum:: Broker::PEER_UNAVAILABLE Broker::ErrorCode

         Remote peer not listening.

      .. zeek:enum:: Broker::PEER_DISCONNECT_DURING_HANDSHAKE Broker::ErrorCode

         Remote peer disconnected during the handshake.

      .. zeek:enum:: Broker::PEER_TIMEOUT Broker::ErrorCode

         A peering request timed out.

      .. zeek:enum:: Broker::MASTER_EXISTS Broker::ErrorCode

         Master with given name already exists.

      .. zeek:enum:: Broker::NO_SUCH_MASTER Broker::ErrorCode

         Master with given name does not exist.

      .. zeek:enum:: Broker::NO_SUCH_KEY Broker::ErrorCode

         The given data store key does not exist.

      .. zeek:enum:: Broker::REQUEST_TIMEOUT Broker::ErrorCode

         The store operation timed out.

      .. zeek:enum:: Broker::TYPE_CLASH Broker::ErrorCode

         The operation expected a different type than provided.

      .. zeek:enum:: Broker::INVALID_DATA Broker::ErrorCode

         The data value cannot be used to carry out the desired operation.

      .. zeek:enum:: Broker::BACKEND_FAILURE Broker::ErrorCode

         The storage backend failed to execute the operation.

      .. zeek:enum:: Broker::STALE_DATA Broker::ErrorCode

         The storage backend failed to execute the operation.

      .. zeek:enum:: Broker::CANNOT_OPEN_FILE Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::CANNOT_WRITE_FILE Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::INVALID_TOPIC_KEY Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::END_OF_FILE Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::INVALID_TAG Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::INVALID_STATUS Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::CAF_ERROR Broker::ErrorCode

         Catch-all for a CAF-level problem.

   Enumerates the possible error types.

.. zeek:type:: Broker::Event
   :source-code: base/frameworks/broker/main.zeek 283 288

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string` :zeek:attr:`&optional`

      The name of the event.  Not set if invalid event or arguments.


   .. zeek:field:: args :zeek:type:`Broker::DataVector`

      The arguments to the event.


   Opaque event communication data.

.. zeek:type:: Broker::LogSeverityLevel
   :source-code: base/frameworks/broker/main.zeek 179 193

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::LOG_CRITICAL Broker::LogSeverityLevel

         Fatal event, normal operation has most likely broken down.

      .. zeek:enum:: Broker::LOG_ERROR Broker::LogSeverityLevel

         Unrecoverable event that imparts at least part of the system.

      .. zeek:enum:: Broker::LOG_WARNING Broker::LogSeverityLevel

         Unexpected or conspicuous event that may still be recoverable.

      .. zeek:enum:: Broker::LOG_INFO Broker::LogSeverityLevel

         Noteworthy event during normal operation.

      .. zeek:enum:: Broker::LOG_VERBOSE Broker::LogSeverityLevel

         Information that might be relevant for a user to understand system behavior.

      .. zeek:enum:: Broker::LOG_DEBUG Broker::LogSeverityLevel

         An event that is relevant only for troubleshooting and debugging.

   The possible log event severity levels for Broker.

.. zeek:type:: Broker::NetworkInfo
   :source-code: base/frameworks/broker/main.zeek 249 254

   :Type: :zeek:type:`record`


   .. zeek:field:: address :zeek:type:`string` :zeek:attr:`&log`

      The IP address or hostname where the endpoint listens.


   .. zeek:field:: bound_port :zeek:type:`port` :zeek:attr:`&log`

      The port where the endpoint is bound to.



.. zeek:type:: Broker::PeerInfo
   :source-code: base/frameworks/broker/main.zeek 263 270

   :Type: :zeek:type:`record`


   .. zeek:field:: peer :zeek:type:`Broker::EndpointInfo`


   .. zeek:field:: status :zeek:type:`Broker::PeerStatus`


   .. zeek:field:: is_outbound :zeek:type:`bool`

      Whether the local node created the peering, as opposed to a
      remote establishing it by connecting to us.



.. zeek:type:: Broker::PeerInfos
   :source-code: base/frameworks/broker/main.zeek 272 272

   :Type: :zeek:type:`vector` of :zeek:type:`Broker::PeerInfo`


.. zeek:type:: Broker::PeerStatus
   :source-code: base/frameworks/broker/main.zeek 234 234

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::INITIALIZING Broker::PeerStatus

         The peering process is initiated.

      .. zeek:enum:: Broker::CONNECTING Broker::PeerStatus

         Connection establishment in process.

      .. zeek:enum:: Broker::CONNECTED Broker::PeerStatus

         Connection established, peering pending.

      .. zeek:enum:: Broker::PEERED Broker::PeerStatus

         Successfully peered.

      .. zeek:enum:: Broker::DISCONNECTED Broker::PeerStatus

         Connection to remote peer lost.

      .. zeek:enum:: Broker::RECONNECTING Broker::PeerStatus

         Reconnecting to peer after a lost connection.

   The possible states of a peer endpoint.

.. zeek:type:: Broker::TableItem
   :source-code: base/frameworks/broker/main.zeek 292 295

   :Type: :zeek:type:`record`


   .. zeek:field:: key :zeek:type:`Broker::Data`


   .. zeek:field:: val :zeek:type:`Broker::Data`


   Opaque communication data used as a convenient way to wrap key-value
   pairs that comprise table entries.

Functions
#########
.. zeek:id:: Broker::default_log_topic
   :source-code: base/frameworks/broker/main.zeek 160 163

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, path: :zeek:type:`string`) : :zeek:type:`string`

   The default implementation for :zeek:see:`Broker::log_topic`.

.. zeek:id:: Broker::flush_logs
   :source-code: base/frameworks/broker/main.zeek 498 501

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Sends all pending log messages to remote peers.  This normally
   doesn't need to be used except for test cases that are time-sensitive.

.. zeek:id:: Broker::forward
   :source-code: base/frameworks/broker/main.zeek 513 516

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`

   Register a topic prefix subscription for events that should only be
   forwarded to any subscribing peers and not raise any event handlers
   on the receiving/forwarding node.  i.e. it's the same as
   :zeek:see:`Broker::subscribe` except matching events are not raised
   on the receiver, just forwarded.  Use :zeek:see:`Broker::unsubscribe`
   with the same argument to undo this operation.
   

   :param topic_prefix: a prefix to match against remote message topics.
                 e.g. an empty prefix matches everything and "a" matches
                 "alice" and "amy" but not "bob".
   

   :returns: true if a new event forwarding/subscription is now registered.

.. zeek:id:: Broker::is_outbound_peering
   :source-code: base/frameworks/broker/main.zeek 478 481

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`

   Whether the local node originally initiated the peering with the
   given endpoint.
   

   :param a: the address used in previous successful call to :zeek:see:`Broker::peer`.
   

   :param p: the port used in previous successful call to :zeek:see:`Broker::peer`.
   
   Returns:: True if this node initiated the peering.

.. zeek:id:: Broker::listen
   :source-code: base/frameworks/broker/main.zeek 450 466

   :Type: :zeek:type:`function` (a: :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`Broker::default_listen_address` :zeek:attr:`&optional`, p: :zeek:type:`port` :zeek:attr:`&default` = :zeek:see:`Broker::default_port` :zeek:attr:`&optional`, retry: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_listen_retry` :zeek:attr:`&optional`) : :zeek:type:`port`

   Listen for remote connections using the native Broker protocol.
   

   :param a: an address string on which to accept connections, e.g.
      "127.0.0.1".  An empty string refers to INADDR_ANY.
   

   :param p: the TCP port to listen on. The value 0 means that the OS should choose
      the next available free port.
   

   :param retry: If non-zero, retries listening in regular intervals if the port cannot be
          acquired immediately. 0 disables retries.  If the
          ZEEK_DEFAULT_LISTEN_RETRY environment variable is set (as number
          of seconds), it overrides any value given here.
   

   :returns: the bound port or 0/? on failure.
   
   .. zeek:see:: Broker::status

.. zeek:id:: Broker::log_topic
   :source-code: base/frameworks/broker/main.zeek 160 163

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, path: :zeek:type:`string`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   A function that will be called for each log entry to determine what
   broker topic string will be used for sending it to peers.  The
   default implementation will return a value based on
   :zeek:see:`Broker::default_log_topic_prefix`.
   

   :param id: the ID associated with the log stream entry that will be sent.
   

   :param path: the path to which the log stream entry will be output.
   

   :returns: a string representing the broker topic to which the log
            will be sent.

.. zeek:id:: Broker::node_id
   :source-code: base/frameworks/broker/main.zeek 488 491

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Get a unique identifier for the local broker endpoint.
   

   :returns: a unique identifier for the local broker endpoint.

.. zeek:id:: Broker::peer
   :source-code: base/frameworks/broker/main.zeek 468 471

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port` :zeek:attr:`&default` = :zeek:see:`Broker::default_port` :zeek:attr:`&optional`, retry: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_connect_retry` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Initiate a remote connection.
   

   :param a: an address to connect to, e.g. "localhost" or "127.0.0.1".
   

   :param p: the TCP port on which the remote side is listening.
   

   :param retry: an interval at which to retry establishing the
          connection with the remote peer if it cannot be made initially, or
          if it ever becomes disconnected.  If the
          ZEEK_DEFAULT_CONNECT_RETRY environment variable is set (as number
          of seconds), it overrides any value given here.
   

   :returns: true if it's possible to try connecting with the peer and
            it's a new peer. The actual connection may not be established
            until a later point in time.
   
   .. zeek:see:: Broker::status

.. zeek:id:: Broker::peering_stats
   :source-code: base/frameworks/broker/main.zeek 493 496

   :Type: :zeek:type:`function` () : :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`BrokerPeeringStats`

   Obtain each peering's send-buffer statistics. The keys are Broker
   endpoint IDs.
   

   :returns: per-peering statistics.

.. zeek:id:: Broker::peers
   :source-code: base/frameworks/broker/main.zeek 483 486

   :Type: :zeek:type:`function` () : :zeek:type:`vector` of :zeek:type:`Broker::PeerInfo`

   Get a list of all peer connections.
   

   :returns: a list of all peer connections.

.. zeek:id:: Broker::publish_id
   :source-code: base/frameworks/broker/main.zeek 503 506

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, id: :zeek:type:`string`) : :zeek:type:`bool`

   Publishes the value of an identifier to a given topic.  The subscribers
   will update their local value for that identifier on receipt.
   

   :param topic: a topic associated with the message.
   

   :param id: the identifier to publish.
   

   :returns: true if the message is sent.

.. zeek:id:: Broker::subscribe
   :source-code: base/frameworks/broker/main.zeek 508 511

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`

   Register interest in all peer event messages that use a certain topic
   prefix.  Note that subscriptions may not be altered immediately after
   calling (except during :zeek:see:`zeek_init`).
   

   :param topic_prefix: a prefix to match against remote message topics.
                 e.g. an empty prefix matches everything and "a" matches
                 "alice" and "amy" but not "bob".
   

   :returns: true if it's a new event subscription and it is now registered.

.. zeek:id:: Broker::unpeer
   :source-code: base/frameworks/broker/main.zeek 473 476

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`

   Remove a remote connection.
   
   Note that this does not terminate the connection to the peer, it
   just means that we won't exchange any further information with it
   unless peering resumes later.
   

   :param a: the address used in previous successful call to :zeek:see:`Broker::peer`.
   

   :param p: the port used in previous successful call to :zeek:see:`Broker::peer`.
   

   :returns: true if the arguments match a previously successful call to
            :zeek:see:`Broker::peer`.
   

   :param TODO: We do not have a function yet to terminate a connection.

.. zeek:id:: Broker::unsubscribe
   :source-code: base/frameworks/broker/main.zeek 518 521

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`

   Unregister interest in all peer event messages that use a topic prefix.
   Note that subscriptions may not be altered immediately after calling
   (except during :zeek:see:`zeek_init`).
   

   :param topic_prefix: a prefix previously supplied to a successful call to
                 :zeek:see:`Broker::subscribe` or :zeek:see:`Broker::forward`.
   

   :returns: true if interest in the topic prefix is no longer advertised.


