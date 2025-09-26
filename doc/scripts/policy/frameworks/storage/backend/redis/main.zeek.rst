:tocdepth: 3

policy/frameworks/storage/backend/redis/main.zeek
=================================================
.. zeek:namespace:: Storage::Backend::Redis

Redis storage backend support

:Namespace: Storage::Backend::Redis
:Imports: :doc:`base/frameworks/storage/main.zeek </scripts/base/frameworks/storage/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================== ==============================================
:zeek:id:`Storage::Backend::Redis::default_connect_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`   Default value for connection attempt timeouts.
:zeek:id:`Storage::Backend::Redis::default_operation_timeout`: :zeek:type:`interval` :zeek:attr:`&redef` Default value for operation timeouts.
======================================================================================================== ==============================================

Types
#####
================================================================== ==============================================
:zeek:type:`Storage::Backend::Redis::Options`: :zeek:type:`record` Options record for the built-in Redis backend.
================================================================== ==============================================

Redefinitions
#############
========================================================= =============================================================================
:zeek:type:`Storage::BackendOptions`: :zeek:type:`record` 
                                                          
                                                          :New Fields: :zeek:type:`Storage::BackendOptions`
                                                          
                                                            redis: :zeek:type:`Storage::Backend::Redis::Options` :zeek:attr:`&optional`
========================================================= =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Storage::Backend::Redis::default_connect_timeout
   :source-code: policy/frameworks/storage/backend/redis/main.zeek 10 10

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   Default value for connection attempt timeouts. This can be overridden
   per-connection with the ``connect_timeout`` backend option.

.. zeek:id:: Storage::Backend::Redis::default_operation_timeout
   :source-code: policy/frameworks/storage/backend/redis/main.zeek 14 14

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   Default value for operation timeouts. This can be overridden per-connection
   with the ``operation_timeout`` backend option.

Types
#####
.. zeek:type:: Storage::Backend::Redis::Options
   :source-code: policy/frameworks/storage/backend/redis/main.zeek 17 49

   :Type: :zeek:type:`record`


   .. zeek:field:: server_host :zeek:type:`string` :zeek:attr:`&optional`


   .. zeek:field:: server_port :zeek:type:`port` :zeek:attr:`&default` = ``6379/tcp`` :zeek:attr:`&optional`


   .. zeek:field:: server_unix_socket :zeek:type:`string` :zeek:attr:`&optional`


   .. zeek:field:: key_prefix :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`


   .. zeek:field:: connect_timeout :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Storage::Backend::Redis::default_connect_timeout` :zeek:attr:`&optional`

      Timeout for connection attempts to the backend. Connection attempts
      that exceed this time will return
      :zeek:see:`Storage::CONNECTION_FAILED`.


   .. zeek:field:: operation_timeout :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Storage::Backend::Redis::default_operation_timeout` :zeek:attr:`&optional`

      Timeout for operation requests sent to the backend. Operations that
      exceed this time will return :zeek:see:`Storage::TIMEOUT`.


   .. zeek:field:: username :zeek:type:`string` :zeek:attr:`&optional`

      A username to use for authentication the server is protected by an ACL.


   .. zeek:field:: password :zeek:type:`string` :zeek:attr:`&optional`

      A username to use for authentication the server is protected by an ACL
      or by a simple password.


   Options record for the built-in Redis backend.


