:tocdepth: 3

base/protocols/redis/main.zeek
==============================
.. zeek:namespace:: Redis


:Namespace: Redis
:Imports: :doc:`base/frameworks/signatures </scripts/base/frameworks/signatures/index>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/redis/spicy-events.zeek </scripts/base/protocols/redis/spicy-events.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== =
:zeek:id:`Redis::max_pending_commands`: :zeek:type:`count` :zeek:attr:`&redef` 
============================================================================== =

Redefinable Options
###################
============================================================= ================================
:zeek:id:`Redis::ports`: :zeek:type:`set` :zeek:attr:`&redef` The ports to register Redis for.
============================================================= ================================

State Variables
###############
========================================================= =
:zeek:id:`Redis::enter_subscribed_mode`: :zeek:type:`set` 
:zeek:id:`Redis::exit_subscribed_mode`: :zeek:type:`set`  
:zeek:id:`Redis::no_response_commands`: :zeek:type:`set`  
========================================================= =

Types
#####
===================================================== ===============================================================================
:zeek:type:`Redis::Info`: :zeek:type:`record`         Record type containing the column fields of the Redis log.
:zeek:type:`Redis::NoReplyRange`: :zeek:type:`record` Which numbered commands should not expect a reply due to CLIENT REPLY commands.
:zeek:type:`Redis::RESPVersion`: :zeek:type:`enum`    
:zeek:type:`Redis::State`: :zeek:type:`record`        
===================================================== ===============================================================================

Redefinitions
#############
============================================ ===============================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      Log stream identifier.
                                             
                                             * :zeek:enum:`Redis::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               redis: :zeek:type:`Redis::Info` :zeek:attr:`&optional`
                                             
                                               redis_state: :zeek:type:`Redis::State` :zeek:attr:`&optional`
============================================ ===============================================================

Hooks
#####
================================================================ =============================================
:zeek:id:`Redis::finalize_redis`: :zeek:type:`Conn::RemovalHook` 
:zeek:id:`Redis::log_policy`: :zeek:type:`Log::PolicyHook`       A default logging policy hook for the stream.
================================================================ =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Redis::max_pending_commands
   :source-code: base/protocols/redis/main.zeek 74 74

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10000``


Redefinable Options
###################
.. zeek:id:: Redis::ports
   :source-code: base/protocols/redis/main.zeek 13 13

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            6379/tcp
         }


   The ports to register Redis for.

State Variables
###############
.. zeek:id:: Redis::enter_subscribed_mode
   :source-code: base/protocols/redis/main.zeek 77 77

   :Type: :zeek:type:`set` [:zeek:type:`Redis::RedisCommand`]
   :Default:

      ::

         {
            Redis::RedisCommand_PSUBSCRIBE,
            Redis::RedisCommand_SSUBSCRIBE,
            Redis::RedisCommand_SUBSCRIBE
         }



.. zeek:id:: Redis::exit_subscribed_mode
   :source-code: base/protocols/redis/main.zeek 81 81

   :Type: :zeek:type:`set` [:zeek:type:`Redis::RedisCommand`]
   :Default:

      ::

         {
            Redis::RedisCommand_RESET,
            Redis::RedisCommand_QUIT
         }



.. zeek:id:: Redis::no_response_commands
   :source-code: base/protocols/redis/main.zeek 84 84

   :Type: :zeek:type:`set` [:zeek:type:`Redis::RedisCommand`]
   :Default:

      ::

         {
            Redis::RedisCommand_SSUBSCRIBE,
            Redis::RedisCommand_SUBSCRIBE,
            Redis::RedisCommand_PUNSUBSCRIBE,
            Redis::RedisCommand_SUNSUBSCRIBE,
            Redis::RedisCommand_UNSUBSCRIBE,
            Redis::RedisCommand_PSUBSCRIBE
         }



Types
#####
.. zeek:type:: Redis::Info
   :source-code: base/protocols/redis/main.zeek 16 29

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the activity happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: cmd :zeek:type:`Redis::Command` :zeek:attr:`&log`

      The Redis command.


   .. zeek:field:: success :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      If the command was successful. Only set if the server responded.


   .. zeek:field:: reply :zeek:type:`Redis::ReplyData` :zeek:attr:`&log` :zeek:attr:`&optional`

      The reply for the command.


   Record type containing the column fields of the Redis log.

.. zeek:type:: Redis::NoReplyRange
   :source-code: base/protocols/redis/main.zeek 39 42

   :Type: :zeek:type:`record`


   .. zeek:field:: begin :zeek:type:`count`


   .. zeek:field:: end :zeek:type:`count` :zeek:attr:`&optional`


   Which numbered commands should not expect a reply due to CLIENT REPLY commands.
   These commands may simply skip one, or they may turn off replies then later
   reenable them. Thus, the end of the interval is optional.

.. zeek:type:: Redis::RESPVersion
   :source-code: base/protocols/redis/main.zeek 44 48

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Redis::RESP2 Redis::RESPVersion

      .. zeek:enum:: Redis::RESP3 Redis::RESPVersion


.. zeek:type:: Redis::State
   :source-code: base/protocols/redis/main.zeek 49 70

   :Type: :zeek:type:`record`


   .. zeek:field:: pending :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`Redis::Info`

      Pending commands.


   .. zeek:field:: current_command :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Current command in the pending queue.


   .. zeek:field:: current_reply :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Current reply in the pending queue.


   .. zeek:field:: no_reply_ranges :zeek:type:`vector` of :zeek:type:`Redis::NoReplyRange`

      Ranges where we do not expect a reply due to CLIENT REPLY commands.
      Each range is one or two elements, one meaning it's unbounded, two meaning
      it begins at one and ends at the second.


   .. zeek:field:: skip_commands :zeek:type:`set` [:zeek:type:`count`]

      The command indexes (from current_command and current_reply) that will
      not get responses no matter what.


   .. zeek:field:: violation :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      We store if this analyzer had a violation to avoid logging if so.
      This should not be super necessary, but worth a shot.


   .. zeek:field:: subscribed_mode :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      If we are in "subscribed" mode


   .. zeek:field:: resp_version :zeek:type:`Redis::RESPVersion` :zeek:attr:`&default` = ``Redis::RESP2`` :zeek:attr:`&optional`

      The RESP version



Hooks
#####
.. zeek:id:: Redis::finalize_redis
   :source-code: base/protocols/redis/main.zeek 337 355

   :Type: :zeek:type:`Conn::RemovalHook`


.. zeek:id:: Redis::log_policy
   :source-code: base/protocols/redis/main.zeek 32 32

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


