:tocdepth: 3

base/frameworks/reporter/main.zeek
==================================
.. zeek:namespace:: Reporter

This framework is intended to create an output and filtering path for
internal messages/warnings/errors.  It should typically be loaded to
log such messages to a file in a standard way.  For the options to
toggle whether messages are additionally written to STDERR, see
:zeek:see:`Reporter::info_to_stderr`,
:zeek:see:`Reporter::warnings_to_stderr`, and
:zeek:see:`Reporter::errors_to_stderr`.

Note that this framework deals with the handling of internally generated
reporter messages, for the interface
into actually creating reporter messages from the scripting layer, use
the built-in functions in :doc:`/scripts/base/bif/reporter.bif.zeek`.

:Namespace: Reporter

Summary
~~~~~~~
Types
#####
================================================ =====================================================================
:zeek:type:`Reporter::Info`: :zeek:type:`record` The record type which contains the column fields of the reporter log.
================================================ =====================================================================

Redefinitions
#############
======================================= =======================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The reporter logging stream identifier.
                                        
                                        * :zeek:enum:`Reporter::LOG`
======================================= =======================================

Hooks
#####
============================================================= =============================================
:zeek:id:`Reporter::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
============================================================= =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Reporter::Info
   :source-code: base/frameworks/reporter/main.zeek 24 38

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The network time at which the reporter event was generated.

      level: :zeek:type:`Reporter::Level` :zeek:attr:`&log`
         The severity of the reporter message. Levels are INFO for informational
         messages, not needing specific attention; WARNING for warning of a potential
         problem, and ERROR for a non-fatal error that should be addressed, but doesn't
         terminate program execution.

      message: :zeek:type:`string` :zeek:attr:`&log`
         An info/warning/error message that could have either been
         generated from the internal Zeek core or at the scripting-layer.

      location: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         This is the location in a Zeek script where the message originated.
         Not all reporter messages will have locations in them though.

   The record type which contains the column fields of the reporter log.

Hooks
#####
.. zeek:id:: Reporter::log_policy
   :source-code: base/frameworks/reporter/main.zeek 21 21

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


