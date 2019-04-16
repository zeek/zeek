:tocdepth: 3

base/frameworks/reporter/main.zeek
==================================
.. bro:namespace:: Reporter

This framework is intended to create an output and filtering path for
internal messages/warnings/errors.  It should typically be loaded to
log such messages to a file in a standard way.  For the options to
toggle whether messages are additionally written to STDERR, see
:bro:see:`Reporter::info_to_stderr`,
:bro:see:`Reporter::warnings_to_stderr`, and
:bro:see:`Reporter::errors_to_stderr`.

Note that this framework deals with the handling of internally generated
reporter messages, for the interface
into actually creating reporter messages from the scripting layer, use
the built-in functions in :doc:`/scripts/base/bif/reporter.bif.zeek`.

:Namespace: Reporter

Summary
~~~~~~~
Types
#####
============================================== =====================================================================
:bro:type:`Reporter::Info`: :bro:type:`record` The record type which contains the column fields of the reporter log.
============================================== =====================================================================

Redefinitions
#############
===================================== =======================================
:bro:type:`Log::ID`: :bro:type:`enum` The reporter logging stream identifier.
===================================== =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Reporter::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The network time at which the reporter event was generated.

      level: :bro:type:`Reporter::Level` :bro:attr:`&log`
         The severity of the reporter message. Levels are INFO for informational
         messages, not needing specific attention; WARNING for warning of a potential
         problem, and ERROR for a non-fatal error that should be addressed, but doesn't
         terminate program execution.

      message: :bro:type:`string` :bro:attr:`&log`
         An info/warning/error message that could have either been
         generated from the internal Bro core or at the scripting-layer.

      location: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         This is the location in a Bro script where the message originated.
         Not all reporter messages will have locations in them though.

   The record type which contains the column fields of the reporter log.


