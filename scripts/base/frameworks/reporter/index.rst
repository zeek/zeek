:orphan:

Package: base/frameworks/reporter
=================================

This framework is intended to create an output and filtering path for
internally generated messages/warnings/errors.

:doc:`/scripts/base/frameworks/reporter/__load__.zeek`


:doc:`/scripts/base/frameworks/reporter/main.zeek`

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

