##! This framework is intended to create an output and filtering path for
##! internal messages/warnings/errors.  It should typically be loaded to
##! log such messages to a file in a standard way.  For the options to
##! toggle whether messages are additionally written to STDERR, see
##! :zeek:see:`Reporter::info_to_stderr`,
##! :zeek:see:`Reporter::warnings_to_stderr`, and
##! :zeek:see:`Reporter::errors_to_stderr`.
##!
##! Note that this framework deals with the handling of internally generated
##! reporter messages, for the interface
##! into actually creating reporter messages from the scripting layer, use
##! the built-in functions in :doc:`/scripts/base/bif/reporter.bif.zeek`.

module Reporter;

export {
	## The reporter logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type which contains the column fields of the reporter log.
	type Info: record {
		## The network time at which the reporter event was generated.
		ts:       time   &log;
		## The severity of the reporter message. Levels are INFO for informational
		## messages, not needing specific attention; WARNING for warning of a potential
		## problem, and ERROR for a non-fatal error that should be addressed, but doesn't
		## terminate program execution.
		level:    Level  &log;
		## An info/warning/error message that could have either been
		## generated from the internal Zeek core or at the scripting-layer.
		message:  string &log;
		## This is the location in a Zeek script where the message originated.
		## Not all reporter messages will have locations in them though.
		location: string &log &optional;
	};
}

event zeek_init() &priority=5
	{
	Log::create_stream(Reporter::LOG, [$columns=Info, $path="reporter", $policy=log_policy]);
	}

event reporter_info(t: time, msg: string, location: string) &priority=-5
	{
	Log::write(Reporter::LOG, [$ts=t, $level=INFO, $message=msg, $location=location]);
	}

event reporter_warning(t: time, msg: string, location: string) &priority=-5
	{
	Log::write(Reporter::LOG, [$ts=t, $level=WARNING, $message=msg, $location=location]);
	}

event reporter_error(t: time, msg: string, location: string) &priority=-5
	{
	Log::write(Reporter::LOG, [$ts=t, $level=ERROR, $message=msg, $location=location]);
	}
