##! This framework is intended to create an output and filtering path for
##! internal messages/warnings/errors.  It should typically be loaded to
##! log such messages to a file in a standard way.  For the options to
##! toggle whether messages are additionally written to STDERR, see
##! :bro:see:`Reporter::info_to_stderr`,
##! :bro:see:`Reporter::warnings_to_stderr`, and
##! :bro:see:`Reporter::errors_to_stderr`.
##!
##! Note that this framework deals with the handling of internally generated
##! reporter messages, for the interface
##! into actually creating reporter messages from the scripting layer, use
##! the built-in functions in :doc:`/scripts/base/bif/reporter.bif.bro`.

module Reporter;

export {
	## The reporter logging stream identifier.
	redef enum Log::ID += { LOG };

	## An indicator of reporter message severity.
	type Level: enum {
		## Informational, not needing specific attention.
		INFO,
		## Warning of a potential problem.
		WARNING,
		## A non-fatal error that should be addressed, but doesn't
		## terminate program execution.
		ERROR
	};

	## The record type which contains the column fields of the reporter log.
	type Info: record {
		## The network time at which the reporter event was generated.
		ts:       time   &log;
		## The severity of the reporter message.
		level:    Level  &log;
		## An info/warning/error message that could have either been
		## generated from the internal Bro core or at the scripting-layer.
		message:  string &log;
		## This is the location in a Bro script where the message originated.
		## Not all reporter messages will have locations in them though.
		location: string &log &optional;
	};
}

event bro_init() &priority=5
	{
	Log::create_stream(Reporter::LOG, [$columns=Info]);
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
