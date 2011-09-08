##! This framework is intended to create an output and filtering path for 
##! internal messages/warnings/errors.  It should typically be loaded to 
##! avoid Bro spewing internal messages to standard error.

module Reporter;

export {
	redef enum Log::ID += { LOG };
	
	type Level: enum { 
		INFO, 
		WARNING, 
		ERROR
	};
	
	type Info: record {
		ts:       time   &log;
		level:    Level  &log;
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

event reporter_info(t: time, msg: string, location: string)
	{
	Log::write(Reporter::LOG, [$ts=t, $level=INFO, $message=msg, $location=location]);
	}
	
event reporter_warning(t: time, msg: string, location: string)
	{
	Log::write(Reporter::LOG, [$ts=t, $level=WARNING, $message=msg, $location=location]);
	}

event reporter_error(t: time, msg: string, location: string)
	{
	Log::write(Reporter::LOG, [$ts=t, $level=ERROR, $message=msg, $location=location]);
	}
