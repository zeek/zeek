##! Interface for the raw input reader.

module InputRaw;

export {
	## Separator between input records.
	## Please note that the separator has to be exactly one character long.
	const record_separator = "\n" &redef;

	## Event that is called when a process created by the raw reader exits.
	##
	## name: name of the input stream.
	## source: source of the input stream.
	## exit_code: exit code of the program, or number of the signal that forced the program to exit.
	## signal_exit: false when program exited normally, true when program was forced to exit by a signal.
	global process_finished: event(name: string, source:string, exit_code:count, signal_exit:bool);
}
