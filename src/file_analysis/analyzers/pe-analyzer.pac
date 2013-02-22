

refine connection File += {

	function proc_sig(sig: bytestring) : bool
		%{
		if ( strcmp("MZ", (const char *) ${sig}.data()) == 0 )
			printf("yep: %s\n", ${sig}.data());
		return true;
		%}

};

refine typeattr DOSStub += &let {
	proc : bool = $context.connection.proc_sig(signature);
};
