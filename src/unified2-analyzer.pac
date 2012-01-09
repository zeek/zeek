
refine flow Flow += {

	%member{
	%}

	%init{
	%}

	%eof{
	%}

	%cleanup{
	%}

	function proc_ids_event(ev: IDSEvent) : bool
		%{
		printf("woo!\n");
		return true;
		%}
};


refine typeattr IDSEvent += &let {
	proc : bool = $context.flow.proc_ids_event(this);
};
