/*
Acts as a bro script checkpoint, fired from within the bro scripting environment.

Meant to be used at regular intervals.
*/
provider bro_checkpoint {
	/*
	Called from script-land with two user-provided arguments.

	cl_1 is the first user-defined argument, and cl_2 is the 
	second.  The context of these arguments depends on the 
	dtrace script doing the processing.

	Returns true if dtrace is enabled, and false otherwise.
	*/
	probe fire(int ci_1, int ci_2);

	/*
	Offered as a mechanism by which to clear the current working
	data set.
	*/
	probe clear();
};

