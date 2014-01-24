
%extern{
#include "Event.h"
#include "file_analysis/File.h"
#include "events.bif.h"
#include "types.bif.h"
%}

refine flow Flow += {

	%member{
	%}

	%init{
	%}

	%eof{
	%}

	%cleanup{
	%}

	function proc_file() : bool
		%{
		printf("Processed file.\n");
		return true;
		%}

};

refine typeattr File += &let {
	proc : bool = $context.flow.proc_file();
};