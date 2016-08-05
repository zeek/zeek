%extern{
#include "util.h"
%}

function network_time(): double
	%{
	return ::network_time;
	%}

