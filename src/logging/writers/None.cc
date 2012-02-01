
#include "None.h"

using namespace logging;
using namespace writer;

bool None::DoRotate(string rotated_path, double open, double close, bool terminating)
	{
	if ( ! FinishedRotation(string("/dev/null"), Path(), open, close, terminating))
		{
		Error(Fmt("error rotating %s", Path().c_str()));
		return false;
		}

	return true;
	}


