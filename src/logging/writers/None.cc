
#include "None.h"

using namespace logging;
using namespace writer;

bool None::DoRotate(string rotated_path, const RotateInfo& info, bool terminating)
	{
	if ( ! FinishedRotation(string("/dev/null"), Path(), info, terminating))
		{
		Error(Fmt("error rotating %s", Path().c_str()));
		return false;
		}

	return true;
	}


