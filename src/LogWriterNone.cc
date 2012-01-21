
#include "LogWriterNone.h"
LogWriter* LogWriterNone::Instantiate(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue)	
{ 
	return new LogWriterNone(parent, in_queue, out_queue); 
}

LogWriterNone::LogWriterNone(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue)
	: LogWriter(parent, in_queue, out_queue)
	{
	}

LogWriterNone::~LogWriterNone()
	{
	}

bool LogWriterNone::DoRotate(string rotated_path, double open,
			      double close, bool terminating)
	{
	if ( ! FinishedRotation(string("/dev/null"), parent.Path(), open, close, terminating))
		{
		Error(Fmt("error rotating %s", parent.Path().c_str()));
		return false;
		}

	return true;
	}


