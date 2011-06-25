// Implementation of watches

#include "config.h"

#include "Debug.h"
#include "DbgWatch.h"
#include "Logger.h"

// Support classes
DbgWatch::DbgWatch(BroObj* var_to_watch)
	{
	bro_logger->InternalError("DbgWatch unimplemented");
	}

DbgWatch::DbgWatch(Expr* expr_to_watch)
	{
	bro_logger->InternalError("DbgWatch unimplemented");
	}

DbgWatch::~DbgWatch()
	{
	}
