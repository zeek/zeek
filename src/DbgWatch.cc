// Implementation of watches

#include "zeek-config.h"

#include "Debug.h"
#include "DbgWatch.h"
#include "Reporter.h"

// Support classes
DbgWatch::DbgWatch(BroObj* var_to_watch)
	{
	reporter->InternalError("DbgWatch unimplemented");
	}

DbgWatch::DbgWatch(Expr* expr_to_watch)
	{
	reporter->InternalError("DbgWatch unimplemented");
	}

DbgWatch::~DbgWatch()
	{
	}
