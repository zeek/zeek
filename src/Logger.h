// $Id: Logger.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef logger_h
#define logger_h

#include "util.h"
#include "Obj.h"

class BroFile;
class Func;

class Logger : public BroObj {
public:
	Logger(const char* name, BroFile* f = 0);
	virtual ~Logger();

	void Log(const char* msg);

	void SetEnabled(int do_enabled)		{ enabled = do_enabled; }

	void Describe(ODesc* d) const;

protected:
	BroFile* f;	// associated file
	int enabled;	// if true, syslog'ing is done, otherwise just file log
};

extern Logger* bro_logger;
extern Func* alarm_hook;

#endif
