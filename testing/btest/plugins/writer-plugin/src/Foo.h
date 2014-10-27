
#ifndef BRO_PLUGIN_DEMO_FOO_H
#define BRO_PLUGIN_DEMO_FOO_H

#include "logging/WriterBackend.h"
#include "threading/formatters/Ascii.h"

namespace logging { namespace writer {

class Foo : public WriterBackend {
public:
	Foo(WriterFrontend* frontend) : WriterBackend(frontend)	{}
	~Foo()	{};

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new Foo(frontend); }

protected:
	virtual bool DoInit(const WriterInfo& info, int num_fields,
			    const threading::Field* const * fields);

	virtual bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals);
	virtual bool DoSetBuf(bool enabled)	{ return true; }
	virtual bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating) { return true; }
	virtual bool DoFlush(double network_time)	{ return true; }
	virtual bool DoFinish(double network_time)	{ return true; }
	virtual bool DoHeartbeat(double network_time, double current_time)	{ return true; }

private:
    string path;
	ODesc desc;
	threading::formatter::Formatter* formatter;
};

} }

#endif
