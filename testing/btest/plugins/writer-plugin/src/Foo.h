
#pragma once

#include "Desc.h"
#include "logging/WriterBackend.h"
#include "threading/formatters/Ascii.h"

namespace btest::logging::writer
	{

class Foo : public zeek::logging::WriterBackend
	{
public:
	Foo(zeek::logging::WriterFrontend* frontend) : zeek::logging::WriterBackend(frontend) { }
	~Foo();

	static zeek::logging::WriterBackend* Instantiate(zeek::logging::WriterFrontend* frontend)
		{
		return new Foo(frontend);
		}

protected:
	virtual bool DoInit(const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
	                    const zeek::threading::Field* const* fields);

	virtual bool DoWrite(int num_fields, const zeek::threading::Field* const* fields,
	                     zeek::threading::Value** vals);
	virtual bool DoSetBuf(bool enabled) { return true; }
	virtual bool DoRotate(const char* rotated_path, double open, double close, bool terminating)
		{
		return true;
		}
	virtual bool DoFlush(double network_time) { return true; }
	virtual bool DoFinish(double network_time) { return true; }
	virtual bool DoHeartbeat(double network_time, double current_time) { return true; }

private:
	std::string path;
	zeek::ODesc desc;
	zeek::threading::Formatter* formatter;
	};

	}
