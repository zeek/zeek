
#pragma once

#include "input/ReaderBackend.h"
#include "threading/formatters/Ascii.h"

namespace input { namespace reader {

/**
 * A Foo reader to measure performance of the input framework.
 */
class Foo : public ReaderBackend {
public:
	Foo(ReaderFrontend* frontend);
	~Foo();

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Foo(frontend); }

protected:
	virtual bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields);
	virtual void DoClose();
	virtual bool DoUpdate();
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	std::string RandomString(const int len);
	threading::Value* EntryToVal(zeek::TypeTag Type, zeek::TypeTag subtype);
	threading::formatter::Ascii* ascii;
};

} }
