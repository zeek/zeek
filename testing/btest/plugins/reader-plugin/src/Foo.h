
#pragma once

#include "input/ReaderBackend.h"
#include "threading/formatters/Ascii.h"

namespace btest::input::reader
	{

/**
 * A Foo reader to measure performance of the input framework.
 */
class Foo : public zeek::input::ReaderBackend
	{
public:
	Foo(zeek::input::ReaderFrontend* frontend);
	~Foo();

	static zeek::input::ReaderBackend* Instantiate(zeek::input::ReaderFrontend* frontend)
		{
		return new Foo(frontend);
		}

protected:
	virtual bool DoInit(const zeek::input::ReaderBackend::ReaderInfo& info, int arg_num_fields,
	                    const zeek::threading::Field* const* fields);
	virtual void DoClose();
	virtual bool DoUpdate();
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	std::string RandomString(const int len);
	zeek::threading::Value* EntryToVal(zeek::TypeTag Type, zeek::TypeTag subtype);
	zeek::threading::formatter::Ascii* ascii;
	};

	}
