// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <iostream>
#include <vector>
#include <fstream>
#include <memory>
#include <unordered_map>
#include <sys/types.h>

#include "input/ReaderBackend.h"
#include "threading/formatters/Ascii.h"

namespace zeek::input::reader::detail {

/**
 * Reader for Configuration files.
 */
class Config : public zeek::input::ReaderBackend {
public:
	explicit Config(zeek::input::ReaderFrontend* frontend);
	~Config() override;

	// prohibit copying and moving
	Config(const Config&) = delete;
	Config(Config&&) = delete;
	Config& operator=(const Config&) = delete;
	Config& operator=(Config&&) = delete;

	static zeek::input::ReaderBackend* Instantiate(zeek::input::ReaderFrontend* frontend) { return new Config(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	bool GetLine(std::string& str);
	bool OpenFile();

	std::ifstream file;
	time_t mtime;
	ino_t ino;

	bool fail_on_file_problem;

	std::string set_separator;
	std::string empty_field;

	std::unique_ptr<zeek::threading::Formatter> formatter;
	std::unordered_map<std::string, std::tuple<zeek::TypeTag, zeek::TypeTag>> option_types;
	std::unordered_map<std::string, std::string> option_values;
};

} // namespace zeek::input::reader::detail

namespace input::reader {
	using Config [[deprecated("Remove in v4.1. Use zeek::input::reader::detail::Config.")]] = zeek::input::reader::detail::Config;
}
