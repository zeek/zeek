// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_CONFIG_H
#define INPUT_READERS_CONFIG_H

#include <iostream>
#include <vector>
#include <fstream>
#include <memory>
#include <unordered_map>
#include <sys/types.h>

#include "input/ReaderBackend.h"
#include "threading/formatters/Ascii.h"

namespace input { namespace reader {

/**
 * Reader for Configuration files.
 */
class Config : public ReaderBackend {
public:
	explicit Config(ReaderFrontend* frontend);
	~Config() override;

	// prohibit copying and moving
	Config(const Config&) = delete;
	Config(Config&&) = delete;
	Config& operator=(const Config&) = delete;
	Config& operator=(Config&&) = delete;

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Config(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	bool GetLine(string& str);
	bool OpenFile();
	// Call Warning or Error, depending on the is_error boolean.
	// In case of a warning, setting suppress_future to true will suppress all future warnings
	// (by setting suppress_warnings to true, until suppress_warnings is set back to false)
	void FailWarn(bool is_error, const char *msg, bool suppress_future = false);

	ifstream file;
	time_t mtime;
	ino_t ino;

	bool fail_on_file_problem;
	// this is an internal indicator in case the read is currently in a failed state
	// it's used to suppress duplicate error messages.
	bool suppress_warnings;

	string set_separator;
	string empty_field;

	std::unique_ptr<threading::formatter::Formatter> formatter;
	std::unordered_map<std::string, std::tuple<TypeTag, TypeTag>> option_types;
	std::unordered_map<std::string, std::string> option_values;
};


}
}

#endif /* INPUT_READERS_CONFIG_H */
