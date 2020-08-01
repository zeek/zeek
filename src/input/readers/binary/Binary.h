// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <fstream>
#include <sys/types.h>

#include "input/ReaderBackend.h"

namespace zeek::input::reader::detail {

/**
 * Binary mode file reader.
 */
class Binary : public zeek::input::ReaderBackend {
public:
	explicit Binary(zeek::input::ReaderFrontend* frontend);
	~Binary() override;

	static zeek::input::ReaderBackend* Instantiate(zeek::input::ReaderFrontend* frontend)
		{ return new Binary(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields,
	            const threading::Field* const* fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	bool OpenInput();
	bool CloseInput();
	std::streamsize GetChunk(char** chunk);
	int UpdateModificationTime();

	std::string fname;
	std::ifstream* in;
	time_t mtime;
	ino_t ino;
	bool firstrun;

	// options set from the script-level.
	static std::streamsize chunk_size;
	std::string path_prefix;
};

} // namespace zeek::input::reader::detail

namespace input::reader {
	using Binary [[deprecated("Remove in v4.1. Use zeek::input::reader::detail::Binary.")]] = zeek::input::reader::detail::Binary;
}
