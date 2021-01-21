// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <vector>
#include <memory>
#include <mutex>

#include "zeek/input/ReaderBackend.h"

namespace zeek::input::reader::detail {

/**
 * A reader that returns a file (or the output of a command) as a single
 * blob.
 */
class Raw : public ReaderBackend {
public:
	explicit Raw(ReaderFrontend* frontend);
	~Raw() override;

	// prohibit copying and moving
	Raw(const Raw&) = delete;
	Raw(Raw&&) = delete;
	Raw& operator=(const Raw&) = delete;
	Raw& operator=(Raw&&) = delete;

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Raw(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	void ClosePipeEnd(int i);
	bool SetFDFlags(int fd, int cmd, int flags);
	std::unique_lock<std::mutex> AcquireForkMutex();

	bool OpenInput();
	bool CloseInput();
	int64_t GetLine(FILE* file);
	bool Execute();
	void WriteToStdin();

	std::string fname; // Source with a potential "|" removed.
	std::unique_ptr<FILE, int(*)(FILE*)> file;
	std::unique_ptr<FILE, int(*)(FILE*)> stderrfile;
	bool execute;
	bool firstrun;
	time_t mtime;
	ino_t ino;

	// options set from the script-level.
	std::string separator;
	unsigned int sep_length; // length of the separator

	int bufpos;
	std::unique_ptr<char[]> buf;
	std::unique_ptr<char[]> outbuf;

	int stdin_fileno;
	int stdout_fileno;
	int stderr_fileno;

	std::string stdin_string;
	uint64_t stdin_towrite;

	bool use_stderr;

	bool forcekill;

	int64_t offset;

	int pipes[6];
	pid_t childpid;

	enum IoChannels {
		stdout_in = 0,
		stdout_out = 1,
		stdin_in = 2,
		stdin_out = 3,
		stderr_in = 4,
		stderr_out = 5
	};

	static const int block_size;
};

} // namespace zeek::input::reader::detail
