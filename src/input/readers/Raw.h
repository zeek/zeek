// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_RAW_H
#define INPUT_READERS_RAW_H

#include <vector>
#include <pthread.h>

#include "../ReaderBackend.h"

namespace input { namespace reader {

/**
 * A reader that returns a file (or the output of a command) as a single
 * blob.
 */
class Raw : public ReaderBackend {
public:
	Raw(ReaderFrontend* frontend);
	~Raw();

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Raw(frontend); }

	static bool ClassInit();

protected:
	virtual bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields);
	virtual void DoClose();
	virtual bool DoUpdate();
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	void ClosePipeEnd(int i);
	bool SetFDFlags(int fd, int cmd, int flags);
	bool LockForkMutex();
	bool UnlockForkMutex();

	bool OpenInput();
	bool CloseInput();
	int64_t GetLine(FILE* file);
	bool Execute();
	void WriteToStdin();

	string fname; // Source with a potential "|" removed.
	FILE* file;
	FILE* stderrfile;
	bool execute;
	bool firstrun;
	time_t mtime;

	// options set from the script-level.
	string separator;
	unsigned int sep_length; // length of the separator

	int bufpos;
	char* buf;
	char* outbuf;

	int stdin_fileno;
	int stdout_fileno;
	int stderr_fileno;

	string stdin_string;
	uint64_t stdin_towrite;

	bool use_stderr;

	bool forcekill;

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
	static pthread_mutex_t fork_mutex;
};

}
}

#endif /* INPUT_READERS_RAW_H */
