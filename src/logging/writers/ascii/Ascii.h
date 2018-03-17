// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for delimiter-separated ASCII logs.

#ifndef LOGGING_WRITER_ASCII_H
#define LOGGING_WRITER_ASCII_H

#include "logging/WriterBackend.h"
#include "threading/formatters/Ascii.h"
#include "threading/formatters/JSON.h"
#include "zlib.h"

namespace logging { namespace writer {

class Ascii : public WriterBackend {
public:
	explicit Ascii(WriterFrontend* frontend);
	~Ascii() override;

	static string LogExt();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new Ascii(frontend); }

protected:
	bool DoInit(const WriterInfo& info, int num_fields,
			    const threading::Field* const* fields) override;
	bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals) override;
	bool DoSetBuf(bool enabled) override;
	bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating) override;
	bool DoFlush(double network_time) override;
	bool DoFinish(double network_time) override;
	bool DoHeartbeat(double network_time, double current_time) override;

private:
	bool IsSpecial(const string &path) 	{ return path.find("/dev/") == 0; }
	bool WriteHeader(const string& path);
	bool WriteHeaderField(const string& key, const string& value);
	void CloseFile(double t);
	string Timestamp(double t); // Uses current time if t is zero.
	void InitConfigOptions();
	bool InitFilterOptions();
	bool InitFormatter();
	bool InternalWrite(int fd, const char* data, int len);
	bool InternalClose(int fd);

	int fd;
	gzFile gzfile;
	string fname;
	ODesc desc;
	bool ascii_done;

	// Options set from the script-level.
	bool output_to_stdout;
	bool include_meta;
	bool tsv;

	string separator;
	string set_separator;
	string empty_field;
	string unset_field;
	string meta_prefix;

	int gzip_level; // level > 0 enables gzip compression
	bool use_json;
	string json_timestamps;

	threading::formatter::Formatter* formatter;
	bool init_options;
};

}
}


#endif
