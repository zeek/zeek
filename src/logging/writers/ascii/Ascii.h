// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for delimiter-separated ASCII logs.

#pragma once

#include "logging/WriterBackend.h"
#include "threading/formatters/Ascii.h"
#include "threading/formatters/JSON.h"
#include "Desc.h"
#include "zlib.h"

namespace plugin::Zeek_AsciiWriter { class Plugin; }

namespace logging { namespace writer {

class Ascii : public WriterBackend {
public:
	explicit Ascii(WriterFrontend* frontend);
	~Ascii() override;

	static std::string LogExt();

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
	friend class plugin::Zeek_AsciiWriter::Plugin;

	static void RotateLeftoverLogs();

	bool IsSpecial(const std::string &path) 	{ return path.find("/dev/") == 0; }
	bool WriteHeader(const std::string& path);
	bool WriteHeaderField(const std::string& key, const std::string& value);
	void CloseFile(double t);
	std::string Timestamp(double t); // Uses current time if t is zero.
	void InitConfigOptions();
	bool InitFilterOptions();
	bool InitFormatter();
	bool InternalWrite(int fd, const char* data, int len);
	bool InternalClose(int fd);

	int fd;
	gzFile gzfile;
	std::string fname;
	ODesc desc;
	bool ascii_done;

	// Options set from the script-level.
	bool output_to_stdout;
	bool include_meta;
	bool tsv;

	std::string separator;
	std::string set_separator;
	std::string empty_field;
	std::string unset_field;
	std::string meta_prefix;

	int gzip_level; // level > 0 enables gzip compression
	std::string gzip_file_extension;
	bool use_json;
	bool enable_utf_8;
	std::string json_timestamps;

	threading::formatter::Formatter* formatter;
	bool init_options;
};

}
}
