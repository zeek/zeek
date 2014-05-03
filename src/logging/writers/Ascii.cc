// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "Ascii.h"

using namespace logging::writer;
using namespace threading;
using threading::Value;
using threading::Field;

Ascii::Ascii(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	fd = 0;
	ascii_done = false;
	output_to_stdout = false;
	include_meta = false;
	tsv = false;
	use_json = false;
	formatter = 0;

	InitConfigOptions();
	init_options = InitFilterOptions();
	}

void Ascii::InitConfigOptions()
	{
	output_to_stdout = BifConst::LogAscii::output_to_stdout;
	include_meta = BifConst::LogAscii::include_meta;
	use_json = BifConst::LogAscii::use_json;

	separator.assign(
			(const char*) BifConst::LogAscii::separator->Bytes(),
			BifConst::LogAscii::separator->Len()
			);

	set_separator.assign(
			(const char*) BifConst::LogAscii::set_separator->Bytes(),
			BifConst::LogAscii::set_separator->Len()
			);

	empty_field.assign(
			(const char*) BifConst::LogAscii::empty_field->Bytes(),
			BifConst::LogAscii::empty_field->Len()
			);

	unset_field.assign(
			(const char*) BifConst::LogAscii::unset_field->Bytes(),
			BifConst::LogAscii::unset_field->Len()
			);

	meta_prefix.assign(
			(const char*) BifConst::LogAscii::meta_prefix->Bytes(),
			BifConst::LogAscii::meta_prefix->Len()
			);

	ODesc tsfmt;
	BifConst::LogAscii::json_timestamps->Describe(&tsfmt);
	json_timestamps.assign(
			(const char*) tsfmt.Bytes(),
			tsfmt.Len()
			);
	}

bool Ascii::InitFilterOptions()
	{
	const WriterInfo& info = Info();

	// Set per-filter configuration options.
	for ( WriterInfo::config_map::const_iterator i = info.config.begin();
	      i != info.config.end(); ++i )
		{
		if ( strcmp(i->first, "tsv") == 0 )
			{
			if ( strcmp(i->second, "T") == 0 )
				tsv = true;
			else if ( strcmp(i->second, "F") == 0 )
				tsv = false;
			else
				{
				Error("invalid value for 'tsv', must be a string and either \"T\" or \"F\"");
				return false;
				}
			}

		else if ( strcmp(i->first, "use_json") == 0 )
			{
			if ( strcmp(i->second, "T") == 0 )
				use_json = true;
			else if ( strcmp(i->second, "F") == 0 )
				use_json = false;
			else
				{
				Error("invalid value for 'use_json', must be a string and either \"T\" or \"F\"");
				return false;
				}
			}

		else if ( strcmp(i->first, "output_to_stdout") == 0 )
			{
			if ( strcmp(i->second, "T") == 0 )
				output_to_stdout = true;
			else if ( strcmp(i->second, "F") == 0 )
				output_to_stdout = false;
			else
				{
				Error("invalid value for 'output_to_stdout', must be a string and either \"T\" or \"F\"");
				return false;
				}
			}

		else if ( strcmp(i->first, "separator") == 0 )
			separator.assign(i->second);

		else if ( strcmp(i->first, "set_separator") == 0 )
			set_separator.assign(i->second);

		else if ( strcmp(i->first, "empty_field") == 0 )
			empty_field.assign(i->second);

		else if ( strcmp(i->first, "unset_field") == 0 )
			unset_field.assign(i->second);

		else if ( strcmp(i->first, "meta_prefix") == 0 )
			meta_prefix.assign(i->second);

		else if ( strcmp(i->first, "json_timestamps") == 0 )
			json_timestamps.assign(i->second);
		}

	if ( ! InitFormatter() )
		return false;

	return true;
	}

bool Ascii::InitFormatter()
	{
	delete formatter;
	formatter = 0;

	if ( use_json )
		{
		formatter::JSON::TimeFormat tf = formatter::JSON::TS_EPOCH;

		// Write out JSON formatted logs.
		if ( strcmp(json_timestamps.c_str(), "JSON::TS_EPOCH") == 0 )
			tf = formatter::JSON::TS_EPOCH;
		else if ( strcmp(json_timestamps.c_str(), "JSON::TS_MILLIS") == 0 )
			tf = formatter::JSON::TS_MILLIS;
		else if ( strcmp(json_timestamps.c_str(), "JSON::TS_ISO8601") == 0 )
			tf = formatter::JSON::TS_ISO8601;
		else
			{
			Error(Fmt("Invalid JSON timestamp format: %s", json_timestamps.c_str()));
			return false;
			}

		formatter = new formatter::JSON(this, tf);
		// Using JSON implicitly turns off the header meta fields.
		include_meta = false;
		}
	else
		{
		// Use the default "Bro logs" format.
		desc.EnableEscaping();
		desc.AddEscapeSequence(separator);
		formatter::Ascii::SeparatorInfo sep_info(separator, set_separator, unset_field, empty_field);
		formatter = new formatter::Ascii(this, sep_info);
		}

	return true;
	}

Ascii::~Ascii()
	{
	if ( ! ascii_done )
		{
		fprintf(stderr, "internal error: finish missing\n");
		abort();
		}

	delete formatter;
	}

bool Ascii::WriteHeaderField(const string& key, const string& val)
	{
	string str = meta_prefix + key + separator + val + "\n";

	return safe_write(fd, str.c_str(), str.length());
	}

void Ascii::CloseFile(double t)
	{
	if ( ! fd )
		return;

	if ( include_meta && ! tsv )
		WriteHeaderField("close", Timestamp(0));

	safe_close(fd);
	fd = 0;
	}

bool Ascii::DoInit(const WriterInfo& info, int num_fields, const Field* const * fields)
	{
	assert(! fd);

	if ( ! init_options )
		return false;

	string path = info.path;

	if ( output_to_stdout )
		path = "/dev/stdout";

	fname = IsSpecial(path) ? path : path + "." + LogExt();

	fd = open(fname.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);

	if ( fd < 0 )
		{
		Error(Fmt("cannot open %s: %s", fname.c_str(),
			  Strerror(errno)));
		fd = 0;
		return false;
		}

	if ( ! WriteHeader(path) )
		{
		Error(Fmt("error writing to %s: %s", fname.c_str(), Strerror(errno)));
		return false;
		}

	return true;
	}

bool Ascii::WriteHeader(const string& path)
	{
	if ( ! include_meta )
		return true;

	string names;
	string types;

	for ( int i = 0; i < NumFields(); ++i )
		{
		if ( i > 0 )
			{
			names += separator;
			types += separator;
			}

		names += string(Fields()[i]->name);
		types += Fields()[i]->TypeName().c_str();
		}

	if ( tsv )
		{
		// A single TSV-style line is all we need.
		string str = names + "\n";
		if ( ! safe_write(fd, str.c_str(), str.length()) )
			return false;

		return true;
		}

	string str = meta_prefix
		+ "separator " // Always use space as separator here.
		+ get_escaped_string(separator, false)
		+ "\n";

	if ( ! safe_write(fd, str.c_str(), str.length()) )
		return false;

	if ( ! (WriteHeaderField("set_separator", get_escaped_string(set_separator, false)) &&
	        WriteHeaderField("empty_field", get_escaped_string(empty_field, false)) &&
	        WriteHeaderField("unset_field", get_escaped_string(unset_field, false)) &&
	        WriteHeaderField("path", get_escaped_string(path, false)) &&
	        WriteHeaderField("open", Timestamp(0))) )
		return false;

	if ( ! (WriteHeaderField("fields", names) &&
	        WriteHeaderField("types", types)) )
		return false;

	return true;
	}

bool Ascii::DoFlush(double network_time)
	{
	fsync(fd);
	return true;
	}

bool Ascii::DoFinish(double network_time)
	{
	if ( ascii_done )
		{
		fprintf(stderr, "internal error: duplicate finish\n");
		abort();
		}

	DoFlush(network_time);

	ascii_done = true;

	CloseFile(network_time);

	return true;
	}

bool Ascii::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
	{
	if ( ! fd )
		DoInit(Info(), NumFields(), Fields());

	desc.Clear();

	if ( ! formatter->Describe(&desc, num_fields, fields, vals) )
		return false;

	desc.AddRaw("\n", 1);

	const char* bytes = (const char*)desc.Bytes();
	int len = desc.Len();

	if ( strncmp(bytes, meta_prefix.data(), meta_prefix.size()) == 0 )
		{
		// It would so escape the first character.
		char hex[4] = {'\\', 'x', '0', '0'};
		bytetohex(bytes[0], hex + 2);

		if ( ! safe_write(fd, hex, 4) )
			goto write_error;

		++bytes;
		--len;
		}

	if ( ! safe_write(fd, bytes, len) )
		goto write_error;

        if ( ! IsBuf() )
		fsync(fd);

	return true;

write_error:
	Error(Fmt("error writing to %s: %s", fname.c_str(), Strerror(errno)));
	return false;
	}

bool Ascii::DoRotate(const char* rotated_path, double open, double close, bool terminating)
	{
	// Don't rotate special files or if there's not one currently open.
	if ( ! fd || IsSpecial(Info().path) )
		{
		FinishedRotation();
		return true;
		}

	CloseFile(close);

	string nname = string(rotated_path) + "." + LogExt();

	if ( rename(fname.c_str(), nname.c_str()) != 0 )
		{
		char buf[256];
		strerror_r(errno, buf, sizeof(buf));
		Error(Fmt("failed to rename %s to %s: %s", fname.c_str(),
		          nname.c_str(), buf));
		FinishedRotation();
		return false;
		}

	if ( ! FinishedRotation(nname.c_str(), fname.c_str(), open, close, terminating) )
		{
		Error(Fmt("error rotating %s to %s", fname.c_str(), nname.c_str()));
		return false;
		}

	return true;
	}

bool Ascii::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}

bool Ascii::DoHeartbeat(double network_time, double current_time)
	{
	// Nothing to do.
	return true;
	}

string Ascii::LogExt()
	{
	const char* ext = getenv("BRO_LOG_SUFFIX");
	if ( ! ext )
		ext = "log";

	return ext;
	}

string Ascii::Timestamp(double t)
	{
	time_t teatime = time_t(t);

	if ( ! teatime )
		{
		// Use wall clock.
		struct timeval tv;
		if ( gettimeofday(&tv, 0) < 0 )
			Error("gettimeofday failed");
		else
			teatime = tv.tv_sec;
		}

	struct tm tmbuf;
	struct tm* tm = localtime_r(&teatime, &tmbuf);

	char tmp[128];
	const char* const date_fmt = "%Y-%m-%d-%H-%M-%S";
	strftime(tmp, sizeof(tmp), date_fmt, tm);

	return tmp;
	}


