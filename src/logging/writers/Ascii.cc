// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "Ascii.h"

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

Ascii::Ascii(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	fd = 0;
	ascii_done = false;
	only_single_header_row = false;

	output_to_stdout = BifConst::LogAscii::output_to_stdout;
	include_meta = BifConst::LogAscii::include_meta;

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

	desc.EnableEscaping();
	desc.AddEscapeSequence(separator);

	io = new AsciiInputOutput(this, separator, set_separator, empty_field, unset_field);
	}

Ascii::~Ascii()
	{
	if ( ! ascii_done )
		{
		fprintf(stderr, "internal error: finish missing\n");
		abort();
		}

	delete io;
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

	if ( include_meta && ! only_single_header_row )
		WriteHeaderField("close", Timestamp(0));

	safe_close(fd);
	fd = 0;
	}

bool Ascii::DoInit(const WriterInfo& info, int num_fields, const Field* const * fields)
	{
	assert(! fd);

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

	for ( WriterInfo::config_map::const_iterator i = info.config.begin(); i != info.config.end(); i++ )
		{
		if ( strcmp(i->first, "only_single_header_row") == 0 )
			{
			if ( strcmp(i->second, "T") == 0 )
				only_single_header_row = true;

			else if ( strcmp(i->second, "F") == 0 )
				only_single_header_row = false;

			else
				{
				Error("invalid value for 'only_single_header_row', must be boolean (T/F)");
				return false;
				}
			}
		}

	if ( include_meta )
		{
		string names;
		string types;

		for ( int i = 0; i < num_fields; ++i )
			{
			if ( i > 0 )
				{
				names += separator;
				types += separator;
				}

			names += string(fields[i]->name);
			types += fields[i]->TypeName().c_str();
			}

		if ( only_single_header_row )
			{
			// A single CSV-style line is all we need.
			string str = names + "\n";
			if ( ! safe_write(fd, str.c_str(), str.length()) )
				goto write_error;

			return true;
			}

		string str = meta_prefix
			+ "separator " // Always use space as separator here.
			+ get_escaped_string(separator, false)
			+ "\n";

		if ( ! safe_write(fd, str.c_str(), str.length()) )
			goto write_error;

		if ( ! (WriteHeaderField("set_separator", get_escaped_string(set_separator, false)) &&
			WriteHeaderField("empty_field", get_escaped_string(empty_field, false)) &&
			WriteHeaderField("unset_field", get_escaped_string(unset_field, false)) &&
			WriteHeaderField("path", get_escaped_string(path, false)) &&
			WriteHeaderField("open", Timestamp(0))) )
			goto write_error;

		if ( ! (WriteHeaderField("fields", names)
			&& WriteHeaderField("types", types)) )
			goto write_error;
		}
	
	return true;

write_error:
	Error(Fmt("error writing to %s: %s", fname.c_str(), Strerror(errno)));
	return false;
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

	for ( int i = 0; i < num_fields; i++ )
		{
		if ( i > 0 )
			desc.AddRaw(separator);

		if ( ! io->ValToODesc(&desc, vals[i], fields[i]) )
			return false;
		}

	desc.AddRaw("\n", 1);

	const char* bytes = (const char*)desc.Bytes();
	int len = desc.Len();

	if ( strncmp(bytes, meta_prefix.data(), meta_prefix.size()) == 0 )
		{
		// It would so escape the first character.
		char buf[16];
		snprintf(buf, sizeof(buf), "\\x%02x", bytes[0]);

		if ( ! safe_write(fd, buf, strlen(buf)) )
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
	rename(fname.c_str(), nname.c_str());

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


