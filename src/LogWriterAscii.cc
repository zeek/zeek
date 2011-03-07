
#include <string>
#include <errno.h>

#include "LogWriterAscii.h"

LogWriterAscii::LogWriterAscii()
	{
	file = 0;
	}

LogWriterAscii::~LogWriterAscii()
	{
	if ( file )
		fclose(file);
	}

bool LogWriterAscii::DoInit(string path, int num_fields, const LogField* const * fields)
	{
	fname = path + ".log";

	if ( ! (file = fopen(fname.c_str(), "w")) )
		{
		Error(Fmt("cannot open %s: %s", fname.c_str(), strerror(errno)));
		return false;
		}

	if ( fputs("# ", file) == EOF )
		goto write_error;

	for ( int i = 0; i < num_fields; i++ )
		{
		const LogField* field = fields[i];
		if ( fputs(field->name.c_str(), file) == EOF )
			goto write_error;

		if ( fputc('\t', file) == EOF )
			goto write_error;
		}

	if ( fputc('\n', file) == EOF )
		goto write_error;

	return true;

write_error:
	Error(Fmt("error writing to %s: %s", fname.c_str(), strerror(errno)));
	return false;
	}

bool LogWriterAscii::DoFlush()
	{
	fflush(file);
	return true;
	}

void LogWriterAscii::DoFinish()
	{
	}

bool LogWriterAscii::DoWrite(int num_fields, const LogField* const * fields, LogVal** vals)
	{
	ODesc desc(DESC_READABLE);

	for ( int i = 0; i < num_fields; i++ )
		{
		if ( i > 0 )
			desc.Add("\t");

		LogVal* val = vals[i];
		const LogField* field = fields[i];

		if ( ! val->present )
			{
			desc.Add("-"); // TODO: Probably want to get rid of the "-".
			continue;
			}

		switch ( field->type ) {
		case TYPE_BOOL:
			desc.Add(val->val.int_val ? "T" : "F");
			break;

		case TYPE_INT:
		case TYPE_ENUM:
			desc.Add(val->val.int_val);
			break;

		case TYPE_COUNT:
		case TYPE_COUNTER:
		case TYPE_PORT:
			desc.Add(val->val.uint_val);
			break;

		case TYPE_SUBNET:
			desc.Add(dotted_addr(val->val.subnet_val.net));
			desc.Add("/");
			desc.Add(val->val.subnet_val.width);
			break;

		case TYPE_NET:
		case TYPE_ADDR:
			desc.Add(dotted_addr(val->val.addr_val));
			break;

		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
			desc.Add(val->val.double_val);
			break;

		case TYPE_STRING:
			desc.AddN(val->val.string_val->data(), val->val.string_val->size());
			break;

		default:
			Error(Fmt("unsupported field format %d for %s", field->type, field->name.c_str()));
			return false;
		}
		}

	desc.Add("\n");

	if ( fwrite(desc.Bytes(), desc.Len(), 1, file) != 1 )
		{
		Error(Fmt("error writing to %s: %s", fname.c_str(), strerror(errno)));
		return false;
		}

	if ( IsBuf() )
		fflush(file);

	return true;
	}

bool LogWriterAscii::DoRotate(string rotated_path, string postprocessor, double open, double close, bool terminating)
	{
	fclose(file);

	string nname = rotated_path + ".log";
	rename(fname.c_str(), nname.c_str());

	if ( postprocessor.size() && ! RunPostProcessor(nname, postprocessor, fname.c_str(), open, close, terminating) )
		return false;

	return DoInit(Path(), NumFields(), Fields());
	}

bool LogWriterAscii::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}


