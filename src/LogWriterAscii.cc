// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <errno.h>

#include "LogWriterAscii.h"
#include "NetVar.h"

/**
 * Takes a string, escapes each character into its equivalent hex code (\x##), and
 * returns a string containing all escaped values.
 *
 * @param str string to escape
 * @return A std::string containing a list of escaped hex values of the form \x##
 */
static string get_escaped_string(const std::string& str)
{
	char tbuf[16];
	string esc = "";

	for ( size_t i = 0; i < str.length(); ++i )
		{
		snprintf(tbuf, sizeof(tbuf), "\\x%02x", str[i]);
		esc += tbuf;
		}

	return esc;
}

LogWriterAscii::LogWriterAscii()
	{
	file = 0;

	output_to_stdout = BifConst::LogAscii::output_to_stdout;
	include_header = BifConst::LogAscii::include_header;

	separator_len = BifConst::LogAscii::separator->Len();
	separator = new char[separator_len];
	memcpy(separator, BifConst::LogAscii::separator->Bytes(),
	       separator_len);

	set_separator_len = BifConst::LogAscii::set_separator->Len();
	set_separator = new char[set_separator_len];
	memcpy(set_separator, BifConst::LogAscii::set_separator->Bytes(),
	       set_separator_len);

	empty_field_len = BifConst::LogAscii::empty_field->Len();
	empty_field = new char[empty_field_len];
	memcpy(empty_field, BifConst::LogAscii::empty_field->Bytes(),
	       empty_field_len);

	unset_field_len = BifConst::LogAscii::unset_field->Len();
	unset_field = new char[unset_field_len];
	memcpy(unset_field, BifConst::LogAscii::unset_field->Bytes(),
	       unset_field_len);

	header_prefix_len = BifConst::LogAscii::header_prefix->Len();
	header_prefix = new char[header_prefix_len];
	memcpy(header_prefix, BifConst::LogAscii::header_prefix->Bytes(),
	       header_prefix_len);

	desc.SetEscape(separator, separator_len);
	}

LogWriterAscii::~LogWriterAscii()
	{
	if ( file )
		fclose(file);

	delete [] separator;
	delete [] set_separator;
	delete [] empty_field;
	delete [] unset_field;
	delete [] header_prefix;
	}

bool LogWriterAscii::WriteHeaderField(const string& key, const string& val)
	{
	string str = string(header_prefix, header_prefix_len) +
		key + string(separator, separator_len) + val + "\n";

	return (fwrite(str.c_str(), str.length(), 1, file) == 1);
	}

bool LogWriterAscii::DoInit(string path, int num_fields,
			    const LogField* const * fields)
	{
	if ( output_to_stdout )
		path = "/dev/stdout";

	fname = IsSpecial(path) ? path : path + "." + LogExt();

	if ( ! (file = fopen(fname.c_str(), "w")) )
		{
		Error(Fmt("cannot open %s: %s", fname.c_str(),
			  strerror(errno)));

		return false;
		}

	if ( include_header )
		{
		string str = string(header_prefix, header_prefix_len)
			+ "separator " // Always use space as separator here.
			+ get_escaped_string(string(separator, separator_len))
			+ "\n";

		if( fwrite(str.c_str(), str.length(), 1, file) != 1 )
			goto write_error;

		if ( ! WriteHeaderField("path", path) )
			goto write_error;

		string names;
		string types;

		for ( int i = 0; i < num_fields; ++i )
			{
			if ( i > 0 )
				{
				names += string(separator, separator_len);
				types += string(separator, separator_len);
				}

			const LogField* field = fields[i];
			names += field->name;
			types += type_name(field->type);
			}

		if ( ! (WriteHeaderField("fields", names)
			&& WriteHeaderField("types", types)) )
			goto write_error;
		}

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

bool LogWriterAscii::DoWriteOne(ODesc* desc, LogVal* val, const LogField* field)
	{
	if ( ! val->present )
		{
		desc->AddN(unset_field, unset_field_len);
		return true;
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		desc->Add(val->val.int_val ? "T" : "F");
		break;

	case TYPE_INT:
		desc->Add(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		desc->Add(val->val.uint_val);
		break;

	case TYPE_SUBNET:
		desc->Add(dotted_addr(val->val.subnet_val.net));
		desc->Add("/");
		desc->Add(val->val.subnet_val.width);
		break;

	case TYPE_ADDR:
		desc->Add(dotted_addr(val->val.addr_val));
		break;

	case TYPE_TIME:
	case TYPE_INTERVAL:
		char buf[256];
		modp_dtoa(val->val.double_val, buf, 6);
		desc->Add(buf);
		break;

	case TYPE_DOUBLE:
		desc->Add(val->val.double_val);
	break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		int size = val->val.string_val->size();
		const char* data = val->val.string_val->data();

		if ( ! size )
			{
			desc->AddN(empty_field, empty_field_len);
			break;
			}

		if ( size == unset_field_len && memcmp(data, unset_field, size) == 0 )
			{
			// The value we'd write out would match exactly the
			// place-holder we use for unset optional fields. We
			// escape the first character so that the output
			// won't be ambigious.
			static const char hex_chars[] = "0123456789abcdef";
			char hex[6] = "\\x00";
			hex[2] = hex_chars[((*data) & 0xf0) >> 4];
			hex[3] = hex_chars[(*data) & 0x0f];
			desc->AddRaw(hex, 4);

			++data;
			--size;
			}

		if ( size )
			desc->AddN(data, size);

		break;
		}

	case TYPE_TABLE:
		{
		if ( ! val->val.set_val.size )
			{
			desc->AddN(empty_field, empty_field_len);
			break;
			}

		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddN(set_separator, set_separator_len);

			if ( ! DoWriteOne(desc, val->val.set_val.vals[j], field) )
				return false;
			}

		break;
		}

	case TYPE_VECTOR:
		{
		if ( ! val->val.vector_val.size )
			{
			desc->AddN(empty_field, empty_field_len);
			break;
			}

		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddN(set_separator, set_separator_len);

			if ( ! DoWriteOne(desc, val->val.vector_val.vals[j], field) )
				return false;
			}

		break;
		}

	default:
		Error(Fmt("unsupported field format %d for %s", val->type,
			  field->name.c_str()));
		return false;
	}

	return true;
	}

bool LogWriterAscii::DoWrite(int num_fields, const LogField* const * fields,
			     LogVal** vals)
	{
	if ( ! file )
		DoInit(Path(), NumFields(), Fields());

	desc.Clear();

	for ( int i = 0; i < num_fields; i++ )
		{
		if ( i > 0 )
			desc.AddRaw(separator, separator_len);

		if ( ! DoWriteOne(&desc, vals[i], fields[i]) )
			return false;
		}

	desc.AddRaw("\n", 1);

	if ( fwrite(desc.Bytes(), desc.Len(), 1, file) != 1 )
		{
		Error(Fmt("error writing to %s: %s", fname.c_str(), strerror(errno)));
		return false;
		}

	if ( IsBuf() )
		fflush(file);

	return true;
	}

bool LogWriterAscii::DoRotate(string rotated_path, double open,
			      double close, bool terminating)
	{
	// Don't rotate special files or if there's not one currently open.
	if ( ! file || IsSpecial(Path()) )
		return true;

	fclose(file);
	file = 0;

	string nname = rotated_path + "." + LogExt();
	rename(fname.c_str(), nname.c_str());

	if ( ! FinishedRotation(nname, fname, open, close, terminating) )
		{
		Error(Fmt("error rotating %s to %s", fname.c_str(), nname.c_str()));
		return false;
		}

	return true;
	}

bool LogWriterAscii::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}

string LogWriterAscii::LogExt()
	{
	const char* ext = getenv("BRO_LOG_SUFFIX");
	if ( ! ext ) ext = "log";
	return ext;
	}
