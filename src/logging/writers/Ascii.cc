// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <errno.h>

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "Ascii.h"

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

Ascii::Ascii(WriterFrontend* frontend) : WriterBackend(frontend)
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

	desc.EnableEscaping();
	desc.AddEscapeSequence(separator, separator_len);
	}

Ascii::~Ascii()
	{
	if ( file )
		fclose(file);

	delete [] separator;
	delete [] set_separator;
	delete [] empty_field;
	delete [] unset_field;
	delete [] header_prefix;
	}

bool Ascii::WriteHeaderField(const string& key, const string& val)
	{
	string str = string(header_prefix, header_prefix_len) +
		key + string(separator, separator_len) + val + "\n";

	return (fwrite(str.c_str(), str.length(), 1, file) == 1);
	}

bool Ascii::DoInit(string path, int num_fields,
			    const Field* const * fields)
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
			+ get_escaped_string(string(separator, separator_len), false)
			+ "\n";

		if( fwrite(str.c_str(), str.length(), 1, file) != 1 )
			goto write_error;

		if ( ! (WriteHeaderField("set_separator", get_escaped_string(
		            string(set_separator, set_separator_len), false)) &&
		        WriteHeaderField("empty_field", get_escaped_string(
		            string(empty_field, empty_field_len), false)) &&
		        WriteHeaderField("unset_field", get_escaped_string(
		            string(unset_field, unset_field_len), false)) &&
		        WriteHeaderField("path", get_escaped_string(path, false))) )
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

			const Field* field = fields[i];
			names += field->name;
			types += type_name(field->type);
			if ( (field->type == TYPE_TABLE) || (field->type == TYPE_VECTOR) )
				{
					types += "[";
					types += type_name(field->subtype);
					types += "]";
				}
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

bool Ascii::DoFlush()
	{
	fflush(file);
	return true;
	}

bool Ascii::DoFinish()
	{
	return true;
	}

bool Ascii::DoWriteOne(ODesc* desc, Value* val, const Field* field)
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
		desc->Add(val->val.uint_val);
		break;

	case TYPE_PORT:
		desc->Add(val->val.port_val.port);
		break;

	case TYPE_SUBNET:
		desc->Add(Render(val->val.subnet_val));
		break;

	case TYPE_ADDR:
		desc->Add(Render(val->val.addr_val));
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

		desc->AddEscapeSequence(set_separator, set_separator_len);
		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddRaw(set_separator, set_separator_len);

			if ( ! DoWriteOne(desc, val->val.set_val.vals[j], field) )
				{
				desc->RemoveEscapeSequence(set_separator, set_separator_len);
				return false;
				}
			}
		desc->RemoveEscapeSequence(set_separator, set_separator_len);

		break;
		}

	case TYPE_VECTOR:
		{
		if ( ! val->val.vector_val.size )
			{
			desc->AddN(empty_field, empty_field_len);
			break;
			}

		desc->AddEscapeSequence(set_separator, set_separator_len);
		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddRaw(set_separator, set_separator_len);

			if ( ! DoWriteOne(desc, val->val.vector_val.vals[j], field) )
				{
				desc->RemoveEscapeSequence(set_separator, set_separator_len);
				return false;
				}
			}
		desc->RemoveEscapeSequence(set_separator, set_separator_len);

		break;
		}

	default:
		Error(Fmt("unsupported field format %d for %s", val->type,
			  field->name.c_str()));
		return false;
	}

	return true;
	}

bool Ascii::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
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

bool Ascii::DoRotate(string rotated_path, double open, double close, bool terminating)
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

bool Ascii::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}

string Ascii::LogExt()
	{
	const char* ext = getenv("BRO_LOG_SUFFIX");
	if ( ! ext ) ext = "log";
	return ext;
	}
