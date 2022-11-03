// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/input/readers/ascii/Ascii.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include <sstream>

#include "zeek/input/readers/ascii/ascii.bif.h"
#include "zeek/threading/SerialTypes.h"

using namespace std;
using zeek::threading::Field;
using zeek::threading::Value;

namespace zeek::input::reader::detail
	{

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position)
	: name(arg_name), type(arg_type), subtype(TYPE_ERROR)
	{
	position = arg_position;
	secondary_position = -1;
	present = true;
	}

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type,
                           const TypeTag& arg_subtype, int arg_position)
	: name(arg_name), type(arg_type), subtype(arg_subtype)
	{
	position = arg_position;
	secondary_position = -1;
	present = true;
	}

FieldMapping::FieldMapping(const FieldMapping& arg)
	: name(arg.name), type(arg.type), subtype(arg.subtype), present(arg.present)
	{
	position = arg.position;
	secondary_position = arg.secondary_position;
	}

FieldMapping FieldMapping::subType()
	{
	return FieldMapping(name, subtype, position);
	}

FieldMapping& FieldMapping::operator=(const FieldMapping& arg)
	{
	if ( this == &arg )
		return *this;

	name = arg.name;
	type = arg.type;
	subtype = arg.subtype;
	present = arg.present;
	position = arg.position;
	secondary_position = arg.secondary_position;

	return *this;
	}

Ascii::Ascii(ReaderFrontend* frontend) : ReaderBackend(frontend)
	{
	mtime = 0;
	ino = 0;
	fail_on_file_problem = false;
	fail_on_invalid_lines = false;
	}

void Ascii::DoClose()
	{
	read_location.reset();
	}

bool Ascii::DoInit(const ReaderInfo& info, int num_fields, const Field* const* fields)
	{
	StopWarningSuppression();

	separator.assign((const char*)BifConst::InputAscii::separator->Bytes(),
	                 BifConst::InputAscii::separator->Len());

	set_separator.assign((const char*)BifConst::InputAscii::set_separator->Bytes(),
	                     BifConst::InputAscii::set_separator->Len());

	empty_field.assign((const char*)BifConst::InputAscii::empty_field->Bytes(),
	                   BifConst::InputAscii::empty_field->Len());

	unset_field.assign((const char*)BifConst::InputAscii::unset_field->Bytes(),
	                   BifConst::InputAscii::unset_field->Len());

	fail_on_invalid_lines = BifConst::InputAscii::fail_on_invalid_lines;
	fail_on_file_problem = BifConst::InputAscii::fail_on_file_problem;

	path_prefix.assign((const char*)BifConst::InputAscii::path_prefix->Bytes(),
	                   BifConst::InputAscii::path_prefix->Len());

	// Set per-filter configuration options.
	for ( const auto& [k, v] : info.config )
		{
		if ( strcmp(k, "separator") == 0 )
			separator.assign(v);

		else if ( strcmp(k, "set_separator") == 0 )
			set_separator.assign(v);

		else if ( strcmp(k, "empty_field") == 0 )
			empty_field.assign(v);

		else if ( strcmp(k, "unset_field") == 0 )
			unset_field.assign(v);

		else if ( strcmp(k, "fail_on_invalid_lines") == 0 )
			fail_on_invalid_lines = (strncmp(v, "T", 1) == 0);

		else if ( strcmp(k, "fail_on_file_problem") == 0 )
			fail_on_file_problem = (strncmp(v, "T", 1) == 0);
		}

	if ( separator.size() != 1 )
		Error("separator length has to be 1. Separator will be truncated.");

	if ( set_separator.size() != 1 )
		Error("set_separator length has to be 1. Separator will be truncated.");

	threading::formatter::Ascii::SeparatorInfo sep_info(separator, set_separator, unset_field,
	                                                    empty_field);
	formatter = unique_ptr<threading::Formatter>(new threading::formatter::Ascii(this, sep_info));

	return DoUpdate();
	}

bool Ascii::OpenFile()
	{
	if ( file.is_open() )
		return true;

	// Handle path-prefixing. See similar logic in Binary::DoInit().
	fname = Info().source;

	if ( fname.front() != '/' && ! path_prefix.empty() )
		{
		string path = path_prefix;
		std::size_t last = path.find_last_not_of('/');

		if ( last == string::npos ) // Nothing but slashes -- weird but ok...
			path = "/";
		else
			path.erase(last + 1);

		fname = path + "/" + fname;
		}

	file.open(fname);

	if ( ! file.is_open() )
		{
		FailWarn(fail_on_file_problem, Fmt("Init: cannot open %s", fname.c_str()), true);

		return ! fail_on_file_problem;
		}

	if ( ReadHeader(false) == false )
		{
		FailWarn(fail_on_file_problem,
		         Fmt("Init: cannot open %s; problem reading file header", fname.c_str()), true);

		file.close();
		return ! fail_on_file_problem;
		}

	if ( ! read_location )
		{
		read_location = LocationPtr(new zeek::detail::Location());
		read_location->filename = util::copy_string(fname.c_str());
		}

	StopWarningSuppression();
	return true;
	}

bool Ascii::ReadHeader(bool useCached)
	{
	// try to read the header line...
	string line;

	if ( ! useCached )
		{
		if ( ! GetLine(line) )
			{
			FailWarn(fail_on_file_problem,
			         Fmt("Could not read input data file %s; first line could not be read",
			             fname.c_str()),
			         true);
			return false;
			}

		headerline = line;
		}

	else
		line = headerline;

	// construct list of field names.
	auto ifields = util::split(line, separator[0]);

	// printf("Updating fields from description %s\n", line.c_str());
	columnMap.clear();

	const auto* fields = Fields();

	for ( int i = 0; i < NumFields(); i++ )
		{
		const Field* field = fields[i];

		auto fit = std::find(ifields.begin(), ifields.end(), field->name);
		if ( fit == ifields.end() )
			{
			if ( field->optional )
				{
				// we do not really need this field. mark it as not present and always send an undef
				// back.
				FieldMapping f(field->name, field->type, field->subtype, -1);
				f.present = false;
				columnMap.push_back(f);
				continue;
				}

			FailWarn(fail_on_file_problem,
			         Fmt("Did not find requested field %s in input data file %s.", field->name,
			             fname.c_str()),
			         true);

			return false;
			}

		int index = static_cast<int>(std::distance(ifields.begin(), fit));
		FieldMapping f(field->name, field->type, field->subtype, index);

		if ( field->secondary_name && strlen(field->secondary_name) != 0 )
			{
			auto fit2 = std::find(ifields.begin(), ifields.end(), field->secondary_name);
			if ( fit2 == ifields.end() )
				{
				FailWarn(fail_on_file_problem,
				         Fmt("Could not find requested port type field %s in input data file %s.",
				             field->secondary_name, fname.c_str()),
				         true);

				return false;
				}

			f.secondary_position = static_cast<int>(std::distance(ifields.begin(), fit2));
			}

		columnMap.push_back(f);
		}

	// well, that seems to have worked...
	return true;
	}

bool Ascii::GetLine(string& str)
	{
	while ( getline(file, str) )
		{
		if ( read_location )
			{
			read_location->first_line++;
			read_location->last_line++;
			}

		if ( str.empty() )
			continue;

		if ( str.back() == '\r' ) // deal with \r\n by removing \r
			str.pop_back();

		if ( str[0] != '#' )
			return true;

		if ( (str.length() > 8) && (str.compare(0, 7, "#fields") == 0) && (str[7] == separator[0]) )
			{
			str = str.substr(8);
			return true;
			}
		}

	return false;
	}

// read the entire file and send appropriate thingies back to InputMgr
bool Ascii::DoUpdate()
	{
	if ( ! OpenFile() )
		return ! fail_on_file_problem;

	if ( read_location )
		{
		read_location->first_line = 0;
		read_location->last_line = 0;
		}

	switch ( Info().mode )
		{
		case MODE_REREAD:
			{
			// check if the file has changed
			struct stat sb;
			if ( stat(fname.c_str(), &sb) == -1 )
				{
				FailWarn(fail_on_file_problem, Fmt("Could not get stat for %s", fname.c_str()),
				         true);

				file.close();
				return ! fail_on_file_problem;
				}

			if ( sb.st_ino == ino && sb.st_mtime == mtime )
				// no change
				return true;

			// Warn again in case of trouble if the file changes. The comparison to 0
			// is to suppress an extra warning that we'd otherwise get on the initial
			// inode assignment.
			if ( ino != 0 )
				StopWarningSuppression();

			mtime = sb.st_mtime;
			ino = sb.st_ino;
			// File changed. Fall through to re-read.
			}

		case MODE_MANUAL:
		case MODE_STREAM:
			{
			// dirty, fix me. (well, apparently after trying seeking, etc
			// - this is not that bad)
			if ( file.is_open() )
				{
				if ( Info().mode == MODE_STREAM )
					{
					file.clear(); // remove end of file evil bits
					if ( ! ReadHeader(true) )
						{
						return ! fail_on_file_problem; // header reading failed
						}

					break;
					}

				file.close();
				}

			OpenFile();

			break;
			}

		default:
			assert(false);
		}

	string line;

	file.sync();

	while ( GetLine(line) )
		{
		// split on tabs
		bool error = false;
		auto stringfields = util::split(line, separator[0]);

		// This needs to be a signed value or the comparisons below will fail.
		int pos = static_cast<int>(stringfields.size() - 1);

		Value** fields = new Value*[NumFields()];

		int fpos = 0;
		for ( const auto& fit : columnMap )
			{
			if ( ! fit.present )
				{
				// add non-present field
				fields[fpos] = new Value(fit.type, false);
				if ( read_location )
					fields[fpos]->SetFileLineNumber(read_location->first_line);
				fpos++;
				continue;
				}

			assert(fit.position >= 0);

			if ( fit.position > pos || fit.secondary_position > pos )
				{
				FailWarn(fail_on_invalid_lines, Fmt("Not enough fields in line '%s' of %s. Found "
				                                    "%d fields, want positions %d and %d",
				                                    line.c_str(), fname.c_str(), pos, fit.position,
				                                    fit.secondary_position));

				if ( fail_on_invalid_lines )
					{
					for ( int i = 0; i < fpos; i++ )
						delete fields[i];

					delete[] fields;

					return false;
					}
				else
					{
					error = true;
					break;
					}
				}

			Value* val = formatter->ParseValue(stringfields[fit.position], fit.name, fit.type,
			                                   fit.subtype);
			if ( ! val )
				{
				Warning(Fmt("Could not convert line '%s' of %s to Val. Ignoring line.",
				            line.c_str(), fname.c_str()));
				error = true;
				break;
				}

			if ( read_location )
				val->SetFileLineNumber(read_location->first_line);

			if ( fit.secondary_position != -1 )
				{
				// we have a port definition :)
				assert(val->type == TYPE_PORT);
				//	Error(Fmt("Got type %d != PORT with secondary position!", val->type));

				val->val.port_val.proto = formatter->ParseProto(
					stringfields[fit.secondary_position]);
				}

			fields[fpos] = val;

			fpos++;
			}

		if ( error )
			{
			// Encountered non-fatal error, ignoring line. But
			// first, delete all successfully read fields and the
			// array structure.

			for ( int i = 0; i < fpos; i++ )
				delete fields[i];

			delete[] fields;
			continue;
			}

		// printf("fpos: %d, second.num_fields: %d\n", fpos, (*it).second.num_fields);
		assert(fpos == NumFields());

		if ( Info().mode == MODE_STREAM )
			Put(fields);
		else
			SendEntry(fields);
		}

	if ( Info().mode != MODE_STREAM )
		EndCurrentSend();

	return true;
	}

bool Ascii::DoHeartbeat(double network_time, double current_time)
	{
	if ( ! OpenFile() )
		return ! fail_on_file_problem;

	switch ( Info().mode )
		{
		case MODE_MANUAL:
			// yay, we do nothing :)
			break;

		case MODE_REREAD:
		case MODE_STREAM:
			Update(); // Call Update, not DoUpdate, because Update
			          // checks the "disabled" flag.
			break;

		default:
			assert(false);
		}

	return true;
	}

	} // namespace zeek::input::reader::detail
