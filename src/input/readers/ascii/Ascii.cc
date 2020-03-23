// See the file "COPYING" in the main distribution directory for copyright.

#include <sstream>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "Ascii.h"
#include "ascii.bif.h"

#include "threading/SerialTypes.h"

using namespace input::reader;
using namespace threading;
using threading::Value;
using threading::Field;

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

Ascii::Ascii(ReaderFrontend *frontend) : ReaderBackend(frontend)
	{
	mtime = 0;
	ino = 0;
	fail_on_file_problem = false;
	fail_on_invalid_lines = false;
	}

Ascii::~Ascii()
	{
	}

void Ascii::DoClose()
	{
	}

bool Ascii::DoInit(const ReaderInfo& info, int num_fields, const Field* const* fields)
	{
	StopWarningSuppression();

	separator.assign( (const char*) BifConst::InputAscii::separator->Bytes(),
	                 BifConst::InputAscii::separator->Len());

	set_separator.assign( (const char*) BifConst::InputAscii::set_separator->Bytes(),
	                     BifConst::InputAscii::set_separator->Len());

	empty_field.assign( (const char*) BifConst::InputAscii::empty_field->Bytes(),
	                   BifConst::InputAscii::empty_field->Len());

	unset_field.assign( (const char*) BifConst::InputAscii::unset_field->Bytes(),
	                   BifConst::InputAscii::unset_field->Len());

	fail_on_invalid_lines = BifConst::InputAscii::fail_on_invalid_lines;
	fail_on_file_problem = BifConst::InputAscii::fail_on_file_problem;

	path_prefix.assign((const char*) BifConst::InputAscii::path_prefix->Bytes(),
	                   BifConst::InputAscii::path_prefix->Len());

	// Set per-filter configuration options.
	for ( ReaderInfo::config_map::const_iterator i = info.config.begin(); i != info.config.end(); i++ )
		{
		if ( strcmp(i->first, "separator") == 0 )
			separator.assign(i->second);

		else if ( strcmp(i->first, "set_separator") == 0 )
			set_separator.assign(i->second);

		else if ( strcmp(i->first, "empty_field") == 0 )
			empty_field.assign(i->second);

		else if ( strcmp(i->first, "unset_field") == 0 )
			unset_field.assign(i->second);

		else if ( strcmp(i->first, "fail_on_invalid_lines") == 0 )
			fail_on_invalid_lines = (strncmp(i->second, "T", 1) == 0);

		else if ( strcmp(i->first, "fail_on_file_problem") == 0 )
			fail_on_file_problem = (strncmp(i->second, "T", 1) == 0);
		}

	if ( separator.size() != 1 )
		Error("separator length has to be 1. Separator will be truncated.");

	if ( set_separator.size() != 1 )
		Error("set_separator length has to be 1. Separator will be truncated.");

	formatter::Ascii::SeparatorInfo sep_info(separator, set_separator, unset_field, empty_field);
	formatter = unique_ptr<threading::formatter::Formatter>(new formatter::Ascii(this, sep_info));

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
		FailWarn(fail_on_file_problem, Fmt("Init: cannot open %s; problem reading file header", fname.c_str()), true);

		file.close();
		return ! fail_on_file_problem;
		}

	StopWarningSuppression();
	return true;
	}

bool Ascii::ReadHeader(bool useCached)
	{
	// try to read the header line...
	string line;
	map<string, uint32_t> ifields;

	if ( ! useCached )
		{
		if ( ! GetLine(line) )
			{
			FailWarn(fail_on_file_problem, Fmt("Could not read input data file %s; first line could not be read",
							   fname.c_str()), true);
			return false;
			}

		headerline = line;
		}

	else
		line = headerline;

	// construct list of field names.
	istringstream splitstream(line);
	int pos=0;
	while ( splitstream )
		{
		string s;
		if ( ! getline(splitstream, s, separator[0]))
			break;

		ifields[s] = pos;
		pos++;
		}

	// printf("Updating fields from description %s\n", line.c_str());
	columnMap.clear();

	for ( int i = 0; i < NumFields(); i++ )
		{
		const Field* field = Fields()[i];

		map<string, uint32_t>::iterator fit = ifields.find(field->name);
		if ( fit == ifields.end() )
			{
			if ( field->optional )
				{
				// we do not really need this field. mark it as not present and always send an undef back.
				FieldMapping f(field->name, field->type, field->subtype, -1);
				f.present = false;
				columnMap.push_back(f);
				continue;
				}

			FailWarn(fail_on_file_problem, Fmt("Did not find requested field %s in input data file %s.",
							   field->name, fname.c_str()), true);

			return false;
			}

		FieldMapping f(field->name, field->type, field->subtype, ifields[field->name]);

		if ( field->secondary_name && strlen(field->secondary_name) != 0 )
			{
			map<string, uint32_t>::iterator fit2 = ifields.find(field->secondary_name);
			if ( fit2 == ifields.end() )
				{
				FailWarn(fail_on_file_problem, Fmt("Could not find requested port type field %s in input data file %s.",
				                                   field->secondary_name, fname.c_str()), true);

				return false;
				}

			f.secondary_position = ifields[field->secondary_name];
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
		if ( ! str.size() )
			continue;

		if ( str.back() == '\r' ) // deal with \r\n by removing \r
			str.pop_back();

		if ( str[0] != '#' )
			return true;

		if ( ( str.length() > 8 ) && ( str.compare(0,7, "#fields") == 0 ) && ( str[7] == separator[0] ) )
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

	switch ( Info().mode ) {
		case MODE_REREAD:
			{
			// check if the file has changed
			struct stat sb;
			if ( stat(fname.c_str(), &sb) == -1 )
				{
				FailWarn(fail_on_file_problem, Fmt("Could not get stat for %s", fname.c_str()), true);

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
		istringstream splitstream(line);

		map<int, string> stringfields;
		int pos = 0;
		while ( splitstream )
			{
			string s;
			if ( ! getline(splitstream, s, separator[0]) )
				break;

			stringfields[pos] = s;
			pos++;
			}

		pos--; // for easy comparisons of max element.

		Value** fields = new Value*[NumFields()];

		int fpos = 0;
		for ( vector<FieldMapping>::iterator fit = columnMap.begin();
			fit != columnMap.end();
			fit++ )
			{

			if ( ! fit->present )
				{
				// add non-present field
				fields[fpos] =  new Value((*fit).type, false);
				fpos++;
				continue;
				}

			assert(fit->position >= 0 );

			if ( (*fit).position > pos || (*fit).secondary_position > pos )
				{
				FailWarn(fail_on_invalid_lines, Fmt("Not enough fields in line '%s' of %s. Found %d fields, want positions %d and %d",
				                                    line.c_str(), fname.c_str(), pos, (*fit).position, (*fit).secondary_position));

				if ( fail_on_invalid_lines )
					{
					for ( int i = 0; i < fpos; i++ )
						delete fields[i];

					delete [] fields;

					return false;
					}
				else
					{
					error = true;
					break;
					}
				}

			Value* val = formatter->ParseValue(stringfields[(*fit).position], (*fit).name, (*fit).type, (*fit).subtype);

			if ( val == 0 )
				{
				Warning(Fmt("Could not convert line '%s' of %s to Val. Ignoring line.", line.c_str(), fname.c_str()));
				error = true;
				break;
				}

			if ( (*fit).secondary_position != -1 )
				{
				// we have a port definition :)
				assert(val->type == TYPE_PORT );
				//	Error(Fmt("Got type %d != PORT with secondary position!", val->type));

				val->val.port_val.proto = formatter->ParseProto(stringfields[(*fit).secondary_position]);
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

			delete [] fields;
			continue;
			}

		//printf("fpos: %d, second.num_fields: %d\n", fpos, (*it).second.num_fields);
		assert ( fpos == NumFields() );

		if ( Info().mode  == MODE_STREAM )
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

