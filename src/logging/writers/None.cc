
#include "None.h"
#include "NetVar.h"

using namespace logging;
using namespace writer;

bool None::DoInit(const WriterInfo& info, int num_fields,
	    const threading::Field* const * fields)
	{
	if ( BifConst::LogNone::debug )
		{
		std::cout << "[logging::writer::None]" << std::endl;
		std::cout << "  path=" << info.path << std::endl;
		std::cout << "  rotation_interval=" << info.rotation_interval << std::endl;
		std::cout << "  rotation_base=" << info.rotation_base << std::endl;

		for ( std::map<string,string>::const_iterator i = info.config.begin(); i != info.config.end(); i++ )
			std::cout << "  config[" << i->first << "] = " << i->second << std::endl;

		for ( int i = 0; i < num_fields; i++ )
			{
			const threading::Field* field = fields[i];
			std::cout << "  field " << field->name << ": "
				  << type_name(field->type) << std::endl;
			}

		std::cout << std::endl;
		}

	return true;
	}

bool None::DoRotate(string rotated_path, double open, double close, bool terminating)
	{
	if ( ! FinishedRotation(string("/dev/null"), Info().path, open, close, terminating))
		{
		Error(Fmt("error rotating %s", Info().path.c_str()));
		return false;
		}

	return true;
	}


