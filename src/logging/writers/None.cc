
#include <algorithm>

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

		// Output the config sorted by keys.

		std::vector<std::pair<string, string> > keys;

		for ( WriterInfo::config_map::const_iterator i = info.config.begin(); i != info.config.end(); i++ )
			keys.push_back(std::make_pair(i->first, i->second));

		std::sort(keys.begin(), keys.end());

		for ( std::vector<std::pair<string,string> >::const_iterator i = keys.begin(); i != keys.end(); i++ )
			std::cout << "  config[" << (*i).first << "] = " << (*i).second << std::endl;

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

bool None::DoRotate(const char* rotated_path, double open, double close, bool terminating)
	{
	if ( ! FinishedRotation("/dev/null", Info().path, open, close, terminating))
		{
		Error(Fmt("error rotating %s", Info().path));
		return false;
		}

	return true;
	}


