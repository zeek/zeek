// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/logging/writers/none/None.h"

#include <algorithm>
#include <iostream>

#include "zeek/logging/writers/none/none.bif.h"

namespace zeek::logging::writer::detail {

bool None::DoInit(const WriterInfo& info, int num_fields, const threading::Field* const* fields) {
    if ( BifConst::LogNone::debug ) {
        std::cout << "[logging::writer::None]\n";
        std::cout << "  path=" << info.path << "\n";
        std::cout << "  rotation_interval=" << info.rotation_interval << "\n";
        std::cout << "  rotation_base=" << info.rotation_base << "\n";

        // Output the config sorted by keys.

        std::vector<std::pair<std::string, std::string>> keys;

        for ( const auto& [key, value] : info.config )
            keys.emplace_back(key, value);

        std::sort(keys.begin(), keys.end());

        for ( const auto& [key, value] : keys )
            std::cout << "  config[" << key << "] = " << value << "\n";

        for ( int i = 0; i < num_fields; i++ ) {
            const threading::Field* field = fields[i];
            std::cout << "  field " << field->name << ": " << type_name(field->type) << "\n";
        }

        std::cout << "\n";
        std::cout << std::flush;
    }

    return true;
}

bool None::DoRotate(const char* rotated_path, double open, double close, bool terminating) {
    if ( ! FinishedRotation("/dev/null", Info().path, open, close, terminating) ) {
        Error(Fmt("error rotating %s", Info().path));
        return false;
    }

    return true;
}

} // namespace zeek::logging::writer::detail
