// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/input/readers/config/Config.h"

#include <regex.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include <unordered_set>

#include "zeek/Desc.h"
#include "zeek/input/Manager.h"
#include "zeek/input/readers/config/config.bif.h"
#include "zeek/threading/SerialTypes.h"
#include "zeek/threading/formatters/Ascii.h"

using zeek::threading::Field;
using zeek::threading::Value;

namespace zeek::input::reader::detail {

Config::Config(ReaderFrontend* frontend) : ReaderBackend(frontend) {
    mtime = 0;
    ino = 0;
    fail_on_file_problem = false;

    // find all option names and their types.
    const auto& globals = zeek::detail::global_scope()->Vars();

    for ( const auto& entry : globals ) {
        auto& id = entry.second;
        if ( ! id->IsOption() )
            continue;

        if ( id->GetType()->Tag() == TYPE_RECORD || ! Manager::IsCompatibleType(id->GetType().get()) ) {
            option_types[id->Name()] = std::make_tuple(TYPE_ERROR, id->GetType()->Tag(), id);
            continue;
        }

        TypeTag primary = id->GetType()->Tag();
        TypeTag secondary = TYPE_VOID;
        if ( primary == TYPE_TABLE )
            secondary = id->GetType()->AsSetType()->GetIndices()->GetPureType()->Tag();
        else if ( primary == TYPE_VECTOR )
            secondary = id->GetType()->AsVectorType()->Yield()->Tag();

        option_types[id->Name()] = std::make_tuple(primary, secondary, id);
    }
}

void Config::DoClose() {}

bool Config::DoInit(const ReaderInfo& info, int num_fields, const Field* const* fields) {
    fail_on_file_problem = BifConst::InputConfig::fail_on_file_problem;

    set_separator.assign((const char*)BifConst::InputConfig::set_separator->Bytes(),
                         BifConst::InputConfig::set_separator->Len());

    empty_field.assign((const char*)BifConst::InputConfig::empty_field->Bytes(),
                       BifConst::InputConfig::empty_field->Len());

    threading::formatter::Ascii::SeparatorInfo sep_info("\t", set_separator, "", empty_field);
    formatter = std::unique_ptr<threading::Formatter>(new threading::formatter::Ascii(this, sep_info));

    return DoUpdate();
}

bool Config::OpenFile() {
    if ( file.is_open() )
        return true;

    file.open(Info().source);

    if ( ! file.is_open() ) {
        FailWarn(fail_on_file_problem, Fmt("Init: cannot open %s", Info().source), true);
        return ! fail_on_file_problem;
    }

    StopWarningSuppression();
    return true;
}

bool Config::GetLine(std::string& str) {
    while ( getline(file, str) ) {
        if ( ! str.size() )
            continue;

        if ( str.back() == '\r' ) // deal with \r\n by removing \r
            str.pop_back();

        if ( str[0] != '#' )
            return true;
    }

    return false;
}

// read the entire file and send appropriate thingies back to InputMgr
bool Config::DoUpdate() {
    if ( ! OpenFile() )
        return ! fail_on_file_problem;

    switch ( Info().mode ) {
        case MODE_REREAD: {
            // check if the file has changed
            struct stat sb;
            if ( stat(Info().source, &sb) == -1 ) {
                FailWarn(fail_on_file_problem, Fmt("Could not get stat for %s", Info().source), true);

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
        case MODE_STREAM: {
            // dirty, fix me. (well, apparently after trying seeking, etc
            // - this is not that bad)
            if ( file.is_open() ) {
                if ( Info().mode == MODE_STREAM ) {
                    file.clear(); // remove end of file evil bits
                    break;
                }

                file.close();
            }

            OpenFile();

            break;
        }

        default: assert(false);
    }

    std::string line;
    file.sync();

    // keep a list of options to remove because they were no longer in the input file.
    // Start out with all element and removes while going along
    std::unordered_set<std::string> unseen_options;
    for ( const auto& i : option_values ) {
        unseen_options.insert(i.first);
    }

    std::string re_str = Fmt("^([^[:blank:]]+)[[:blank:]]+([^[:blank:]](.*[^[:blank:]%c])?)?[[:blank:]%c]*$",
                             set_separator[0], set_separator[0]);

    regex_t re;
    if ( regcomp(&re, re_str.c_str(), REG_EXTENDED) ) {
        Error(Fmt("Failed to compile regex."));
        return true;
    }

    while ( GetLine(line) ) {
        regmatch_t match[3];
        if ( regexec(&re, line.c_str(), 3, match, 0) ) {
            Warning(Fmt("Could not parse '%s'; line has invalid format. Ignoring line.", line.c_str()));
            continue;
        }

        std::string key = line.substr(match[1].rm_so, match[1].rm_eo - match[1].rm_so);
        std::string value;
        if ( match[2].rm_so > 0 )
            value = line.substr(match[2].rm_so, match[2].rm_eo - match[2].rm_so);

        auto typeit = option_types.find(key);
        if ( typeit == option_types.end() ) {
            Warning(Fmt("Option '%s' does not exist. Ignoring line.", key.c_str()));
            continue;
        }

        if ( std::get<0>((*typeit).second) == TYPE_ERROR ) {
            ODesc d;
            std::get<2>((*typeit).second)->GetType()->Describe(&d);
            Warning(Fmt("Option '%s' has type '%s', which is not supported for file input. Ignoring line.", key.c_str(),
                        d.Description()));
            continue;
        }

        Value* eventval =
            formatter->ParseValue(value, key, std::get<0>((*typeit).second), std::get<1>((*typeit).second));
        if ( ! eventval ) {
            Warning(Fmt("Could not convert line '%s' to value. Ignoring line.", line.c_str()));
            continue;
        }
        else if ( ! eventval->present ) {
            Warning(Fmt("Line '%s' has no value. Ignoring line.", line.c_str()));
            delete eventval;
            continue;
        }

        unseen_options.erase(key);

        // we only send the event if the underlying value has changed. Let's check that.
        // (Yes, this means we keep all configuration options in memory twice - once here in
        // the reader and once in memory in Zeek; that is difficult to change.
        auto search = option_values.find(key);
        if ( search != option_values.end() && search->second == value ) {
            delete eventval;
            continue;
        }

        option_values[key] = value;

        {
            Value** fields = new Value*[2];
            Value* keyval = new threading::Value(TYPE_STRING, true);
            keyval->val.string_val.length = key.size();
            keyval->val.string_val.data = util::copy_string(key.c_str(), key.size());
            fields[0] = keyval;
            Value* val = new threading::Value(TYPE_STRING, true);
            val->val.string_val.length = value.size();
            val->val.string_val.data = util::copy_string(value.c_str(), value.size());
            fields[1] = val;

            if ( Info().mode == MODE_STREAM )
                Put(fields);
            else
                SendEntry(fields);
        }

        {
            Value** vals = new Value*[4];
            vals[0] = new Value(TYPE_STRING, true);
            auto val0_len = strlen(Info().name);
            vals[0]->val.string_val.data = util::copy_string(Info().name, val0_len);
            vals[0]->val.string_val.length = val0_len;
            vals[1] = new Value(TYPE_STRING, true);
            auto val1_len = strlen(Info().source);
            vals[1]->val.string_val.data = util::copy_string(Info().source, val1_len);
            vals[1]->val.string_val.length = val1_len;
            vals[2] = new Value(TYPE_STRING, true);
            vals[2]->val.string_val.data = util::copy_string(key.c_str(), key.size());
            vals[2]->val.string_val.length = key.size();
            vals[3] = eventval;

            SendEvent("InputConfig::new_value", 4, vals);
        }
    }

    regfree(&re);

    if ( Info().mode != MODE_STREAM )
        EndCurrentSend();

    // clean up all options we did not see
    for ( const auto& i : unseen_options )
        option_values.erase(i);

    return true;
}

bool Config::DoHeartbeat(double network_time, double current_time) {
    switch ( Info().mode ) {
        case MODE_MANUAL:
            // yay, we do nothing :)
            break;

        case MODE_REREAD:
        case MODE_STREAM:
            Update(); // Call Update, not DoUpdate, because Update
                      // checks the "disabled" flag.
            break;

        default: assert(false);
    }

    return true;
}

} // namespace zeek::input::reader::detail
