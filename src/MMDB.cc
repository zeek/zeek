// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/MMDB.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <chrono>

#include "zeek/Func.h"
#include "zeek/IPAddr.h"
#include "zeek/ZeekString.h"

namespace zeek {

#ifdef USE_GEOIP

static int msg_count = 0;
static double msg_suppression_time = 0;
static bool did_loc_db_error = false;
static bool did_asn_db_error = false;
static constexpr int msg_limit = 20;
static constexpr double msg_suppression_duration = 300;

static std::unique_ptr<MMDB> mmdb_loc;
static std::unique_ptr<MMDB> mmdb_asn;

static void report_msg(const char* format, ...) {
    if ( zeek::run_state::network_time > msg_suppression_time + msg_suppression_duration ) {
        msg_count = 0;
        msg_suppression_time = zeek::run_state::network_time;
    }

    if ( msg_count >= msg_limit )
        return;

    ++msg_count;

    va_list al;
    va_start(al, format);
    std::string msg = zeek::util::vfmt(format, al);
    va_end(al);

    zeek::reporter->Info("%s", msg.data());
}

MMDB::MMDB(const char* filename, struct stat info)
    : file_info(info), lookup_error{false}, last_check{zeek::run_state::network_time} {
    int status = MMDB_open(filename, MMDB_MODE_MMAP, &mmdb);

    if ( MMDB_SUCCESS != status ) {
        throw std::runtime_error(MMDB_strerror(status));
    }
}

MMDB::~MMDB() { MMDB_close(&mmdb); }

bool MMDB::Lookup(const zeek::IPAddr& addr, MMDB_lookup_result_s& result) {
    struct sockaddr_storage ss = {0};

    if ( IPv4 == addr.GetFamily() ) {
        struct sockaddr_in* sa = (struct sockaddr_in*)&ss;
        sa->sin_family = AF_INET;
        addr.CopyIPv4(&sa->sin_addr);
    }
    else {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)&ss;
        sa->sin6_family = AF_INET6;
        addr.CopyIPv6(&sa->sin6_addr);
    }

    try {
        result = Lookup((struct sockaddr*)&ss);
    } catch ( const std::exception& e ) {
        report_msg("MaxMind DB lookup location error [%s]", e.what());
        return false;
    }

    return result.found_entry;
}

MMDB_lookup_result_s MMDB::Lookup(const struct sockaddr* const sa) {
    int mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&mmdb, sa, &mmdb_error);

    if ( MMDB_SUCCESS != mmdb_error ) {
        lookup_error = true;
        throw std::runtime_error(MMDB_strerror(mmdb_error));
    }

    return result;
}

// Check to see if the Maxmind DB should be closed and reopened.  This will
// happen if there was a lookup error or if the mmap'd file has been replaced
// by an external process.
bool MMDB::StaleDB() {
    struct stat buf;

    if ( lookup_error )
        return true;

    static double mmdb_stale_check_interval = zeek::id::find_val("mmdb_stale_check_interval")->AsInterval();

    if ( mmdb_stale_check_interval < 0.0 )
        return false;

    if ( zeek::run_state::network_time - last_check < mmdb_stale_check_interval )
        return false;

    last_check = zeek::run_state::network_time;

    if ( 0 != stat(mmdb.filename, &buf) )
        return true;

    if ( buf.st_ino != file_info.st_ino || buf.st_mtime != file_info.st_mtime ) {
        report_msg("%s change detected for MaxMind DB [%s]",
                   buf.st_ino != file_info.st_ino ? "Inode" : "Modification time", mmdb.filename);
        return true;
    }

    return false;
}

const char* MMDB::Filename() { return mmdb.filename; }

static bool mmdb_open(const char* filename, bool asn) {
    struct stat buf;

    if ( 0 != stat(filename, &buf) ) {
        return false;
    }

    try {
        if ( asn ) {
            mmdb_asn.reset(new MMDB(filename, buf));
        }
        else {
            mmdb_loc.reset(new MMDB(filename, buf));
        }
    }

    catch ( const std::exception& e ) {
        if ( asn )
            did_asn_db_error = false;
        else
            did_loc_db_error = false;

        report_msg("Failed to open MaxMind DB: %s [%s]", filename, e.what());
        return false;
    }

    return true;
}

static bool mmdb_open_loc(const char* filename) { return mmdb_open(filename, false); }

static bool mmdb_open_asn(const char* filename) { return mmdb_open(filename, true); }

static void mmdb_check_loc() {
    if ( mmdb_loc && mmdb_loc->StaleDB() ) {
        report_msg("Closing stale MaxMind DB [%s]", mmdb_loc->Filename());
        did_loc_db_error = false;
        mmdb_loc.reset();
    }
}

static void mmdb_check_asn() {
    if ( mmdb_asn && mmdb_asn->StaleDB() ) {
        report_msg("Closing stale MaxMind DB [%s]", mmdb_asn->Filename());
        did_asn_db_error = false;
        mmdb_asn.reset();
    }
}

static zeek::ValPtr mmdb_getvalue(MMDB_entry_data_s* entry_data, int status, int data_type) {
    switch ( status ) {
        case MMDB_SUCCESS:
            if ( entry_data->has_data ) {
                switch ( data_type ) {
                    case MMDB_DATA_TYPE_UTF8_STRING:
                        return zeek::make_intrusive<zeek::StringVal>(entry_data->data_size, entry_data->utf8_string);
                        break;

                    case MMDB_DATA_TYPE_DOUBLE:
                        return zeek::make_intrusive<zeek::DoubleVal>(entry_data->double_value);
                        break;

                    case MMDB_DATA_TYPE_UINT32: return zeek::val_mgr->Count(entry_data->uint32);

                    default: break;
                }
            }
            break;

        case MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR:
            // key doesn't exist, nothing to do
            break;

        default: report_msg("MaxMind DB error [%s]", MMDB_strerror(status)); break;
    }

    return nullptr;
}

static bool mmdb_try_open_loc() {
    // City database is always preferred over Country database.
    const auto& mmdb_dir_val = zeek::detail::global_scope()->Find("mmdb_dir")->GetVal();
    std::string mmdb_dir = mmdb_dir_val->AsString()->CheckString();

    const auto& mmdb_city_db_val = zeek::detail::global_scope()->Find("mmdb_city_db")->GetVal();
    std::string mmdb_city_db = mmdb_city_db_val->AsString()->CheckString();

    const auto& mmdb_country_db_val = zeek::detail::global_scope()->Find("mmdb_country_db")->GetVal();
    std::string mmdb_country_db = mmdb_country_db_val->AsString()->CheckString();

    if ( ! mmdb_dir.empty() ) {
        auto d = mmdb_dir + "/" + mmdb_city_db;

        if ( mmdb_open_loc(d.data()) )
            return true;

        d = mmdb_dir + "/" + mmdb_country_db;

        if ( mmdb_open_loc(d.data()) )
            return true;
    }

    const auto& mmdb_dir_fallbacks_val = zeek::detail::global_scope()->Find("mmdb_dir_fallbacks")->GetVal();
    auto* vv = mmdb_dir_fallbacks_val->AsVectorVal();

    for ( unsigned int i = 0; i < vv->Size(); ++i ) {
        auto d = std::string(vv->StringAt(i)->CheckString()) + "/" + mmdb_city_db;
        if ( mmdb_open_loc(d.data()) )
            return true;
    }

    for ( unsigned int i = 0; i < vv->Size(); ++i ) {
        auto d = std::string(vv->StringAt(i)->CheckString()) + "/" + mmdb_country_db;
        if ( mmdb_open_loc(d.data()) )
            return true;
    }

    return false;
}

static bool mmdb_try_open_asn() {
    const auto& mmdb_dir_val = zeek::detail::global_scope()->Find("mmdb_dir")->GetVal();
    std::string mmdb_dir = mmdb_dir_val->AsString()->CheckString();

    const auto& mmdb_asn_db_val = zeek::detail::global_scope()->Find("mmdb_asn_db")->GetVal();
    std::string mmdb_asn_db = mmdb_asn_db_val->AsString()->CheckString();

    if ( ! mmdb_dir.empty() ) {
        auto d = mmdb_dir + "/" + mmdb_asn_db;

        if ( mmdb_open_asn(d.data()) )
            return true;
    }

    const auto& mmdb_dir_fallbacks_val = zeek::detail::global_scope()->Find("mmdb_dir_fallbacks")->GetVal();
    auto* vv = mmdb_dir_fallbacks_val->AsVectorVal();

    for ( unsigned int i = 0; i < vv->Size(); ++i ) {
        auto d = std::string(vv->StringAt(i)->CheckString()) + "/" + mmdb_asn_db;
        if ( mmdb_open_loc(d.data()) )
            return true;
    }

    return false;
}
#endif // USE_GEOIP

ValPtr mmdb_open_location_db(StringVal* filename) {
#ifdef USE_GEOIP
    return zeek::val_mgr->Bool(mmdb_open_loc(filename->CheckString()));
#else
    return zeek::val_mgr->False();
#endif
}

ValPtr mmdb_open_asn_db(StringVal* filename) {
#ifdef USE_GEOIP
    return zeek::val_mgr->Bool(mmdb_open_asn(filename->CheckString()));
#else
    return zeek::val_mgr->False();
#endif
}

RecordValPtr mmdb_lookup_location(AddrVal* addr) {
    static auto geo_location = zeek::id::find_type<zeek::RecordType>("geo_location");
    auto location = zeek::make_intrusive<zeek::RecordVal>(geo_location);

#ifdef USE_GEOIP
    mmdb_check_loc();
    if ( ! mmdb_loc ) {
        if ( ! mmdb_try_open_loc() ) {
            if ( ! did_loc_db_error ) {
                did_loc_db_error = true;
                zeek::emit_builtin_error("Failed to open GeoIP location database");
            }

            return location;
        }
    }

    MMDB_lookup_result_s result;

    if ( mmdb_loc->Lookup(addr->AsAddr(), result) ) {
        MMDB_entry_data_s entry_data;
        int status;

        // Get Country ISO Code
        status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", nullptr);
        location->Assign(0, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UTF8_STRING));

        // Get Major Subdivision ISO Code
        status = MMDB_get_value(&result.entry, &entry_data, "subdivisions", "0", "iso_code", nullptr);
        location->Assign(1, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UTF8_STRING));

        // Get City English Name
        status = MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", nullptr);
        location->Assign(2, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UTF8_STRING));

        // Get Location Latitude
        status = MMDB_get_value(&result.entry, &entry_data, "location", "latitude", nullptr);
        location->Assign(3, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_DOUBLE));

        // Get Location Longitude
        status = MMDB_get_value(&result.entry, &entry_data, "location", "longitude", nullptr);
        location->Assign(4, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_DOUBLE));

        return location;
    }

#else // not USE_GEOIP
    static int missing_geoip_reported = 0;

    if ( ! missing_geoip_reported ) {
        zeek::emit_builtin_error("Zeek was not configured for GeoIP support");
        missing_geoip_reported = 1;
    }
#endif

    // We can get here even if we have MMDB support if we weren't
    // able to initialize it or it didn't return any information for
    // the address.
    return location;
}

RecordValPtr mmdb_lookup_autonomous_system(AddrVal* addr) {
    static auto geo_autonomous_system = zeek::id::find_type<zeek::RecordType>("geo_autonomous_system");
    auto autonomous_system = zeek::make_intrusive<zeek::RecordVal>(geo_autonomous_system);

#ifdef USE_GEOIP
    mmdb_check_asn();
    if ( ! mmdb_asn ) {
        if ( ! mmdb_try_open_asn() ) {
            if ( ! did_asn_db_error ) {
                did_asn_db_error = true;
                zeek::emit_builtin_error("Failed to open GeoIP ASN database");
            }

            return autonomous_system;
        }
    }

    MMDB_lookup_result_s result;

    if ( mmdb_asn->Lookup(addr->AsAddr(), result) ) {
        MMDB_entry_data_s entry_data;
        int status;

        // Get Autonomous System Number
        status = MMDB_get_value(&result.entry, &entry_data, "autonomous_system_number", nullptr);
        autonomous_system->Assign(0, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UINT32));

        // Get Autonomous System Organization
        status = MMDB_get_value(&result.entry, &entry_data, "autonomous_system_organization", nullptr);
        autonomous_system->Assign(1, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UTF8_STRING));

        return autonomous_system;
    }

#else // not USE_GEOIP
    static int missing_geoip_reported = 0;

    if ( ! missing_geoip_reported ) {
        zeek::emit_builtin_error("Zeek was not configured for GeoIP ASN support");
        missing_geoip_reported = 1;
    }
#endif

    // We can get here even if we have GeoIP support, if we weren't
    // able to initialize it or it didn't return any information for
    // the address.
    return autonomous_system;
}

} // namespace zeek
