// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/MMDB.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "zeek/Func.h"
#include "zeek/IPAddr.h"
#include "zeek/ZeekString.h"

namespace zeek {

#ifdef USE_GEOIP

static int msg_count = 0;
static double msg_suppression_time = 0;
static constexpr int msg_limit = 20;
static constexpr double msg_suppression_duration = 300;

LocDB mmdb_loc;
AsnDB mmdb_asn;

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

MMDB::MMDB() : mmdb{}, file_info{}, last_check{zeek::run_state::network_time} {}

MMDB::~MMDB() { Close(); }

bool MMDB::OpenFile(const std::string& a_filename) {
    filename = a_filename;
    Close();

    if ( 0 != stat(filename.data(), &file_info) ) {
        return false;
    }

    int status = MMDB_open(a_filename.data(), MMDB_MODE_MMAP, &mmdb);

    if ( MMDB_SUCCESS != status ) {
        memset(&mmdb, 0, sizeof(mmdb));
        report_msg("Failed to open MaxMind DB: %s [%s]", filename.data(), MMDB_strerror(status));
        return false;
    }

    return true;
}

void MMDB::Close() {
    if ( IsOpen() ) {
        MMDB_close(&mmdb);
        memset(&mmdb, 0, sizeof(mmdb));
        reported_error = false;
    }
}

bool MMDB::EnsureLoaded() {
    bool res = true;

    if ( filename.empty() )
        res = OpenFromScriptConfig();
    else if ( ! IsOpen() )
        res = OpenFile(filename);
    else if ( IsStaleDB() ) {
        report_msg("Closing stale MaxMind DB [%s]", filename.data());
        if ( ! OpenFile(filename) )
            res = false;
    }

    if ( ! res && ! reported_error ) {
        reported_error = true;
        zeek::emit_builtin_error(
            zeek::util::fmt("Failed to open %.*s", static_cast<int>(Description().size()), Description().data()));
    }

    return res;
}

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

    int mmdb_error;
    result = MMDB_lookup_sockaddr(&mmdb, (struct sockaddr*)&ss, &mmdb_error);

    if ( MMDB_SUCCESS != mmdb_error ) {
        report_msg("MaxMind DB lookup location error [%s]", MMDB_strerror(mmdb_error));
        Close();
        return false;
    }

    return result.found_entry;
}

// Check to see if the Maxmind DB should be closed and reopened.  This will
// happen if there was a lookup error or if the mmap'd file has been replaced
// by an external process.
bool MMDB::IsStaleDB() {
    if ( ! IsOpen() )
        return false;

    static double mmdb_stale_check_interval = zeek::id::find_val("mmdb_stale_check_interval")->AsInterval();

    if ( mmdb_stale_check_interval < 0.0 )
        return false;

    if ( zeek::run_state::network_time - last_check < mmdb_stale_check_interval )
        return false;

    last_check = zeek::run_state::network_time;
    struct stat buf;

    if ( 0 != stat(mmdb.filename, &buf) )
        return true;

    if ( buf.st_ino != file_info.st_ino || buf.st_mtime != file_info.st_mtime ) {
        report_msg("%s change detected for MaxMind DB [%s]",
                   buf.st_ino != file_info.st_ino ? "Inode" : "Modification time", mmdb.filename);
        return true;
    }

    return false;
}

bool LocDB::OpenFromScriptConfig() {
    // City database is always preferred over Country database.
    const auto& mmdb_dir_val = zeek::id::find_val<StringVal>("mmdb_dir");
    std::string mmdb_dir{mmdb_dir_val->ToStdStringView()};

    const auto& mmdb_city_db_val = zeek::id::find_val<StringVal>("mmdb_city_db");
    std::string mmdb_city_db{mmdb_city_db_val->ToStdStringView()};

    const auto& mmdb_country_db_val = zeek::id::find_val<StringVal>("mmdb_country_db");
    std::string mmdb_country_db{mmdb_country_db_val->ToStdStringView()};

    if ( ! mmdb_dir.empty() ) {
        auto d = mmdb_dir + "/" + mmdb_city_db;

        if ( OpenFile(d) )
            return true;

        d = mmdb_dir + "/" + mmdb_country_db;

        if ( OpenFile(d) )
            return true;
    }

    const auto& mmdb_dir_fallbacks_val = zeek::id::find_val<VectorVal>("mmdb_dir_fallbacks");

    for ( unsigned int i = 0; i < mmdb_dir_fallbacks_val->Size(); ++i ) {
        auto d = mmdb_dir_fallbacks_val->StringValAt(i)->ToStdString() + "/" + mmdb_city_db;
        if ( OpenFile(d) )
            return true;
    }

    for ( unsigned int i = 0; i < mmdb_dir_fallbacks_val->Size(); ++i ) {
        auto d = mmdb_dir_fallbacks_val->StringValAt(i)->ToStdString() + "/" + mmdb_country_db;
        if ( OpenFile(d) )
            return true;
    }

    return false;
}
bool AsnDB::OpenFromScriptConfig() {
    const auto& mmdb_dir_val = zeek::id::find_val<StringVal>("mmdb_dir");
    std::string mmdb_dir{mmdb_dir_val->ToStdStringView()};

    const auto& mmdb_asn_db_val = zeek::id::find_val<StringVal>("mmdb_asn_db");
    std::string mmdb_asn_db{mmdb_asn_db_val->ToStdStringView()};

    if ( ! mmdb_dir.empty() ) {
        auto d = mmdb_dir + "/" + mmdb_asn_db;

        if ( OpenFile(d) )
            return true;
    }

    const auto& mmdb_dir_fallbacks_val = zeek::id::find_val<VectorVal>("mmdb_dir_fallbacks");

    for ( unsigned int i = 0; i < mmdb_dir_fallbacks_val->Size(); ++i ) {
        auto d = mmdb_dir_fallbacks_val->StringValAt(i)->ToStdString() + "/" + mmdb_asn_db;
        if ( OpenFile(d) )
            return true;
    }

    return false;
}
#endif // USE_GEOIP

ValPtr mmdb_open_location_db(const StringValPtr& filename) {
#ifdef USE_GEOIP
    return zeek::val_mgr->Bool(mmdb_loc.OpenFile(filename->ToStdString()));
#else
    return zeek::val_mgr->False();
#endif
}

ValPtr mmdb_open_asn_db(const StringValPtr& filename) {
#ifdef USE_GEOIP
    return zeek::val_mgr->Bool(mmdb_asn.OpenFile(filename->ToStdString()));
#else
    return zeek::val_mgr->False();
#endif
}

RecordValPtr mmdb_lookup_location(const AddrValPtr& addr) {
    static auto geo_location = zeek::id::find_type<zeek::RecordType>("geo_location");
    auto location = zeek::make_intrusive<zeek::RecordVal>(geo_location);

#ifdef USE_GEOIP
    if ( ! mmdb_loc.EnsureLoaded() )
        return location;

    MMDB_lookup_result_s result;

    if ( mmdb_loc.Lookup(addr->AsAddr(), result) ) {
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

RecordValPtr mmdb_lookup_autonomous_system(const AddrValPtr& addr) {
    static auto geo_autonomous_system = zeek::id::find_type<zeek::RecordType>("geo_autonomous_system");
    auto autonomous_system = zeek::make_intrusive<zeek::RecordVal>(geo_autonomous_system);

#ifdef USE_GEOIP
    if ( ! mmdb_asn.EnsureLoaded() )
        return autonomous_system;

    MMDB_lookup_result_s result;

    if ( mmdb_asn.Lookup(addr->AsAddr(), result) ) {
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
