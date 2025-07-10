// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/stat.h>

#include "zeek/Val.h"

namespace zeek {

#ifdef USE_GEOIP

#include <maxminddb.h>

// The MMDB class encapsulates a low-level libmaxmind MMDB_s structure. It
// tracks whether that DB is currently loaded, and can open it from a file in
// two ways: (1) via explicit specification of a filename, (2) by determining
// the configuration from configuration settings in the script layer (mmdb_dir
// etc). This configuration depends on whether this is a geolocation DB or an
// ASN one, so details are left to derived classes below that specialize.
//
// The class tracks the inode and modification time of a DB file to detect
// "stale" DBs, which get reloaded (from the same location in the file system)
// upon the first lookup that detects staleness.
class MMDB {
public:
    MMDB();
    virtual ~MMDB();

    // Implements the logic to determine a file system path for the DB from
    // script-layer configuration settings, and opens the DB from there. Returns
    // true if successful, false otherwise.
    virtual bool OpenFromScriptConfig() = 0;

    // Helper string to identify the type of DB, useful in error messages.
    virtual std::string_view Description() = 0;

    // Opens the DB at the given location, closing and cleaning up any currently
    // opened DB if there is one. Returns true if successful, false otherwise.
    bool OpenFile(const std::string& filename);

    // Closes a currently opened DB, releasing its state. Safe to call on a
    // closed DB.
    void Close();

    // Predicate; returns true if the DB is currently opened.
    bool IsOpen() const { return mmdb.filename != nullptr; }

    // Ensures that upon return the underlying DB file is loaded. When no
    // filename is configured for the DB (i.e. OpenFile() has never been called
    // on it), this triggers the script-level configuration lookup via
    // OpenFromScriptConfig(). When a filename is available but it's not
    // currently loaded, it does so. Finally, if there's a loaded DB but it's
    // found to be stale, it gets reloaded. When the load operation succeeds, or
    // the DB was already loaded and not stale, this returns true, and false if
    // anything went wrong.
    bool EnsureLoaded();

    // Looks up a given IP address in the DB, storing the result in the provided
    // result structure.
    bool Lookup(const zeek::IPAddr& addr, MMDB_lookup_result_s& result);

private:
    bool IsStaleDB();

    std::string filename;
    MMDB_s mmdb;
    struct stat file_info;
    bool reported_error = false; // to ensure we emit builtin errors during opening only once.
    double last_check;
};

class LocDB : public MMDB {
public:
    bool OpenFromScriptConfig() override;
    std::string_view Description() override { return "GeoIP location database"; }
};

class AsnDB : public MMDB {
public:
    bool OpenFromScriptConfig() override;
    std::string_view Description() override { return "GeoIP ASN database"; }
};

#endif // USE_GEOIP

ValPtr mmdb_open_location_db(const StringValPtr& filename);
ValPtr mmdb_open_asn_db(const StringValPtr& filename);

RecordValPtr mmdb_lookup_location(const AddrValPtr& addr);
RecordValPtr mmdb_lookup_autonomous_system(const AddrValPtr& addr);

} // namespace zeek
