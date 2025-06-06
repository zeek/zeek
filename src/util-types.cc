// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/util-types.h"

#include "zeek/Reporter.h"

#include "zeek/3rdparty/doctest.h"

namespace zeek::util {

namespace detail {

void SafePathOp::CheckValid(const char* op_result, const char* path, bool error_aborts) {
    if ( op_result ) {
        result = op_result;
        error = false;
    }
    else {
        if ( error_aborts )
            reporter->InternalError("Path operation failed on %s: %s", path ? path : "<null>", strerror(errno));
        else
            error = true;
    }
}


TEST_CASE("util path ops") {
#ifdef _MSC_VER
// TODO: adapt these tests to Windows paths
#else
    SUBCASE("SafeDirname") {
        SafeDirname d("/this/is/a/path", false);
        CHECK(d.result == "/this/is/a");

        SafeDirname d2("invalid", false);
        CHECK(d2.result == ".");

        SafeDirname d3("./filename", false);
        CHECK(d2.result == ".");
    }

    SUBCASE("SafeBasename") {
        SafeBasename b("/this/is/a/path", false);
        CHECK(b.result == "path");
        CHECK(! b.error);

        SafeBasename b2("justafile", false);
        CHECK(b2.result == "justafile");
        CHECK(! b2.error);
    }
#endif
}

} // namespace detail

SafeDirname::SafeDirname(const char* path, bool error_aborts) : SafePathOp() { DoFunc(path ? path : "", error_aborts); }

SafeDirname::SafeDirname(const std::string& path, bool error_aborts) : SafePathOp() { DoFunc(path, error_aborts); }

void SafeDirname::DoFunc(const std::string& path, bool error_aborts) {
    char* tmp = copy_string(path.c_str());
    CheckValid(dirname(tmp), tmp, error_aborts);
    delete[] tmp;
}

SafeBasename::SafeBasename(const char* path, bool error_aborts) : SafePathOp() {
    DoFunc(path ? path : "", error_aborts);
}

SafeBasename::SafeBasename(const std::string& path, bool error_aborts) : SafePathOp() { DoFunc(path, error_aborts); }

void SafeBasename::DoFunc(const std::string& path, bool error_aborts) {
    char* tmp = copy_string(path.c_str());
    CheckValid(basename(tmp), tmp, error_aborts);
    delete[] tmp;
}

} // namespace zeek::util
