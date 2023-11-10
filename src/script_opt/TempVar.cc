// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/TempVar.h"

#include "zeek/Reporter.h"

namespace zeek::detail {

TempVar::TempVar(size_t num, ExprPtr _rhs) {
    char buf[8192];
    snprintf(buf, sizeof buf, "#%zu", num);
    name = buf;
    rhs = std::move(_rhs);
}

void TempVar::SetAlias(IDPtr _alias) {
    if ( _alias == alias )
        // This can happen when treating function parameters as
        // temporary variables.
        return;

    if ( alias )
        reporter->InternalError("Re-aliasing a temporary");

    if ( alias == id )
        reporter->InternalError("Creating alias loop");

    alias = std::move(_alias);
}

} // namespace zeek::detail
