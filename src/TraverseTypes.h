// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>

namespace zeek::detail {

class TraversalCallback;

enum TraversalCode : uint8_t {
    TC_CONTINUE = 0,
    TC_ABORTALL = 1,
    TC_ABORTSTMT = 2,
};

#define HANDLE_TC_STMT_PRE(code)                                                                                       \
    {                                                                                                                  \
        switch ( code ) {                                                                                              \
            case zeek::detail::TC_ABORTALL: return (code);                                                             \
            case zeek::detail::TC_ABORTSTMT: return zeek::detail::TC_CONTINUE;                                         \
            case zeek::detail::TC_CONTINUE:                                                                            \
            default: break;                                                                                            \
        }                                                                                                              \
    }

#define HANDLE_TC_STMT_POST(code)                                                                                      \
    {                                                                                                                  \
        switch ( code ) {                                                                                              \
            case zeek::detail::TC_ABORTSTMT: return zeek::detail::TC_CONTINUE;                                         \
            case zeek::detail::TC_ABORTALL:                                                                            \
            case zeek::detail::TC_CONTINUE:                                                                            \
            default: return (code);                                                                                    \
        }                                                                                                              \
    }

#define HANDLE_TC_EXPR_PRE(code) HANDLE_TC_STMT_PRE(code)
#define HANDLE_TC_EXPR_POST(code) return (code);

#define HANDLE_TC_TYPE_PRE(code) HANDLE_TC_STMT_PRE(code)
#define HANDLE_TC_TYPE_POST(code) return (code);

#define HANDLE_TC_ATTRS_PRE(code) HANDLE_TC_STMT_PRE(code)
#define HANDLE_TC_ATTRS_POST(code) return (code);

#define HANDLE_TC_ATTR_PRE(code) HANDLE_TC_STMT_PRE(code)
#define HANDLE_TC_ATTR_POST(code) return (code);

} // namespace zeek::detail
