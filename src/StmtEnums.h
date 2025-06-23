// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>

namespace zeek::detail {

// These are in a separate file to break circular dependences
enum StmtTag : uint8_t {
    STMT_ALARM, // Does no longer exist but kept to create enums consistent.
    STMT_PRINT,
    STMT_EVENT,
    STMT_EXPR,
    STMT_IF,
    STMT_WHEN,
    STMT_SWITCH,
    STMT_FOR,
    STMT_NEXT,
    STMT_BREAK,
    STMT_RETURN,
    STMT_LIST,
    STMT_EVENT_BODY_LIST,
    STMT_INIT,
    STMT_FALLTHROUGH,
    STMT_WHILE,
    STMT_CATCH_RETURN,  // for reduced InlineExpr's
    STMT_CHECK_ANY_LEN, // internal reduced statement
    STMT_CPP,           // compiled C++
    STMT_ZAM,           // a ZAM function body
    STMT_NULL,
    STMT_ASSERT,
    STMT_EXTERN,       // for custom Stmt subclasses provided by plugins
    STMT_STD_FUNCTION, // statements that call a std::function from c++
#define NUM_STMTS (int(STMT_STD_FUNCTION) + 1)
};

enum StmtFlowType : uint8_t {
    FLOW_NEXT,       // continue on to next statement
    FLOW_LOOP,       // go to top of loop
    FLOW_BREAK,      // break out of loop
    FLOW_RETURN,     // return from function
    FLOW_FALLTHROUGH // fall through to next switch case
};

extern const char* stmt_name(StmtTag t);

} // namespace zeek::detail
