// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

namespace zeek::detail {

// These are in a separate file to break circular dependences
enum StmtTag {
	STMT_ANY = -1,
	STMT_ALARM, // Does no longer exist but kept to create enums consistent.
	STMT_PRINT, STMT_EVENT,
	STMT_EXPR,
	STMT_IF, STMT_WHEN, STMT_SWITCH,
	STMT_FOR, STMT_NEXT, STMT_BREAK,
	STMT_RETURN,
	STMT_ADD, STMT_DELETE,
	STMT_LIST, STMT_EVENT_BODY_LIST,
	STMT_INIT,
	STMT_FALLTHROUGH,
	STMT_WHILE,
	STMT_NULL
#define NUM_STMTS (int(STMT_NULL) + 1)
};

enum StmtFlowType {
	FLOW_NEXT,		// continue on to next statement
	FLOW_LOOP,		// go to top of loop
	FLOW_BREAK,		// break out of loop
	FLOW_RETURN,		// return from function
	FLOW_FALLTHROUGH	// fall through to next switch case
};

extern const char* stmt_name(StmtTag t);

} // namespace zeek::detail

using BroStmtTag [[deprecated("Remove in v4.1. Use zeek::detail::StmtTag.")]] = zeek::detail::StmtTag;
constexpr auto STMT_ANY [[deprecated("Remove in v4.1. Use zeek::detail::STMT_ANY.")]] = zeek::detail::STMT_ANY;
constexpr auto STMT_ALARM [[deprecated("Remove in v4.1. Use zeek::detail::STMT_ALARM.")]] = zeek::detail::STMT_ALARM;
constexpr auto STMT_PRINT [[deprecated("Remove in v4.1. Use zeek::detail::STMT_PRINT.")]] = zeek::detail::STMT_PRINT;
constexpr auto STMT_EVENT [[deprecated("Remove in v4.1. Use zeek::detail::STMT_EVENT.")]] = zeek::detail::STMT_EVENT;
constexpr auto STMT_EXPR [[deprecated("Remove in v4.1. Use zeek::detail::STMT_EXPR.")]] = zeek::detail::STMT_EXPR;
constexpr auto STMT_IF [[deprecated("Remove in v4.1. Use zeek::detail::STMT_IF.")]] = zeek::detail::STMT_IF;
constexpr auto STMT_WHEN [[deprecated("Remove in v4.1. Use zeek::detail::STMT_WHEN.")]] = zeek::detail::STMT_WHEN;
constexpr auto STMT_SWITCH [[deprecated("Remove in v4.1. Use zeek::detail::STMT_SWITCH.")]] = zeek::detail::STMT_SWITCH;
constexpr auto STMT_FOR [[deprecated("Remove in v4.1. Use zeek::detail::STMT_FOR.")]] = zeek::detail::STMT_FOR;
constexpr auto STMT_NEXT [[deprecated("Remove in v4.1. Use zeek::detail::STMT_NEXT.")]] = zeek::detail::STMT_NEXT;
constexpr auto STMT_BREAK [[deprecated("Remove in v4.1. Use zeek::detail::STMT_BREAK.")]] = zeek::detail::STMT_BREAK;
constexpr auto STMT_RETURN [[deprecated("Remove in v4.1. Use zeek::detail::STMT_RETURN.")]] = zeek::detail::STMT_RETURN;
constexpr auto STMT_ADD [[deprecated("Remove in v4.1. Use zeek::detail::STMT_ADD.")]] = zeek::detail::STMT_ADD;
constexpr auto STMT_DELETE [[deprecated("Remove in v4.1. Use zeek::detail::STMT_DELETE.")]] = zeek::detail::STMT_DELETE;
constexpr auto STMT_LIST [[deprecated("Remove in v4.1. Use zeek::detail::STMT_LIST.")]] = zeek::detail::STMT_LIST;
constexpr auto STMT_EVENT_BODY_LIST [[deprecated("Remove in v4.1. Use zeek::detail::STMT_EVENT_BODY_LIST.")]] = zeek::detail::STMT_EVENT_BODY_LIST;
constexpr auto STMT_INIT [[deprecated("Remove in v4.1. Use zeek::detail::STMT_INIT.")]] = zeek::detail::STMT_INIT;
constexpr auto STMT_FALLTHROUGH [[deprecated("Remove in v4.1. Use zeek::detail::STMT_FALLTHROUGH.")]] = zeek::detail::STMT_FALLTHROUGH;
constexpr auto STMT_WHILE [[deprecated("Remove in v4.1. Use zeek::detail::STMT_WHILE.")]] = zeek::detail::STMT_WHILE;
constexpr auto STMT_NULL [[deprecated("Remove in v4.1. Use zeek::detail::STMT_NULL.")]] = zeek::detail::STMT_NULL;

using stmt_flow_type [[deprecated("Remove in v4.1. Use zeek::detail::StmtFlowType.")]] = zeek::detail::StmtFlowType;
constexpr auto FLOW_NEXT [[deprecated("Remove in v4.1. Use zeek::detail::FLOW_NEXT.")]] = zeek::detail::FLOW_NEXT;
constexpr auto FLOW_LOOP [[deprecated("Remove in v4.1. Use zeek::detail::FLOW_LOOP.")]] = zeek::detail::FLOW_LOOP;
constexpr auto FLOW_BREAK [[deprecated("Remove in v4.1. Use zeek::detail::FLOW_BREAK.")]] = zeek::detail::FLOW_BREAK;
constexpr auto FLOW_RETURN [[deprecated("Remove in v4.1. Use zeek::detail::FLOW_RETURN.")]] = zeek::detail::FLOW_RETURN;
constexpr auto FLOW_FALLTHROUGH [[deprecated("Remove in v4.1. Use zeek::detail::FLOW_FALLTHROUGH.")]] = zeek::detail::FLOW_FALLTHROUGH;

constexpr auto stmt_name [[deprecated("Remove in v4.1. Use zeek::detail::stmt_name.")]] = zeek::detail::stmt_name;
