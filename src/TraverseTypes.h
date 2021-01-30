// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(TraversalCallback, zeek::detail);

namespace zeek::detail {

enum TraversalCode {
	TC_CONTINUE = 0,
	TC_ABORTALL = 1,
	TC_ABORTSTMT = 2,
};

#define HANDLE_TC_STMT_PRE(code) \
	{ \
	if ( (code) == zeek::detail::TC_ABORTALL ) \
		return (code); \
	else if ( (code) == zeek::detail::TC_ABORTSTMT ) \
		return zeek::detail::TC_CONTINUE; \
	}

#define HANDLE_TC_STMT_POST(code) \
	{ \
	if ( (code) == zeek::detail::TC_ABORTALL ) \
		return (code); \
	else if ( (code) == zeek::detail::TC_ABORTSTMT ) \
		return zeek::detail::TC_CONTINUE; \
	else \
		return (code); \
	}

#define HANDLE_TC_EXPR_PRE(code) \
	{ \
	if ( (code) == zeek::detail::TC_ABORTALL ) \
		return (code); \
	else if ( (code) == zeek::detail::TC_ABORTSTMT ) \
		return zeek::detail::TC_CONTINUE; \
	}

#define HANDLE_TC_EXPR_POST(code) \
	return (code);

} // namespace zeek::detail
