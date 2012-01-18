// See the file "COPYING" in the main distribution directory for copyright.

#ifndef statictypes_h
#define statictypes_h

enum TraversalCode {
	TC_CONTINUE = 0,
	TC_ABORTALL = 1,
	TC_ABORTSTMT = 2,
};

#define HANDLE_TC_STMT_PRE(code) \
	{ \
	if ( (code) == TC_ABORTALL || (code) == TC_ABORTSTMT ) \
		return (code); \
	}

#define HANDLE_TC_STMT_POST(code) \
	{ \
	if ( (code) == TC_ABORTALL ) \
		return (code); \
	else if ( (code) == TC_ABORTSTMT ) \
		return TC_CONTINUE; \
	else \
		return (code); \
	}

#define HANDLE_TC_EXPR_PRE(code) \
	{ \
	if ( (code) != TC_CONTINUE ) \
		return (code); \
	}

#define HANDLE_TC_EXPR_POST(code) \
	return (code);

class TraversalCallback;

#endif
