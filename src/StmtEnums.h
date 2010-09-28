// $Id: StmtEnums.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.


#ifndef stmt_enums_h
#define stmt_enums_h

// These are in a separate file to break circular dependences 
typedef enum {
	STMT_ANY = -1,
	STMT_ALARM, STMT_PRINT, STMT_EVENT,
	STMT_EXPR,
	STMT_IF, STMT_WHEN, STMT_SWITCH,
	STMT_FOR, STMT_NEXT, STMT_BREAK,
	STMT_RETURN,
	STMT_ADD, STMT_DELETE,
	STMT_LIST, STMT_EVENT_BODY_LIST,
	STMT_INIT,
	STMT_NULL
#define NUM_STMTS (int(STMT_NULL) + 1)
} BroStmtTag;

typedef enum {
	FLOW_NEXT,		// continue on to next statement
	FLOW_LOOP,		// go to top of loop
	FLOW_BREAK,		// break out of loop
	FLOW_RETURN		// return from function
} stmt_flow_type;

extern const char* stmt_name(BroStmtTag t);

#endif
