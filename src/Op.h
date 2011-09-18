// See the file "COPYING" in the main distribution directory for copyright.

#ifndef op_h
#define op_h

// BRO operations.

typedef enum {
	OP_INCR, OP_DECR, OP_NOT, OP_NEGATE,
	OP_PLUS, OP_MINUS, OP_TIMES, OP_DIVIDE, OP_MOD,
	OP_AND, OP_OR,
	OP_LT, OP_LE, OP_EQ, OP_NE, OP_GE, OP_GT,
	OP_MATCH,
	OP_ASSIGN,
	OP_INDEX, OP_FIELD,
	OP_IN,
	OP_LIST,
	OP_CALL,
	OP_SCHED,
	OP_NAME, OP_CONST, OP_THIS
} BroOP;

#endif
