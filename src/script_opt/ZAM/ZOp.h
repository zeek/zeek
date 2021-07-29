// See the file "COPYING" in the main distribution directory for copyright.

// ZAM instruction opcodes and associated information.

#pragma once

namespace zeek::detail {

// Opcodes associated with ZAM instructions.
typedef enum {
#include "zeek/ZAM-OpsDefs.h"
	OP_NOP,
} ZOp;


// Possible types of instruction operands in terms of which fields they use.
// Used for low-level optimization (so important that they're correct),
// and for dumping instructions.

// V: one of the instruction's integer values, treated as a frame slot
// C: the instruction's associated constant
// I1/I2/I3/I4: the instruction's integer value, used directly (not as a slot)
// FRAME: a slot in the (intrepreter) Frame object
// X: no operands
typedef enum {
	OP_X, OP_C, OP_V, OP_V_I1, OP_VC_I1,

	OP_VC,
	OP_VV,
	OP_VV_I2,
	OP_VV_I1_I2,
	OP_VV_FRAME,

	OP_VVC,
	OP_VVC_I2,
	OP_VVV,
	OP_VVV_I3,
	OP_VVV_I2_I3,

	OP_VVVC,
	OP_VVVC_I3,
	OP_VVVC_I2_I3,
	OP_VVVC_I1_I2_I3,
	OP_VVVV,
	OP_VVVV_I4,
	OP_VVVV_I3_I4,
	OP_VVVV_I2_I3_I4,

} ZAMOpType;

// Possible "flavors" for an operator's first slot.
typedef enum {
	OP1_READ,	// the slot is read, not modified
	OP1_WRITE,	// the slot is modified, not read - the most common
	OP1_READ_WRITE,	// the slot is both read and then modified, e.g. "++"
	OP1_INTERNAL,	// we're doing some internal manipulation of the slot
} ZAMOp1Flavor;

// Maps an operand to its flavor.
extern ZAMOp1Flavor op1_flavor[];

// Maps an operand to whether it has side effects.
extern bool op_side_effects[];

} // namespace zeek::detail
