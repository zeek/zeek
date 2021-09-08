// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/Support.h"
#include "zeek/script_opt/ZAM/ZOp.h"


namespace zeek::detail {

const char* ZOP_name(ZOp op)
	{
	switch ( op ) {
#include "zeek/ZAM-OpsNamesDefs.h"
	case OP_NOP:	return "nop";
	}
	}

static const char* op_type_name(ZAMOpType ot)
	{
	switch ( ot ) {
		case OP_X:		return "X";
		case OP_C:		return "C";
		case OP_V:		return "V";
		case OP_V_I1:		return "V_I1";
		case OP_VC_I1:		return "VC_I1";
		case OP_VC:		return "VC";
		case OP_VV:		return "VV";
		case OP_VV_I2:		return "VV_I2";
		case OP_VV_I1_I2:	return "VV_I1_I2";
		case OP_VV_FRAME:	return "VV_FRAME";
		case OP_VVC:		return "VVC";
		case OP_VVC_I2:		return "VVC_I2";
		case OP_VVV:		return "VVV";
		case OP_VVV_I3:		return "VVV_I3";
		case OP_VVV_I2_I3:	return "VVV_I2_I3";
		case OP_VVVC:		return "VVVC";
		case OP_VVVC_I3:	return "VVVC_I3";
		case OP_VVVC_I2_I3:	return "VVVC_I2_I3";
		case OP_VVVC_I1_I2_I3:	return "VVVC_I1_I2_I3";
		case OP_VVVV:		return "VVVV";
		case OP_VVVV_I4:	return "VVVV_I4";
		case OP_VVVV_I3_I4:	return "VVVV_I3_I4";
		case OP_VVVV_I2_I3_I4:	return "VVVV_I2_I3_I4";
	}
	}


ZAMOp1Flavor op1_flavor[] = {
#include "zeek/ZAM-Op1FlavorsDefs.h"
	OP1_INTERNAL,	// OP_NOP
};

bool op_side_effects[] = {
#include "zeek/ZAM-OpSideEffects.h"
	false,	// OP_NOP
};


std::unordered_map<ZOp, std::unordered_map<TypeTag, ZOp>> assignment_flavor;
std::unordered_map<ZOp, ZOp> assignmentless_op;
std::unordered_map<ZOp, ZAMOpType> assignmentless_op_type;

ZOp AssignmentFlavor(ZOp orig, TypeTag tag, bool strict)
	{
	static bool did_init = false;

	if ( ! did_init )
		{
		std::unordered_map<TypeTag, ZOp> empty_map;

#include "zeek/ZAM-AssignFlavorsDefs.h"

		did_init = true;
		}

	// Map type tag to equivalent, as needed.
	switch ( tag ) {
	case TYPE_BOOL:
	case TYPE_ENUM:
		tag = TYPE_INT;
		break;

	case TYPE_PORT:
		tag = TYPE_COUNT;
		break;

	case TYPE_TIME:
	case TYPE_INTERVAL:
		tag = TYPE_DOUBLE;
		break;

	default:
		break;
	}

	if ( assignment_flavor.count(orig) == 0 )
		{
		if ( strict )
			ASSERT(false);
		else
			return OP_NOP;
		}

	auto orig_map = assignment_flavor[orig];

	if ( orig_map.count(tag) == 0 )
		{
		if ( strict )
			ASSERT(false);
		else
			return OP_NOP;
		}

	return orig_map[tag];
	}

} // zeek::detail
