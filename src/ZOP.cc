// See the file "COPYING" in the main distribution directory for copyright.

#include "ZOP.h"
#include "Desc.h"
#include "Reporter.h"


bool ZAM_error = false;


const char* ZOP_name(ZOp op)
	{
	switch ( op ) {
#include "ZAM-OpsNamesDefs.h"
	case OP_NOP:	return "nop";
	}
	}

static const char* op_type_name(ZAMOpType ot)
	{
	switch ( ot ) {
		case OP_X:		return "X";
		case OP_E:		return "E";
		case OP_C:		return "C";
		case OP_c:		return "c";
		case OP_V:		return "V";
		case OP_V_I1:		return "V_I1";
		case OP_VC_I1:		return "VC_I1";
		case OP_VE:		return "VE";
		case OP_VC:		return "VC";
		case OP_Vc:		return "Vc";
		case OP_VV:		return "VV";
		case OP_VV_I2:		return "VV_I2";
		case OP_VV_I1_I2:	return "VV_I1_I2";
		case OP_VV_FRAME:	return "VV_FRAME";
		case OP_VVC:		return "VVC";
		case OP_VVC_I2:		return "VVC_I2";
		case OP_ViC_ID:		return "ViC_ID";
		case OP_VVc:		return "VVc";
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
#include "ZAM-Op1FlavorsDefs.h"
	OP1_INTERNAL,	// OP_NOP
};

bool op_side_effects[] = {
#include "ZAM-OpSideEffects.h"
	false,	// OP_NOP
};


void ZInst::Dump(int inst_num, const FrameReMap* mappings) const
	{
	int n = NumFrameSlots();
	// printf("v%d ", n);

	auto id1 = VName(n, 1, inst_num, mappings);
	auto id2 = VName(n, 2, inst_num, mappings);
	auto id3 = VName(n, 3, inst_num, mappings);
	auto id4 = VName(n, 4, inst_num, mappings);

	Dump(id1, id2, id3, id4);

	delete id1;
	delete id2;
	delete id3;
	delete id4;
	}

void ZInst::Dump(const char* id1, const char* id2, const char* id3,
			const char* id4) const
	{
	printf("%s ", ZOP_name(op));
	// printf("(%s) ", op_type_name(op_type));
	if ( t && 0 )
		printf("(%s) ", type_name(t->Tag()));

	switch ( op_type ) {
	case OP_X:
		break;

	case OP_V:
		printf("%s", id1);
		break;

	case OP_VV:
		printf("%s, %s", id1, id2);
		break;

	case OP_VVV:
		printf("%s, %s, %s", id1, id2, id3);
		break;

	case OP_VVVV:
		printf("%s, %s, %s, %s", id1, id2, id3, id4);
		break;

	case OP_VVVC:
		printf("%s, %s, %s, %s", id1, id2, id3, ConstDump());
		break;

	case OP_C:
		printf("%s", ConstDump());
		break;

	case OP_c:
		printf("<special-constant>");
		break;

	case OP_VC:
		printf("%s, %s", id1, ConstDump());
		break;

	case OP_Vc:
		printf("%s, <special-constant>", id1);
		break;

	case OP_VVC:
		// Special-case OP_LOG_WRITE_VVC, which uses a different
		// type for its constant.
		if ( op == OP_LOG_WRITE_VVC )
			printf("%s, %s, %llu", id1, id2, c.uint_val);
		else
			printf("%s, %s, %s", id1, id2, ConstDump());
		break;

	case OP_E:
		printf("%s", obj_desc(e));
		break;

	case OP_VE:
		printf("%s, %s", id1, obj_desc(e));
		break;

	case OP_V_I1:
		printf("%d", v1);
		break;

	case OP_VC_I1:
		printf("%d %s", v1, ConstDump());
		break;

	case OP_VV_FRAME:
		printf("%s, interpreter frame[%d]", id1, v2);
		break;

	case OP_VVc:
		printf("%s, %s, <special-constant>", id1, id2);
		break;

	case OP_VV_I2:
		printf("%s, %d", id1, v2);
		break;

	case OP_VV_I1_I2:
		printf("%d, %d", v1, v2);
		break;

	case OP_VVC_I2:
		printf("%s, %d, %s", id1, v2, ConstDump());
		break;

	case OP_ViC_ID:
		printf("%s, %d, ID %s", id1, v2, obj_desc(c.any_val));
		break;

	case OP_VVV_I3:
		printf("%s, %s, %d", id1, id2, v3);
		break;

	case OP_VVV_I2_I3:
		printf("%s, %d, %d", id1, v2, v3);
		break;

	case OP_VVVV_I4:
		printf("%s, %s, %s, %d", id1, id2, id3, v4);
		break;

	case OP_VVVV_I3_I4:
		printf("%s, %s, %d, %d", id1, id2, v3, v4);
		break;

	case OP_VVVV_I2_I3_I4:
		printf("%s, %d, %d, %d", id1, v2, v3, v4);
		break;

	case OP_VVVC_I3:
		printf("%s, %s, %d, %s", id1, id2, v3, ConstDump());
		break;

	case OP_VVVC_I2_I3:
		printf("%s, %d, %d, %s", id1, v2, v3, ConstDump());
		break;

	case OP_VVVC_I1_I2_I3:
		printf("%d, %d, %d, %s", v1, v2, v3, ConstDump());
		break;
	}

	if ( func )
		printf(" (func %s)", func->Name());

	printf("\n");
	}

int ZInst::NumFrameSlots() const
	{
	switch ( op_type ) {
	case OP_X:	return 0;
	case OP_V:	return 1;
	case OP_VV:	return 2;
	case OP_VVV:	return 3;
	case OP_VVVV:	return 4;
	case OP_VVVC:	return 3;
	case OP_C:	return 0;
	case OP_c:	return 0;
	case OP_VC:	return 1;
	case OP_Vc:	return 1;
	case OP_VVC:	return 2;
	case OP_E:	return 0;
	case OP_VE:	return 1;

	case OP_V_I1:	return 0;
	case OP_VC_I1:	return 0;
	case OP_VV_I1_I2:	return 0;
	case OP_VV_FRAME:	return 1;
	case OP_VVc:	return 2;
	case OP_VV_I2:	return 1;
	case OP_VVC_I2:	return 1;
	case OP_ViC_ID:	return 1;
	case OP_VVV_I3:	return 2;
	case OP_VVV_I2_I3:	return 1;

	case OP_VVVV_I4:	return 3;
	case OP_VVVV_I3_I4:	return 2;
	case OP_VVVV_I2_I3_I4:	return 1;
	case OP_VVVC_I3:	return 2;
	case OP_VVVC_I2_I3:	return 1;
	case OP_VVVC_I1_I2_I3:	return 0;
	}
	}

const char* ZInst::VName(int max_n, int n, int inst_num,
				const FrameReMap* mappings) const
	{
	if ( n > max_n )
		return nullptr;

	int slot = n == 1 ? v1 : (n == 2 ? v2 : (n == 3 ? v3 : v4));

	const ID* id;

	// Find which identifier manifests at this instruction.
	ASSERT(slot >= 0 && slot < mappings->size());

	auto& map = (*mappings)[slot];

	int i;
	for ( i = 0; i < map.ids.size(); ++i )
		{
		// If the slot is right at the boundary between
		// two identifiers, then it matters whether this
		// is slot 1 (starts right here) vs. slot > 1
		// (ignore change right at the boundary and stick
		// with older value).
		if ( (n == 1 && map.id_start[i] > inst_num) ||
		     (n > 1 && map.id_start[i] >= inst_num) )
			// Went too far.
			break;
		}

	if ( i < map.ids.size() )
		{
		ASSERT(i > 0);
		}

	id = map.ids[i-1];

	return copy_string(fmt("%d (%s)", slot, id->Name()));
	}

const char* ZInst::ConstDump() const
	{
	auto v = c.ToVal(t);

	static ODesc d;

	d.Clear();
	v->Describe(&d);

	return d.Description();
	}


void ZInstI::Dump(const FrameMap* frame_ids, const FrameReMap* remappings)
			const
	{
	int n = NumFrameSlots();
	// printf("v%d ", n);

	auto id1 = VName(n, 1, frame_ids, remappings);
	auto id2 = VName(n, 2, frame_ids, remappings);
	auto id3 = VName(n, 3, frame_ids, remappings);
	auto id4 = VName(n, 4, frame_ids, remappings);

	ZInst::Dump(id1, id2, id3, id4);

	delete id1;
	delete id2;
	delete id3;
	delete id4;
	}

const char* ZInstI::VName(int max_n, int n, const FrameMap* frame_ids,
				const FrameReMap* remappings) const
	{
	if ( n > max_n )
		return nullptr;

	int slot = n == 1 ? v1 : (n == 2 ? v2 : (n == 3 ? v3 : v4));

	const ID* id;

	if ( remappings && live )
		{ // Find which identifier manifests at this instruction.
		ASSERT(slot >= 0 && slot < remappings->size());

		auto& map = (*remappings)[slot];

		int i;
		for ( i = 0; i < map.ids.size(); ++i )
			{
			// If the slot is right at the boundary between
			// two identifiers, then it matters whether this
			// is slot 1 (starts right here) vs. slot > 1
			// (ignore change right at the boundary and stick
			// with older value).
			if ( (n == 1 && map.id_start[i] > inst_num) ||
			     (n > 1 && map.id_start[i] >= inst_num) )
				// Went too far.
				break;
			}

		if ( i < map.ids.size() )
			{
			ASSERT(i > 0);
			}

		id = map.ids[i-1];
		}

	else
		id = (*frame_ids)[slot];

	return copy_string(fmt("%d (%s)", slot, id->Name()));
	}

bool ZInstI::DoesNotContinue() const
	{
	switch ( op ) {
	case OP_RETURN_X:
	case OP_RETURN_V:
	case OP_RETURN_C:
	case OP_GOTO_V:
	case OP_HOOK_BREAK_X:
		return true;

	default:
		return false;
	}
	}

bool ZInstI::IsDirectAssignment() const
	{
	if ( op_type != OP_VV )
		return false;

	switch ( op ) {
	case OP_ASSIGN_VVi_N:
	case OP_ASSIGN_VVi_A:
	case OP_ASSIGN_VVi_O:
	case OP_ASSIGN_VVi_P:
	case OP_ASSIGN_VVi_R:
	case OP_ASSIGN_VVi_S:
	case OP_ASSIGN_VVi_F:
	case OP_ASSIGN_VVi_T:
	case OP_ASSIGN_VVi_V:
	case OP_ASSIGN_VVi_L:
	case OP_ASSIGN_VVi_f:
	case OP_ASSIGN_VVi_t:
	case OP_ASSIGN_VVi:
		return true;

	default:
		return false;
	}
	}

bool ZInstI::HasSideEffects() const
	{
	return op_side_effects[op];
	}

bool ZInstI::AssignsToSlot1() const
	{
	switch ( op_type ) {
	case OP_X:
	case OP_C:
	case OP_c:
	case OP_E:
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return false;

	// We use this ginormous set of cases rather than "default" so
	// that when we add a new operand type, we have to consider
	// its behavior here.
	case OP_V:
	case OP_VC:
	case OP_Vc:
	case OP_VE:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_ViC_ID:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
	case OP_VV:
	case OP_VVc:
	case OP_VVC:
	case OP_VVV_I3:
	case OP_VVVV_I3_I4:
	case OP_VVVC_I3:
	case OP_VVV:
	case OP_VVVC:
	case OP_VVVV_I4:
	case OP_VVVV:
		auto fl = op1_flavor[op];
		return fl == OP1_WRITE || fl == OP1_READ_WRITE;
	}
	}

bool ZInstI::UsesSlot(int slot) const
	{
	auto fl = op1_flavor[op];
	auto v1_relevant = fl == OP1_READ || fl == OP1_READ_WRITE;
	auto v1_match = v1_relevant && v1 == slot;

	switch ( op_type ) {
	case OP_X:
	case OP_C:
	case OP_c:
	case OP_E:
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return false;

	case OP_V:
	case OP_VC:
	case OP_Vc:
	case OP_VE:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_ViC_ID:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
		return v1_match;

	case OP_VV:
	case OP_VVc:
	case OP_VVC:
	case OP_VVV_I3:
	case OP_VVVV_I3_I4:
	case OP_VVVC_I3:
		return v1_match || v2 == slot;

	case OP_VVV:
	case OP_VVVC:
	case OP_VVVV_I4:
		return v1_match || v2 == slot || v3 == slot;

	case OP_VVVV:
		return v1_match || v2 == slot || v3 == slot || v4 == slot;
	}
	}

bool ZInstI::UsesSlots(int& s1, int& s2, int& s3, int& s4) const
	{
	s1 = s2 = s3 = s4 = -1;

	auto fl = op1_flavor[op];
	auto v1_relevant = fl == OP1_READ || fl == OP1_READ_WRITE;

	switch ( op_type ) {
	case OP_X:
	case OP_C:
	case OP_c:
	case OP_E:
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return false;

	case OP_V:
	case OP_VC:
	case OP_Vc:
	case OP_VE:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_ViC_ID:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
		if ( ! v1_relevant )
			return false;

		s1 = v1;
		return true;

	case OP_VV:
	case OP_VVc:
	case OP_VVC:
	case OP_VVV_I3:
	case OP_VVVV_I3_I4:
	case OP_VVVC_I3:
		s1 = v2;

		if ( v1_relevant )
			s2 = v1;

		return true;

	case OP_VVV:
	case OP_VVVC:
	case OP_VVVV_I4:
		s1 = v2;
		s2 = v3;

		if ( v1_relevant )
			s3 = v1;

		return true;

	case OP_VVVV:
		s1 = v2;
		s2 = v3;
		s3 = v4;

		if ( v1_relevant )
			s4 = v1;

		return true;
	}
	}

void ZInstI::UpdateSlots(std::vector<int>& slot_mapping)
	{
	switch ( op_type ) {
	case OP_X:
	case OP_C:
	case OP_c:
	case OP_E:
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return;	// so we don't do any v1 remapping.

	case OP_V:
	case OP_VC:
	case OP_Vc:
	case OP_VE:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_ViC_ID:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
		break;

	case OP_VV:
	case OP_VVc:
	case OP_VVC:
	case OP_VVV_I3:
	case OP_VVVV_I3_I4:
	case OP_VVVC_I3:
		v2 = slot_mapping[v2];
		break;

	case OP_VVV:
	case OP_VVVC:
	case OP_VVVV_I4:
		v2 = slot_mapping[v2];
		v3 = slot_mapping[v3];
		break;

	case OP_VVVV:
		v2 = slot_mapping[v2];
		v3 = slot_mapping[v3];
		v4 = slot_mapping[v4];
		break;
	}

	// Note, unlike for UsesSlots we do *not* include OP1_READ_WRITE
	// here, because such instructions will already have v1 remapped
	// given it's an assignment target.
	if ( op1_flavor[op] == OP1_READ )
		v1 = slot_mapping[v1];
	}

void ZInstI::InitConst(const ConstExpr* ce)
	{
	auto v = ce->ValuePtr();
	auto ct = ce->Type().get();
	t = ct;
	c = ZAMValUnion(v, t);

	if ( ZAM_error )
		reporter->InternalError("bad value compiling code");
	}
