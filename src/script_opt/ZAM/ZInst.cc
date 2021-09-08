// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/Func.h"
#include "zeek/script_opt/ZAM/ZInst.h"

using std::string;

namespace zeek::detail {

void ZInst::Dump(int inst_num, const FrameReMap* mappings) const
	{
	// printf("v%d ", n);

	auto id1 = VName(1, inst_num, mappings);
	auto id2 = VName(2, inst_num, mappings);
	auto id3 = VName(3, inst_num, mappings);
	auto id4 = VName(4, inst_num, mappings);

	Dump(id1, id2, id3, id4);
	}

void ZInst::Dump(const string& id1, const string& id2, const string& id3,
                 const string& id4) const
	{
	printf("%s ", ZOP_name(op));
	// printf("(%s) ", op_type_name(op_type));
	if ( t && 0 )
		printf("(%s) ", type_name(t->Tag()));

	switch ( op_type ) {
	case OP_X:
		break;

	case OP_V:
		printf("%s", id1.c_str());
		break;

	case OP_VV:
		printf("%s, %s", id1.c_str(), id2.c_str());
		break;

	case OP_VVV:
		printf("%s, %s, %s", id1.c_str(), id2.c_str(), id3.c_str());
		break;

	case OP_VVVV:
		printf("%s, %s, %s, %s", id1.c_str(), id2.c_str(), id3.c_str(),
	 	       id4.c_str());
		break;

	case OP_VVVC:
		printf("%s, %s, %s, %s", id1.c_str(), id2.c_str(), id3.c_str(),
		       ConstDump().c_str());
		break;

	case OP_C:
		printf("%s", ConstDump().c_str());
		break;

	case OP_VC:
		printf("%s, %s", id1.c_str(), ConstDump().c_str());
		break;

	case OP_VVC:
		printf("%s, %s, %s", id1.c_str(), id2.c_str(),
		       ConstDump().c_str());
		break;

	case OP_V_I1:
		printf("%d", v1);
		break;

	case OP_VC_I1:
		printf("%d %s", v1, ConstDump().c_str());
		break;

	case OP_VV_FRAME:
		printf("%s, interpreter frame[%d]", id1.c_str(), v2);
		break;

	case OP_VV_I2:
		printf("%s, %d", id1.c_str(), v2);
		break;

	case OP_VV_I1_I2:
		printf("%d, %d", v1, v2);
		break;

	case OP_VVC_I2:
		printf("%s, %d, %s", id1.c_str(), v2, ConstDump().c_str());
		break;

	case OP_VVV_I3:
		printf("%s, %s, %d", id1.c_str(), id2.c_str(), v3);
		break;

	case OP_VVV_I2_I3:
		printf("%s, %d, %d", id1.c_str(), v2, v3);
		break;

	case OP_VVVV_I4:
		printf("%s, %s, %s, %d", id1.c_str(), id2.c_str(), id3.c_str(),
		       v4);
		break;

	case OP_VVVV_I3_I4:
		printf("%s, %s, %d, %d", id1.c_str(), id2.c_str(), v3, v4);
		break;

	case OP_VVVV_I2_I3_I4:
		printf("%s, %d, %d, %d", id1.c_str(), v2, v3, v4);
		break;

	case OP_VVVC_I3:
		printf("%s, %s, %d, %s", id1.c_str(), id2.c_str(), v3,
		       ConstDump().c_str());
		break;

	case OP_VVVC_I2_I3:
		printf("%s, %d, %d, %s", id1.c_str(), v2, v3,
		       ConstDump().c_str());
		break;

	case OP_VVVC_I1_I2_I3:
		printf("%d, %d, %d, %s", v1, v2, v3, ConstDump().c_str());
		break;
	}

	if ( func )
		printf(" (func %s)", func->Name());

	printf("\n");
	}

int ZInst::NumFrameSlots() const
	{
	switch ( op_type ) {
	case OP_X:
	case OP_C:
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return 0;

	case OP_V:
	case OP_VC:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
		return 1;

	case OP_VV:
	case OP_VVC:
	case OP_VVV_I3:
	case OP_VVVC_I3:
	case OP_VVVV_I3_I4:
		return 2;

	case OP_VVV:
	case OP_VVVC:
	case OP_VVVV_I4:
		return 3;

	case OP_VVVV:
		return 4;
	}
	}

int ZInst::NumSlots() const
	{
	switch ( op_type ) {
	case OP_C:
	case OP_X:
		return 0;

	case OP_V:
	case OP_V_I1:
	case OP_VC:
	case OP_VC_I1:
		return 1;

	case OP_VV:
	case OP_VVC:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_VV_I1_I2:
		return 2;

	case OP_VVV:
	case OP_VVV_I3:
	case OP_VVV_I2_I3:
	case OP_VVVC:
	case OP_VVVC_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVC_I1_I2_I3:
		return 3;

	case OP_VVVV:
	case OP_VVVV_I4:
	case OP_VVVV_I3_I4:
	case OP_VVVV_I2_I3_I4:
		return 4;
	}
	}

string ZInst::VName(int n, int inst_num, const FrameReMap* mappings) const
	{
	if ( n > NumFrameSlots() )
		return "";

	int slot = n == 1 ? v1 : (n == 2 ? v2 : (n == 3 ? v3 : v4));

	if ( slot < 0 )
		return "<special>";

	// Find which identifier manifests at this instruction.
	ASSERT(slot >= 0 && slot < mappings->size());

	auto& map = (*mappings)[slot];

	unsigned int i;
	for ( i = 0; i < map.id_start.size(); ++i )
		{
		// If the slot is right at the boundary between two
		// identifiers, then it matters whether this is slot 1
		// (starts right here) vs. slot > 1 (ignore change right
		// at the boundary and stick with older value).
		if ( (n == 1 && map.id_start[i] > inst_num) ||
		     (n > 1 && map.id_start[i] >= inst_num) )
			// Went too far.
			break;
		}

	if ( i < map.id_start.size() )
		{
		ASSERT(i > 0);
		}

	auto id = map.names.empty() ? map.ids[i-1]->Name() : map.names[i-1];

	return util::fmt("%d (%s)", slot, id);
	}

ValPtr ZInst::ConstVal() const
	{
	switch ( op_type ) {
	case OP_C:
	case OP_VC:
	case OP_VC_I1:
	case OP_VVC:
	case OP_VVC_I2:
	case OP_VVVC:
	case OP_VVVC_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVC_I1_I2_I3:
		return c.ToVal(t);

	case OP_X:
	case OP_V:
	case OP_VV:
	case OP_VVV:
	case OP_VVVV:
	case OP_V_I1:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VV_I1_I2:
	case OP_VVV_I3:
	case OP_VVV_I2_I3:
	case OP_VVVV_I4:
	case OP_VVVV_I3_I4:
	case OP_VVVV_I2_I3_I4:
		return nullptr;
	}
	}

string ZInst::ConstDump() const
	{
	auto v = ConstVal();

	ODesc d;

	d.Clear();
	v->Describe(&d);

	return d.Description();
	}


void ZInstI::Dump(const FrameMap* frame_ids, const FrameReMap* remappings) const
	{
	int n = NumFrameSlots();
	// printf("v%d ", n);

	auto id1 = VName(1, frame_ids, remappings);
	auto id2 = VName(2, frame_ids, remappings);
	auto id3 = VName(3, frame_ids, remappings);
	auto id4 = VName(4, frame_ids, remappings);

	ZInst::Dump(id1, id2, id3, id4);
	}

string ZInstI::VName(int n, const FrameMap* frame_ids,
                     const FrameReMap* remappings) const
	{
	if ( n > NumFrameSlots() )
		return "";

	int slot = n == 1 ? v1 : (n == 2 ? v2 : (n == 3 ? v3 : v4));

	if ( slot < 0 )
		return "<special>";

	const ID* id;

	if ( remappings && live )
		{ // Find which identifier manifests at this instruction.
		ASSERT(slot >= 0 && slot < remappings->size());

		auto& map = (*remappings)[slot];

		unsigned int i;
		for ( i = 0; i < map.id_start.size(); ++i )
			{
			// See discussion for ZInst::VName.
			if ( (n == 1 && map.id_start[i] > inst_num) ||
			     (n > 1 && map.id_start[i] >= inst_num) )
				// Went too far.
				break;
			}

		if ( i < map.id_start.size() )
			{
			ASSERT(i > 0);
			}

		// For ZInstI's, map.ids is always populated.
		id = map.ids[i-1];
		}

	else
		id = (*frame_ids)[slot];

	return util::fmt("%d (%s)", slot, id->Name());
	}

bool ZInstI::DoesNotContinue() const
	{
	switch ( op ) {
	case OP_GOTO_V:
	case OP_HOOK_BREAK_X:
	case OP_RETURN_C:
	case OP_RETURN_V:
	case OP_RETURN_X:
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
	case OP_ASSIGN_VV_N:
	case OP_ASSIGN_VV_A:
	case OP_ASSIGN_VV_O:
	case OP_ASSIGN_VV_P:
	case OP_ASSIGN_VV_R:
	case OP_ASSIGN_VV_S:
	case OP_ASSIGN_VV_F:
	case OP_ASSIGN_VV_T:
	case OP_ASSIGN_VV_V:
	case OP_ASSIGN_VV_L:
	case OP_ASSIGN_VV_f:
	case OP_ASSIGN_VV_t:
	case OP_ASSIGN_VV:
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
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return false;

	// We use this ginormous set of cases rather than "default" so
	// that when we add a new operand type, we have to consider
	// its behavior here.  (Same for many of the other switch's
	// used for ZInst/ZinstI.)
	case OP_V:
	case OP_VC:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
	case OP_VV:
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
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return false;

	case OP_V:
	case OP_VC:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
		return v1_match;

	case OP_VV:
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
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return false;

	case OP_V:
	case OP_VC:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
		if ( ! v1_relevant )
			return false;

		s1 = v1;
		return true;

	case OP_VV:
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
	case OP_V_I1:
	case OP_VC_I1:
	case OP_VV_I1_I2:
	case OP_VVVC_I1_I2_I3:
		return;	// so we don't do any v1 remapping.

	case OP_V:
	case OP_VC:
	case OP_VV_FRAME:
	case OP_VV_I2:
	case OP_VVC_I2:
	case OP_VVV_I2_I3:
	case OP_VVVC_I2_I3:
	case OP_VVVV_I2_I3_I4:
		break;

	case OP_VV:
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

	// Note, unlike for UsesSlots() we do *not* include OP1_READ_WRITE
	// here, because such instructions will already have v1 remapped
	// given it's an assignment target.
	if ( op1_flavor[op] == OP1_READ && v1 >= 0 )
		v1 = slot_mapping[v1];
	}

bool ZInstI::IsGlobalLoad() const
	{
	if ( op == OP_LOAD_GLOBAL_TYPE_VV )
		// These don't have flavors.
		return true;

	static std::unordered_set<ZOp> global_ops;

	if ( global_ops.empty() )
		{ // Initialize the set.
		for ( int t = 0; t < NUM_TYPES; ++t )
			{
			TypeTag tag = TypeTag(t);
			ZOp global_op_flavor =
			        AssignmentFlavor(OP_LOAD_GLOBAL_VV, tag, false);

			if ( global_op_flavor != OP_NOP )
				global_ops.insert(global_op_flavor);
			}
		}

	return global_ops.count(op) > 0;
	}

void ZInstI::InitConst(const ConstExpr* ce)
	{
	auto v = ce->ValuePtr();
	t = ce->GetType();
	c = ZVal(v, t);

	if ( ZAM_error )
		reporter->InternalError("bad value compiling code");
	}

} // zeek::detail
