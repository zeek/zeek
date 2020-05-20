// See the file "COPYING" in the main distribution directory for copyright.

#include "ZOP.h"
#include "Desc.h"
#include "Reporter.h"


static const char* abstract_op_name(ZOp op)
	{
	switch ( op ) {
	case OP_NOP:	return "nop";
#include "ZAM-OpsNamesDefs.h"
	}
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
	case OP_VC:	return 1;
	case OP_VVC:	return 2;
	case OP_E:	return 0;
	case OP_VE:	return 1;

	case OP_V_I1:	return 0;
	case OP_VV_FRAME:	return 1;
	case OP_VC_ID:	return 1;
	case OP_VV_I2:	return 1;
	case OP_VVC_I2:	return 1;
	case OP_VVV_I3:	return 2;
	case OP_VVV_I2_I3:	return 1;
	}
	}

const char* ZInst::VName(int max_n, int n, const frame_map& frame_ids) const
	{
	if ( n > max_n )
		return nullptr;

	int slot = n == 1 ? v1 : (n == 2 ? v2 : (n == 3 ? v3 : v4));

	if ( slot == 0 )
		return copy_string("<reg0>");

	if ( slot >= frame_ids.size() )
		return copy_string(fmt("extra-slot %d", slot));

	return copy_string(fmt("%d (%s)", slot, frame_ids[slot]->Name()));
	}

void ZInst::Dump(const frame_map& frame_ids) const
	{
	printf("%s ", abstract_op_name(op));
	if ( t && 0 )
		printf("(%s) ", type_name(t->Tag()));

	int n = NumFrameSlots();

	auto id1 = VName(n, 1, frame_ids);
	auto id2 = VName(n, 2, frame_ids);
	auto id3 = VName(n, 3, frame_ids);
	auto id4 = VName(n, 4, frame_ids);

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

	case OP_VC:
		printf("%s, %s", id1, ConstDump());
		break;

	case OP_VVC:
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

	case OP_VV_FRAME:
		printf("%s, interpreter frame[%d]", id1, v2);
		break;

	case OP_VC_ID:
		printf("%s, ID %s", id1, obj_desc(c.any_val));
		break;

	case OP_VV_I2:
		printf("%s, %d", id1, v2);
		break;

	case OP_VVC_I2:
		printf("%s, %d, %s", id1, v2, ConstDump());
		break;

	case OP_VVV_I3:
		printf("%s, %s, %d", id1, id2, v3);
		break;

	case OP_VVV_I2_I3:
		printf("%s, %d, %d", id1, v2, v3);
		break;
	}

	printf("\n");

	delete id1;
	delete id2;
	delete id3;
	delete id4;
	}

const char* ZInst::ConstDump() const
	{
	auto v = c.ToVal(t);

	static ODesc d;

	d.Clear();
	v->Describe(&d);

	return d.Description();
	}

void ZInst::InitConst(const ConstExpr* ce)
	{
	auto v = ce->Value();
	auto ct = ce->Type().get();
	t = ct;

	bool error = false;
	c = ZAMValUnion(v, t, nullptr, ce, error);

	if ( error )
		reporter->InternalError("bad value compiling code");
	}
