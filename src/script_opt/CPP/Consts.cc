// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/File.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/Compile.h"

using namespace std;

namespace zeek::detail
	{

shared_ptr<CPP_InitInfo> CPPCompile::RegisterConstant(const ValPtr& vp, int& consts_offset)
	{
	// Make sure the value pointer, which might be transient
	// in construction, sticks around so we can track its
	// value.
	cv_indices.push_back(vp);

	auto v = vp.get();
	auto cv = const_vals.find(v);

	if ( cv != const_vals.end() )
		{
		// Already did this one.
		consts_offset = const_offsets[v];
		return cv->second;
		}

	// Formulate a key that's unique per distinct constant.

	const auto& t = v->GetType();
	string c_desc;

	if ( t->Tag() == TYPE_STRING )
		{
		// We can't rely on these to render with consistent
		// escaping, sigh.  Just use the raw string.
		auto s = v->AsString();
		auto b = (const char*)(s->Bytes());
		c_desc = string(b, s->Len()) + "string";
		}
	else
		{
		ODesc d;
		v->Describe(&d);

		// Don't confuse constants of different types that happen to
		// render the same.
		t->Describe(&d);

		// Likewise, tables that have attributes.
		if ( t->Tag() == TYPE_TABLE )
			{
			const auto& attrs = v->AsTableVal()->GetAttrs();
			if ( attrs )
				attrs->Describe(&d);
			else
				d.Add("<no-attrs>");
			}

		c_desc = d.Description();
		}

	auto c = constants.find(c_desc);
	if ( c != constants.end() )
		{
		const_vals[v] = c->second;
		consts_offset = const_offsets[v] = constants_offsets[c_desc];
		return c->second;
		}

	auto tag = t->Tag();
	auto const_name = const_info[tag]->NextName();
	shared_ptr<CPP_InitInfo> gi;

	switch ( tag )
		{
		case TYPE_BOOL:
			gi = make_shared<BasicConstInfo>(vp->AsBool() ? "true" : "false");
			break;

		case TYPE_INT:
			gi = make_shared<BasicConstInfo>(to_string(vp->AsInt()));
			break;

		case TYPE_COUNT:
			gi = make_shared<BasicConstInfo>(to_string(vp->AsCount()) + "ULL");
			break;

		case TYPE_DOUBLE:
			gi = make_shared<BasicConstInfo>(to_string(vp->AsDouble()));
			break;

		case TYPE_TIME:
			gi = make_shared<BasicConstInfo>(to_string(vp->AsDouble()));
			break;

		case TYPE_INTERVAL:
			gi = make_shared<BasicConstInfo>(to_string(vp->AsDouble()));
			break;

		case TYPE_ADDR:
			gi = make_shared<DescConstInfo>(this, vp);
			break;

		case TYPE_SUBNET:
			gi = make_shared<DescConstInfo>(this, vp);
			break;

		case TYPE_ENUM:
			gi = make_shared<EnumConstInfo>(this, vp);
			break;

		case TYPE_STRING:
			gi = make_shared<StringConstInfo>(this, vp);
			break;

		case TYPE_PATTERN:
			gi = make_shared<PatternConstInfo>(this, vp);
			break;

		case TYPE_PORT:
			gi = make_shared<PortConstInfo>(vp);
			break;

		case TYPE_LIST:
			gi = make_shared<ListConstInfo>(this, vp);
			break;

		case TYPE_VECTOR:
			gi = make_shared<VectorConstInfo>(this, vp);
			break;

		case TYPE_RECORD:
			gi = make_shared<RecordConstInfo>(this, vp);
			break;

		case TYPE_TABLE:
			gi = make_shared<TableConstInfo>(this, vp);
			break;

		case TYPE_FILE:
			gi = make_shared<FileConstInfo>(this, vp);
			break;

		case TYPE_FUNC:
			gi = make_shared<FuncConstInfo>(this, vp);
			break;

		default:
			reporter->InternalError("bad constant type in CPPCompile::AddConstant");
			break;
		}

	const_info[tag]->AddInstance(gi);
	const_vals[v] = constants[c_desc] = gi;

	consts_offset = const_offsets[v] = constants_offsets[c_desc] = consts.size();
	consts.emplace_back(pair(tag, gi->Offset()));

	return gi;
	}

	} // zeek::detail
