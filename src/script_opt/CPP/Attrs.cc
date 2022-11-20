// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

shared_ptr<CPP_InitInfo> CPPCompile::RegisterAttributes(const AttributesPtr& attrs)
	{
	if ( ! attrs )
		return nullptr;

	auto a = attrs.get();
	auto pa = processed_attrs.find(a);

	if ( pa != processed_attrs.end() )
		return pa->second;

	attributes.AddKey(attrs, pfs.HashAttrs(attrs));

	// The cast is just so we can make an IntrusivePtr.
	auto a_rep = const_cast<Attributes*>(attributes.GetRep(attrs));
	if ( a_rep != a )
		{
		AttributesPtr a_rep_ptr = {NewRef{}, a_rep};
		processed_attrs[a] = RegisterAttributes(a_rep_ptr);
		return processed_attrs[a];
		}

	for ( const auto& a : attrs->GetAttrs() )
		(void)RegisterAttr(a);

	shared_ptr<CPP_InitInfo> gi = make_shared<AttrsInfo>(this, attrs);
	attrs_info->AddInstance(gi);
	processed_attrs[a] = gi;

	return gi;
	}

shared_ptr<CPP_InitInfo> CPPCompile::RegisterAttr(const AttrPtr& attr)
	{
	auto a = attr.get();
	auto pa = processed_attr.find(a);

	if ( pa != processed_attr.end() )
		return pa->second;

	const auto& e = a->GetExpr();
	if ( e && ! IsSimpleInitExpr(e) )
		{
		auto h = p_hash(e);

		// Include the type in the hash, otherwise expressions
		// like "vector()" are ambiguous.
		h = merge_p_hashes(h, p_hash(e->GetType()));

		init_exprs.AddKey(e, h);
		}

	auto gi = make_shared<AttrInfo>(this, attr);
	attr_info->AddInstance(gi);
	processed_attr[a] = gi;

	return gi;
	}

void CPPCompile::BuildAttrs(const AttributesPtr& attrs, string& attr_tags, string& attr_vals)
	{
	if ( attrs )
		{
		for ( const auto& a : attrs->GetAttrs() )
			{
			if ( attr_tags.size() > 0 )
				{
				attr_tags += ", ";
				attr_vals += ", ";
				}

			attr_tags += Fmt(int(a->Tag()));

			const auto& e = a->GetExpr();

			if ( e )
				attr_vals += GenExpr(e, GEN_VAL_PTR, false);
			else
				attr_vals += "nullptr";
			}
		}

	attr_tags = string("{") + attr_tags + "}";
	attr_vals = string("{") + attr_vals + "}";
	}

const char* CPPCompile::AttrName(AttrTag t)
	{
	switch ( t )
		{
		case ATTR_OPTIONAL:
			return "ATTR_OPTIONAL";
		case ATTR_DEFAULT:
			return "ATTR_DEFAULT";
		case ATTR_REDEF:
			return "ATTR_REDEF";
		case ATTR_ADD_FUNC:
			return "ATTR_ADD_FUNC";
		case ATTR_DEL_FUNC:
			return "ATTR_DEL_FUNC";
		case ATTR_EXPIRE_FUNC:
			return "ATTR_EXPIRE_FUNC";
		case ATTR_EXPIRE_READ:
			return "ATTR_EXPIRE_READ";
		case ATTR_EXPIRE_WRITE:
			return "ATTR_EXPIRE_WRITE";
		case ATTR_EXPIRE_CREATE:
			return "ATTR_EXPIRE_CREATE";
		case ATTR_RAW_OUTPUT:
			return "ATTR_RAW_OUTPUT";
		case ATTR_PRIORITY:
			return "ATTR_PRIORITY";
		case ATTR_GROUP:
			return "ATTR_GROUP";
		case ATTR_LOG:
			return "ATTR_LOG";
		case ATTR_ERROR_HANDLER:
			return "ATTR_ERROR_HANDLER";
		case ATTR_TYPE_COLUMN:
			return "ATTR_TYPE_COLUMN";
		case ATTR_TRACKED:
			return "ATTR_TRACKED";
		case ATTR_ON_CHANGE:
			return "ATTR_ON_CHANGE";
		case ATTR_BROKER_STORE:
			return "ATTR_BROKER_STORE";
		case ATTR_BROKER_STORE_ALLOW_COMPLEX:
			return "ATTR_BROKER_STORE_ALLOW_COMPLEX";
		case ATTR_BACKEND:
			return "ATTR_BACKEND";
		case ATTR_DEPRECATED:
			return "ATTR_DEPRECATED";
		case ATTR_IS_ASSIGNED:
			return "ATTR_IS_ASSIGNED";
		case ATTR_IS_USED:
			return "ATTR_IS_USED";

		default:
			return "<busted>";
		}
	}

	} // zeek::detail
