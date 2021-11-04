// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

void CPPCompile::RegisterAttributes(const AttributesPtr& attrs)
	{
	if ( ! attrs || attributes.HasKey(attrs) )
		return;

	attributes.AddKey(attrs);
	AddInit(attrs);

	auto a_rep = attributes.GetRep(attrs);
	if ( a_rep != attrs.get() )
		{
		NoteInitDependency(attrs.get(), a_rep);
		return;
		}

	for ( const auto& a : attrs->GetAttrs() )
		{
		const auto& e = a->GetExpr();
		if ( e )
			{
			if ( IsSimpleInitExpr(e) )
				{
				// Make sure any dependencies it has get noted.
				(void)GenExpr(e, GEN_VAL_PTR);
				continue;
				}

			init_exprs.AddKey(e);
			AddInit(e);
			NoteInitDependency(attrs, e);

			auto e_rep = init_exprs.GetRep(e);
			if ( e_rep != e.get() )
				NoteInitDependency(e.get(), e_rep);
			}
		}
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

void CPPCompile::GenAttrs(const AttributesPtr& attrs)
	{
	NL();

	Emit("AttributesPtr %s", AttrsName(attrs));

	StartBlock();

	const auto& avec = attrs->GetAttrs();
	Emit("auto attrs = std::vector<AttrPtr>();");

	AddInit(attrs);

	for ( const auto& attr : avec )
		{
		const auto& e = attr->GetExpr();

		if ( ! e )
			{
			Emit("attrs.emplace_back(make_intrusive<Attr>(%s));", AttrName(attr));
			continue;
			}

		NoteInitDependency(attrs, e);
		AddInit(e);

		string e_arg;
		if ( IsSimpleInitExpr(e) )
			e_arg = GenAttrExpr(e);
		else
			e_arg = InitExprName(e);

		Emit("attrs.emplace_back(make_intrusive<Attr>(%s, %s));", AttrName(attr), e_arg);
		}

	Emit("return make_intrusive<Attributes>(attrs, nullptr, true, false);");

	EndBlock();
	}

string CPPCompile::GenAttrExpr(const ExprPtr& e)
	{
	switch ( e->Tag() )
		{
		case EXPR_CONST:
			return string("make_intrusive<ConstExpr>(") + GenExpr(e, GEN_VAL_PTR) + ")";

		case EXPR_NAME:
			NoteInitDependency(e, e->AsNameExpr()->IdPtr());
			return string("make_intrusive<NameExpr>(") + globals[e->AsNameExpr()->Id()->Name()] +
			       ")";

		case EXPR_RECORD_COERCE:
			NoteInitDependency(e, TypeRep(e->GetType()));
			return string("make_intrusive<RecordCoerceExpr>(make_intrusive<RecordConstructorExpr>("
			              "make_intrusive<ListExpr>()), cast_intrusive<RecordType>(") +
			       GenTypeName(e->GetType()) + "))";

		default:
			reporter->InternalError("bad expr tag in CPPCompile::GenAttrs");
			return "###";
		}
	}

string CPPCompile::AttrsName(const AttributesPtr& a)
	{
	return attributes.KeyName(a) + "()";
	}

const char* CPPCompile::AttrName(const AttrPtr& attr)
	{
	switch ( attr->Tag() )
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
