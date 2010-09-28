#include "pac_exception.h"
#include "pac_enum.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_output.h"
#include "pac_typedecl.h"

Enum::Enum(ID* id, Expr* expr)
	: id_(id), expr_(expr)
	{
	}

Enum::~Enum()
	{
	delete id_;
	delete expr_;
	}

void Enum::GenHeader(Output* out_h, int *pval)
	{
	ASSERT(pval);
	if ( expr_ )
		{
		if ( ! expr_->ConstFold(global_env(), pval) )
			throw ExceptionNonConstExpr(expr_);
		out_h->println("%s = %d,", id_->Name(), *pval);
		}
	else
		out_h->println("%s,", id_->Name());
	global_env()->AddConstID(id_, *pval);
	}

EnumDecl::EnumDecl(ID *id, EnumList *enumlist)
	: Decl(id, ENUM), enumlist_(enumlist) 
	{
	ID *type_id = id->clone();
	datatype_ = new ExternType(type_id, ExternType::NUMBER);
	extern_typedecl_ = new TypeDecl(type_id, 0, datatype_);
	}

EnumDecl::~EnumDecl()
	{ 
	delete_list(EnumList, enumlist_); 
	delete extern_typedecl_;
	}

void EnumDecl::Prepare() 
	{ 
	// Do nothing 
	}

void EnumDecl::GenForwardDeclaration(Output *out_h)
	{ 
	out_h->println("enum %s {", id_->Name());
	out_h->inc_indent();
	int c = 0;
	foreach(i, EnumList, enumlist_)
		{
		(*i)->GenHeader(out_h, &c);
		++c;
		}
	out_h->dec_indent();
	out_h->println("};");
	}

void EnumDecl::GenCode(Output* out_h, Output* /* out_cc */)
	{
	// Do nothing 
	}

