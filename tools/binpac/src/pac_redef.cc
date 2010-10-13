#include "pac_analyzer.h"
#include "pac_case.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_func.h"
#include "pac_record.h"
#include "pac_redef.h"
#include "pac_type.h"
#include "pac_typedecl.h"

namespace {

Decl *find_decl(const ID *id)
	{
	Decl *decl = Decl::LookUpDecl(id);
	if ( ! decl )
		{
		throw Exception(id, 
		                fmt("cannot find declaration for %s", 
		                    id->Name()));
		}

	return decl;
	}

}

Decl *ProcessTypeRedef(const ID *id, FieldList *fieldlist)
	{
	Decl *decl = find_decl(id);

	if ( decl->decl_type() != Decl::TYPE )
		{
		throw Exception(id, 
		                fmt("not a type declaration: %s", 
		                    id->Name()));
		}

	TypeDecl *type_decl = static_cast<TypeDecl *>(decl);
	ASSERT(type_decl);
	Type *type = type_decl->type();

	foreach(i, FieldList, fieldlist)
		{
		Field *f = *i;

		// One cannot change data layout in 'redef'.
		// Only 'let' or 'action' can be added
		if ( f->tof() == LET_FIELD ||
		     f->tof() == WITHINPUT_FIELD )
			{
			type->AddField(f);
			}
		else if ( f->tof() == RECORD_FIELD || 
		          f->tof() == PADDING_FIELD )
			{
			throw Exception(f, 
				"cannot change data layout in redef");
			}
		else if ( f->tof() == CASE_FIELD )
			{
			throw Exception(f, 
				"use 'redef case' adding cases");
			}
		}

	return decl;
	}

Decl *ProcessCaseTypeRedef(const ID *id, CaseFieldList *casefieldlist)
	{
	Decl *decl = find_decl(id);

	if ( decl->decl_type() != Decl::TYPE )
		{
		throw Exception(id, 
		                fmt("not a type declaration: %s", 
		                    id->Name()));
		}

	TypeDecl *type_decl = static_cast<TypeDecl *>(decl);
	ASSERT(type_decl);

	Type *type = type_decl->type();
	if ( type->tot() != Type::CASE )
		{
		throw Exception(id, 
		                fmt("not a case type: %s", 
		                    id->Name()));
		}

	CaseType *casetype = static_cast<CaseType*>(type);
	ASSERT(casetype);

	foreach(i, CaseFieldList, casefieldlist)
		{
		CaseField *f = *i;
		casetype->AddCaseField(f);
		}

	return decl;
	}

Decl *ProcessCaseExprRedef(const ID *id, CaseExprList *caseexprlist)
	{
	Decl *decl = find_decl(id);

	if ( decl->decl_type() != Decl::FUNC )
		{
		throw Exception(id, 
		                fmt("not a function declaration: %s", 
		                    id->Name()));
		}

	FuncDecl *func_decl = static_cast<FuncDecl *>(decl);
	ASSERT(func_decl);

	Expr *expr = func_decl->function()->expr();
	if ( ! expr ||expr->expr_type() != Expr::EXPR_CASE )
		{
		throw Exception(id, 
		                fmt("function not defined by a case expression: %s", 
		                    id->Name()));
		}

	foreach(i, CaseExprList, caseexprlist)
		{
		CaseExpr *e = *i;
		expr->AddCaseExpr(e);
		}
	
	return decl;
	}

Decl *ProcessAnalyzerRedef(const ID *id, 
		Decl::DeclType decl_type, 
		AnalyzerElementList *elements)
	{
	Decl *decl = find_decl(id);

	if ( decl->decl_type() != decl_type )
		{
		throw Exception(id, 
		                fmt("not a connection/flow declaration: %s", 
		                    id->Name()));
		}

	AnalyzerDecl *analyzer_decl = static_cast<AnalyzerDecl *>(decl);
	ASSERT(analyzer_decl);

	analyzer_decl->AddElements(elements);

	return decl;
	}

Decl *ProcessTypeAttrRedef(const ID *id, AttrList *attrlist)
	{
	Decl *decl = find_decl(id);

	if ( decl->decl_type() != Decl::TYPE )
		{
		throw Exception(id, 
		                fmt("not a type declaration: %s", 
		                    id->Name()));
		}

	TypeDecl *type_decl = static_cast<TypeDecl *>(decl);
	ASSERT(type_decl);

	type_decl->AddAttrs(attrlist);

	return decl;
	}
