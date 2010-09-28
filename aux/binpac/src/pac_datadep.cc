#include "pac_datadep.h"
#include "pac_expr.h"
#include "pac_id.h"
#include "pac_type.h"

DataDepElement::DataDepElement(DDE_Type type) 
	: dde_type_(type), in_traversal(false)
	{ 
	}

bool DataDepElement::Traverse(DataDepVisitor *visitor)
	{
	// Avoid infinite loop
	if ( in_traversal )
		return true;
	if ( ! visitor->PreProcess(this) )
		return false;

	in_traversal = true;
	bool cont = DoTraverse(visitor);
	in_traversal = false;

	if ( ! cont )
		return false;
	if ( ! visitor->PostProcess(this) )
		return false;
	return true;
	}

Expr *DataDepElement::expr()
	{ 
	return static_cast<Expr *>(this); 
	}

Type *DataDepElement::type()
	{ 
	return static_cast<Type *>(this); 
	}

bool RequiresAnalyzerContext::PreProcess(DataDepElement *element)
	{
	switch ( element->dde_type() ) 
		{
		case DataDepElement::EXPR:
			ProcessExpr(element->expr());
			break;
		default:
			break;
		}

	// Continue traversal until we know the answer is 'yes'
	return ! requires_analyzer_context_;
	}

bool RequiresAnalyzerContext::PostProcess(DataDepElement *element)
	{
	return ! requires_analyzer_context_;
	}

void RequiresAnalyzerContext::ProcessExpr(Expr *expr)
	{
	if ( expr->expr_type() == Expr::EXPR_ID )
		{
		requires_analyzer_context_ = 
			(requires_analyzer_context_ || 
		       	 *expr->id() == *analyzer_context_id ||
		       	 *expr->id() == *context_macro_id);
		}
	}

bool RequiresAnalyzerContext::compute(DataDepElement *element)
	{
	RequiresAnalyzerContext visitor;
	element->Traverse(&visitor);
	return visitor.requires_analyzer_context_;
	}
