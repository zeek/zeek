#include "pac_attr.h"
#include "pac_expr.h"

bool Attr::DoTraverse(DataDepVisitor *visitor)
	{
	if ( expr_ && ! expr_->Traverse(visitor) )
		return false;
	return true;
	}

bool Attr::RequiresAnalyzerContext() const
	{
	return (expr_ && expr_->RequiresAnalyzerContext());
	}

void Attr::init()
	{
	expr_ = 0;
	seqend_ = 0;
	}

Attr::Attr(AttrType type)
	: DataDepElement(DataDepElement::ATTR)
	{
	type_ = type;
	init();
	}

Attr::Attr(AttrType type, Expr *expr)
	: DataDepElement(DataDepElement::ATTR)
	{
	type_ = type;
	init();
	expr_ = expr;
	}

Attr::Attr(AttrType type, ExprList *exprlist)
	: DataDepElement(DataDepElement::ATTR)
	{
	type_ = type;
	init();
	expr_ = new Expr(exprlist);
	}

Attr::Attr(AttrType type, SeqEnd *seqend)
	: DataDepElement(DataDepElement::ATTR)
	{
	type_ = type;
	init();
	seqend_ = seqend;
	}

LetAttr::LetAttr(FieldList *letfields)
	: Attr(ATTR_LET)
	{
	letfields_ = letfields;
	}
