#ifndef pac_attr_h
#define pac_attr_h

#include "pac_common.h"
#include "pac_datadep.h"

enum AttrType { 
	ATTR_BYTEORDER, 
	ATTR_CHECK, 
	ATTR_CHUNKED,
	ATTR_EXPORTSOURCEDATA,
	ATTR_IF,
	ATTR_LENGTH, 
	ATTR_LET,
	ATTR_LINEBREAKER,
	ATTR_MULTILINE,
	ATTR_ONELINE,
	ATTR_REFCOUNT,
	ATTR_REQUIRES,
	ATTR_RESTOFDATA, 
	ATTR_RESTOFFLOW, 
	ATTR_TRANSIENT,
	ATTR_UNTIL,
};

class Attr : public Object, public DataDepElement
{
public:
	Attr(AttrType type);
	Attr(AttrType type, Expr *expr);
	Attr(AttrType type, ExprList *exprlist);
	Attr(AttrType type, SeqEnd *seqend);

	AttrType type() const 		{ return type_; }
	Expr *expr() const		{ return expr_; }
	SeqEnd *seqend() const		{ return seqend_; }

	bool RequiresAnalyzerContext() const;

protected:
	bool DoTraverse(DataDepVisitor *visitor);

protected:
	void init();

	AttrType type_;
	Expr *expr_;
	SeqEnd *seqend_;
};

class LetAttr : public Attr
{
public:
	LetAttr(FieldList *letfields);
	FieldList *letfields() const	{ return letfields_; }

private:
	FieldList *letfields_;
};

#endif  // pac_attr_h
