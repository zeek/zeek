#ifndef pac_primitive_h
#define pac_primitive_h

#include "pac_common.h"

class PacPrimitive
{
public:
	enum PrimitiveType { VAL, SET, TYPE, CONST_DEF };

	explicit PacPrimitive(PrimitiveType type) : type_(type) {}
	virtual ~PacPrimitive() {}

	PrimitiveType type() const	{ return type(); }

	virtual string ToCode(Env *env) = 0;

private:
	PrimitiveType type_;
};

class PPVal : public PacPrimitive
{
public:
	PPVal(Expr *expr) : PacPrimitive(VAL), expr_(expr) {}
	Expr *expr() const	{ return expr_; }

	string ToCode(Env *env);

private:
	Expr *expr_;
};

class PPSet : public PacPrimitive
{
public:
	PPSet(Expr *expr) : PacPrimitive(SET), expr_(expr) {}
	Expr *expr() const	{ return expr_; }

	string ToCode(Env *env);

private:
	Expr *expr_;
};

class PPType : public PacPrimitive
{
public:
	PPType(Expr *expr) : PacPrimitive(TYPE), expr_(expr) {}
	Expr *expr() const	{ return expr_; }

	string ToCode(Env *env);

private:
	Expr *expr_;
};

class PPConstDef : public PacPrimitive
{
public:
	PPConstDef(const ID *id, Expr *expr) 
		: PacPrimitive(CONST_DEF), 
		  id_(id),
		  expr_(expr) {}
	const ID *id() const	{ return id_; }
	Expr *expr() const	{ return expr_; }

	string ToCode(Env *env);

private:
	const ID *id_;
	Expr *expr_;
};

#endif  // pac_primitive_h
