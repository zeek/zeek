#ifndef pac_exception_h
#define pac_exception_h

#include <string>
using namespace std;

#include "pac_common.h"

class Exception
{
public:
	Exception(const Object* o, const char* msg = 0);

	const char* msg() const 	{ return msg_.c_str(); }
	void append(const char* s) 	{ msg_ += s; }

private:
	string msg_;
};

class ExceptionIDNotFound : public Exception
{
public:
	ExceptionIDNotFound(const ID* id);
	const ID* id() const { return id_; }

private:
	const ID* id_;
};

class ExceptionIDRedefinition : public Exception
{
public:
	ExceptionIDRedefinition(const ID* id);
	const ID* id() const { return id_; }

private:
	const ID* id_;
};

class ExceptionIDNotEvaluated : public Exception
{
public:
	ExceptionIDNotEvaluated(const ID* id);
	const ID* id() const { return id_; }

private:
	const ID* id_;
};

class ExceptionCyclicDependence : public Exception
{
public:
	ExceptionCyclicDependence(const ID* id);
	const ID* id() const { return id_; }

private:
	const ID* id_;
};

class ExceptionPaddingError : public Exception
{
public:
	ExceptionPaddingError(const Object* o, const char* msg);
};

class ExceptionIDNotField : public Exception
{
public:
	ExceptionIDNotField(const ID* id);
	const ID* id() const { return id_; }

private:
	const ID* id_;
};

class ExceptionMemberNotFound : public Exception
{
public:
	ExceptionMemberNotFound(const ID* type_id, const ID *member_id);

private:
	const ID *type_id_, *member_id_;
};

class ExceptionNonConstExpr : public Exception
{
public:
	ExceptionNonConstExpr(const Expr* expr);

private:
	const Expr *expr;
};

#endif /* pac_exception_h */
