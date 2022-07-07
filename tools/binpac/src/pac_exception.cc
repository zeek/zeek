#include "pac_exception.h"

#include "pac_expr.h"
#include "pac_id.h"
#include "pac_utils.h"

Exception::Exception(const Object* o, string msg)
	{
	if ( o )
		{
		msg_ = o->Location();
		msg_ += ": error : ";
		}

	msg_ += msg;

	if ( FLAGS_pac_debug )
		{
		DEBUG_MSG("Exception: %s\n", msg_.c_str());
		abort();
		}
	}

ExceptionIDNotFound::ExceptionIDNotFound(const ID* id) : Exception(id), id_(id)
	{
	append(strfmt("`%s' undeclared", id_->Name()));
	}

ExceptionIDRedefinition::ExceptionIDRedefinition(const ID* id) : Exception(id), id_(id)
	{
	append(strfmt("`%s' redefined", id_->Name()));
	}

ExceptionIDNotEvaluated::ExceptionIDNotEvaluated(const ID* id) : Exception(id), id_(id)
	{
	append(strfmt("ID `%s' not evaluated before used", id->Name()));
	}

ExceptionIDNotField::ExceptionIDNotField(const ID* id) : Exception(id), id_(id)
	{
	append(strfmt("ID `%s' is not a field", id_->Name()));
	}

ExceptionMemberNotFound::ExceptionMemberNotFound(const ID* type_id, const ID* member_id)
	: Exception(member_id), type_id_(type_id), member_id_(member_id)
	{
	append(strfmt("type %s does not have member `%s'", type_id_->Name(), member_id_->Name()));
	}

ExceptionCyclicDependence::ExceptionCyclicDependence(const ID* id) : Exception(id), id_(id)
	{
	append(strfmt("cyclic dependence through `%s'", id_->Name()));
	}

ExceptionPaddingError::ExceptionPaddingError(const Object* o, string msg) : Exception(o)
	{
	append(msg.c_str());
	}

ExceptionNonConstExpr::ExceptionNonConstExpr(const Expr* expr) : Exception(expr), expr(expr)
	{
	append(strfmt("Expression `%s' is not constant", expr->orig()));
	}

ExceptionInvalidCaseSizeExpr::ExceptionInvalidCaseSizeExpr(const Expr* expr)
	: Exception(expr), expr(expr)
	{
	append(strfmt("Expression `%s' is greater than the 32-bit limit for use as a case index",
	              expr->orig()));
	}

ExceptionInvalidCaseLimitExpr::ExceptionInvalidCaseLimitExpr(const Expr* expr)
	: Exception(expr), expr(expr)
	{
	append(strfmt("Expression `%s' as a case index is outside the numeric limit of the type used "
	              "for the switch expression",
	              expr->orig()));
	}
