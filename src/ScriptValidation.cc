#include "zeek/ScriptValidation.h"

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"

namespace zeek::detail
	{

// Validate context of break and next statement usage.
class BreakNextScriptValidation : public TraversalCallback
	{
public:
	TraversalCode PreStmt(const Stmt* stmt)
		{
		if ( ! StmtIsRelevant(stmt) )
			return TC_CONTINUE;

		stmt_depths[stmt->Tag()] += 1;

		if ( stmt->Tag() == STMT_BREAK && ! BreakStmtIsValid() )
			{
			zeek::reporter->PushLocation(stmt->GetLocationInfo());
			zeek::reporter->Error("break statement used outside of for, while or "
			                      "switch statement and not within a hook");
			zeek::reporter->PopLocation();
			}

		if ( stmt->Tag() == STMT_NEXT && ! NextStmtIsValid() )
			{
			zeek::reporter->PushLocation(stmt->GetLocationInfo());
			zeek::reporter->Error("next statement used outside of for or while statement");
			zeek::reporter->PopLocation();
			}

		return TC_CONTINUE;
		}

	TraversalCode PostStmt(const Stmt* stmt)
		{
		if ( ! StmtIsRelevant(stmt) )
			return TC_CONTINUE;

		--stmt_depths[stmt->Tag()];

		assert(stmt_depths[stmt->Tag()] >= 0);

		return TC_CONTINUE;
		}

	TraversalCode PreFunction(const zeek::Func* func)
		{
		if ( func->Flavor() == zeek::FUNC_FLAVOR_HOOK )
			++hook_depth;

		assert(hook_depth <= 1);

		return TC_CONTINUE;
		}

	TraversalCode PostFunction(const zeek::Func* func)
		{
		if ( func->Flavor() == zeek::FUNC_FLAVOR_HOOK )
			--hook_depth;

		assert(hook_depth >= 0);

		return TC_CONTINUE;
		}

private:
	bool StmtIsRelevant(const Stmt* stmt)
		{
		StmtTag tag = stmt->Tag();
		return tag == STMT_FOR || tag == STMT_WHILE || tag == STMT_SWITCH || tag == STMT_BREAK ||
		       tag == STMT_NEXT;
		}

	bool BreakStmtIsValid()
		{
		return hook_depth > 0 || stmt_depths[STMT_FOR] > 0 || stmt_depths[STMT_WHILE] > 0 ||
		       stmt_depths[STMT_SWITCH] > 0;
		}

	bool NextStmtIsValid() { return stmt_depths[STMT_FOR] > 0 || stmt_depths[STMT_WHILE] > 0; }

	std::unordered_map<StmtTag, int> stmt_depths;
	int hook_depth = 0;
	};

void script_validation()
	{
	zeek::detail::BreakNextScriptValidation bn_cb;
	zeek::detail::traverse_all(&bn_cb);
	}
	}
