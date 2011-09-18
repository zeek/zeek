// Structures and methods for implementing watches in the Bro debugger.

#ifndef dbg_display_h
#define dbg_display_h

#include "Debug.h"

// Automatic displays: display these at each stoppage.
class DbgDisplay {
public:
	DbgDisplay(Expr* expr_to_display);

	bool IsEnabled()	{ return enabled; }
	bool SetEnable(bool do_enable)
		{
		bool old_value = enabled;
		enabled = do_enable;
		return old_value;
		}

	const Expr* Expression() const	{ return expression; }

protected:
	bool enabled;
	Expr* expression;
	};

#endif
