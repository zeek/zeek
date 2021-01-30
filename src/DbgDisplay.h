// Structures and methods for implementing watches in the Bro debugger.

#pragma once

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

namespace zeek::detail {

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

} // namespace zeek::detail
