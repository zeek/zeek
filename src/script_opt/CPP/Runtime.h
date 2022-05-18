// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/Expr.h"
#include "zeek/File.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/IPAddr.h"
#include "zeek/OpaqueVal.h"
#include "zeek/RE.h"
#include "zeek/RunState.h"
#include "zeek/Scope.h"
#include "zeek/Trigger.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/CPP/Func.h"
#include "zeek/script_opt/CPP/RuntimeInitSupport.h"
#include "zeek/script_opt/CPP/RuntimeInits.h"
#include "zeek/script_opt/CPP/RuntimeOps.h"
#include "zeek/script_opt/CPP/RuntimeVec.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek::detail
	{

using BoolValPtr = IntrusivePtr<zeek::BoolVal>;
using IntValPtr = IntrusivePtr<zeek::IntVal>;
using CountValPtr = IntrusivePtr<zeek::CountVal>;
using DoubleValPtr = IntrusivePtr<zeek::DoubleVal>;
using StringValPtr = IntrusivePtr<zeek::StringVal>;
using TimeValPtr = IntrusivePtr<zeek::TimeVal>;
using IntervalValPtr = IntrusivePtr<zeek::IntervalVal>;
using PatternValPtr = IntrusivePtr<zeek::PatternVal>;
using FuncValPtr = IntrusivePtr<zeek::FuncVal>;
using FileValPtr = IntrusivePtr<zeek::FileVal>;
using SubNetValPtr = IntrusivePtr<zeek::SubNetVal>;

	}
