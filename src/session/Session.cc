// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/session/Session.h"

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/session/Manager.h"

namespace zeek::session
	{
namespace detail
	{

void Timer::Init(Session* arg_session, timer_func arg_timer, bool arg_do_expire)
	{
	session = arg_session;
	timer = arg_timer;
	do_expire = arg_do_expire;
	Ref(session);
	}

Timer::~Timer()
	{
	if ( session->RefCnt() < 1 )
		reporter->InternalError("reference count inconsistency in session~Timer");

	session->RemoveTimer(this);
	Unref(session);
	}

void Timer::Dispatch(double t, bool is_expire)
	{
	if ( is_expire && ! do_expire )
		return;

	// Remove ourselves from the session's set of timers so
	// it doesn't try to cancel us.
	session->RemoveTimer(this);

	(session->*timer)(t);

	if ( session->RefCnt() < 1 )
		reporter->InternalError("reference count inconsistency in session::Timer::Dispatch");
	}

	} // namespace detail

Session::Session(double t, EventHandlerPtr timeout_event, EventHandlerPtr status_update_event,
                 double status_update_interval)
	: start_time(t), last_time(t), session_timeout_event(timeout_event),
	  session_status_update_event(status_update_event),
	  session_status_update_interval(status_update_interval)
	{
	in_session_table = true;
	record_contents = record_packets = 1;
	record_current_packet = record_current_content = 0;
	is_active = 1;
	timers_canceled = 0;
	inactivity_timeout = 0;
	installed_status_timer = 0;
	}

void Session::Event(EventHandlerPtr f, analyzer::Analyzer* analyzer, const char* name)
	{
	if ( ! f )
		return;

	if ( name )
		EnqueueEvent(f, analyzer, make_intrusive<StringVal>(name), GetVal());
	else
		EnqueueEvent(f, analyzer, GetVal());
	}

void Session::EnqueueEvent(EventHandlerPtr f, analyzer::Analyzer* a, Args args)
	{
	// "this" is passed as a cookie for the event
	event_mgr.Enqueue(f, std::move(args), util::detail::SOURCE_LOCAL, a ? a->GetID() : 0, this);
	}

void Session::Describe(ODesc* d) const
	{
	d->Add(start_time);
	d->Add("(");
	d->Add(last_time);
	d->AddSP(")");
	}

void Session::SetLifetime(double lifetime)
	{
	ADD_TIMER(&Session::DeleteTimer, run_state::network_time + lifetime, 0,
	          zeek::detail::TIMER_CONN_DELETE);
	}

void Session::SetInactivityTimeout(double timeout)
	{
	if ( timeout == inactivity_timeout )
		return;

	// First cancel and remove any existing inactivity timer.
	for ( const auto& timer : timers )
		if ( timer->Type() == zeek::detail::TIMER_CONN_INACTIVITY )
			{
			zeek::detail::timer_mgr->Cancel(timer);
			break;
			}

	if ( timeout )
		ADD_TIMER(&Session::InactivityTimer, last_time + timeout, 0,
		          zeek::detail::TIMER_CONN_INACTIVITY);

	inactivity_timeout = timeout;
	}

void Session::EnableStatusUpdateTimer()
	{
	if ( installed_status_timer )
		return;

	if ( session_status_update_event && session_status_update_interval )
		{
		ADD_TIMER(&Session::StatusUpdateTimer,
		          run_state::network_time + session_status_update_interval, 0,
		          zeek::detail::TIMER_CONN_STATUS_UPDATE);
		installed_status_timer = 1;
		}
	}

void Session::CancelTimers()
	{
	// We are going to cancel our timers which, in turn, may cause them to
	// call RemoveTimer(), which would then modify the list we're just
	// traversing. Thus, we first make a copy of the list which we then
	// iterate through.
	TimerPList tmp(timers.length());
	std::copy(timers.begin(), timers.end(), std::back_inserter(tmp));

	for ( const auto& timer : tmp )
		zeek::detail::timer_mgr->Cancel(timer);

	timers_canceled = 1;
	timers.clear();
	}

void Session::DeleteTimer(double /* t */)
	{
	if ( is_active )
		Event(session_timeout_event, nullptr);

	session_mgr->Remove(this);
	}

void Session::AddTimer(timer_func timer, double t, bool do_expire, zeek::detail::TimerType type)
	{
	if ( timers_canceled )
		return;

	// If the key is cleared, the session isn't stored in the session table
	// anymore and will soon be deleted. We're not installed new timers
	// anymore then.
	if ( ! IsInSessionTable() )
		return;

	zeek::detail::Timer* conn_timer = new detail::Timer(this, timer, t, do_expire, type);
	zeek::detail::timer_mgr->Add(conn_timer);
	timers.push_back(conn_timer);
	}

void Session::RemoveTimer(zeek::detail::Timer* t)
	{
	timers.remove(t);
	}

void Session::InactivityTimer(double t)
	{
	if ( last_time + inactivity_timeout <= t )
		{
		Event(session_timeout_event, nullptr);
		session_mgr->Remove(this);
		++zeek::detail::killed_by_inactivity;
		}
	else
		ADD_TIMER(&Session::InactivityTimer, last_time + inactivity_timeout, 0,
		          zeek::detail::TIMER_CONN_INACTIVITY);
	}

void Session::StatusUpdateTimer(double t)
	{
	EnqueueEvent(session_status_update_event, nullptr, GetVal());
	ADD_TIMER(&Session::StatusUpdateTimer, run_state::network_time + session_status_update_interval,
	          0, zeek::detail::TIMER_CONN_STATUS_UPDATE);
	}

void Session::RemoveConnectionTimer(double t)
	{
	RemovalEvent();
	session_mgr->Remove(this);
	}

AnalyzerConfirmationState Session::AnalyzerState(const zeek::Tag& tag) const
	{
	auto it = analyzer_confirmations.find(tag);
	if ( it == analyzer_confirmations.end() )
		return AnalyzerConfirmationState::UNKNOWN;

	return it->second;
	}

void Session::SetAnalyzerState(const zeek::Tag& tag, AnalyzerConfirmationState value)
	{
	analyzer_confirmations.insert_or_assign(tag, value);
	}

	} // namespace zeek::session
