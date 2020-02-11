// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "Analyzer.h"
#include "Manager.h"
#include "binpac.h"

#include "analyzer/protocol/pia/PIA.h"
#include "../Event.h"

namespace analyzer {

class AnalyzerTimer : public Timer {
public:
	AnalyzerTimer(Analyzer* arg_analyzer, analyzer_timer_func arg_timer,
			double arg_t, int arg_do_expire, TimerType arg_type);

	virtual ~AnalyzerTimer();

	void Dispatch(double t, int is_expire);

protected:
	AnalyzerTimer() : analyzer(), timer(), do_expire()	{}

	void Init(Analyzer* analyzer, analyzer_timer_func timer, int do_expire);

	Analyzer* analyzer;
	analyzer_timer_func timer;
	int do_expire;
};

}

using namespace analyzer;

AnalyzerTimer::AnalyzerTimer(Analyzer* arg_analyzer, analyzer_timer_func arg_timer,
			     double arg_t, int arg_do_expire, TimerType arg_type)
	: Timer(arg_t, arg_type)
	{
	Init(arg_analyzer, arg_timer, arg_do_expire);
	}

AnalyzerTimer::~AnalyzerTimer()
	{
	analyzer->RemoveTimer(this);
	Unref(analyzer->Conn());
	}

void AnalyzerTimer::Dispatch(double t, int is_expire)
	{
	if ( is_expire && ! do_expire )
		return;

	// Remove ourselves from the connection's set of timers so
	// it doesn't try to cancel us.
	analyzer->RemoveTimer(this);

	(analyzer->*timer)(t);
	}

void AnalyzerTimer::Init(Analyzer* arg_analyzer, analyzer_timer_func arg_timer,
				int arg_do_expire)
	{
	analyzer = arg_analyzer;
	timer = arg_timer;
	do_expire = arg_do_expire;

	// We need to Ref the connection as the analyzer doesn't do it and
	// we need to have it around until we expire.
	Ref(analyzer->Conn());
	}

analyzer::ID Analyzer::id_counter = 0;

const char* Analyzer::GetAnalyzerName() const
	{
	assert(tag);
	return analyzer_mgr->GetComponentName(tag).c_str();
	}

void Analyzer::SetAnalyzerTag(const Tag& arg_tag)
	{
	assert(! tag || tag == arg_tag);
	tag = arg_tag;
	}

bool Analyzer::IsAnalyzer(const char* name)
	{
	assert(tag);
	return strcmp(analyzer_mgr->GetComponentName(tag).c_str(), name) == 0;
	}

Analyzer::Analyzer(const char* name, Connection* conn)
	{
	Tag tag = analyzer_mgr->GetComponentTag(name);

	if ( ! tag )
		reporter->InternalError("unknown analyzer name %s; mismatch with tag analyzer::Component?", name);

	CtorInit(tag, conn);
	}

Analyzer::Analyzer(const Tag& tag, Connection* conn)
	{
	CtorInit(tag, conn);
	}

Analyzer::Analyzer(Connection* conn)
	{
	CtorInit(Tag(), conn);
	}

void Analyzer::CtorInit(const Tag& arg_tag, Connection* arg_conn)
	{
	// Don't Ref conn here to avoid circular ref'ing. It can't be deleted
	// before us.
	conn = arg_conn;
	tag = arg_tag;
	id = ++id_counter;
	protocol_confirmed = false;
	timers_canceled = false;
	skip = false;
	finished = false;
	removing = false;
	parent = 0;
	orig_supporters = 0;
	resp_supporters = 0;
	signature = 0;
	output_handler = 0;
	}

Analyzer::~Analyzer()
	{
	assert(finished);

	LOOP_OVER_CHILDREN(i)
		delete *i;

	SupportAnalyzer* next = 0;

	for ( SupportAnalyzer* a = orig_supporters; a; a = next )
		{
		next = a->sibling;
		delete a;
		}

	for ( SupportAnalyzer* a = resp_supporters; a; a = next)
		{
		next = a->sibling;
		delete a;
		}

	delete output_handler;
	}

void Analyzer::Init()
	{
	}

void Analyzer::InitChildren()
	{
	AppendNewChildren();

	LOOP_OVER_CHILDREN(i)
		{
		(*i)->Init();
		(*i)->InitChildren();
		}
	}

void Analyzer::Done()
	{
	assert(!finished);

	if ( ! skip )
		{
		EndOfData(true);
		EndOfData(false);
		}

	CancelTimers();

	AppendNewChildren();

	LOOP_OVER_CHILDREN(i)
		if ( ! (*i)->finished )
			(*i)->Done();

	for ( SupportAnalyzer* a = orig_supporters; a; a = a->sibling )
		if ( ! a->finished )
			a->Done();

	for ( SupportAnalyzer* a = resp_supporters; a; a = a->sibling )
		if ( ! a->finished )
			a->Done();

	finished = true;
	}

void Analyzer::NextPacket(int len, const u_char* data, bool is_orig, uint64_t seq,
				const IP_Hdr* ip, int caplen)
	{
	if ( skip )
		return;

	SupportAnalyzer* next_sibling = FirstSupportAnalyzer(is_orig);

	if ( next_sibling )
		next_sibling->NextPacket(len, data, is_orig, seq, ip, caplen);

	else
		{
		try
			{
			DeliverPacket(len, data, is_orig, seq, ip, caplen);
			}
		catch ( binpac::Exception const &e )
			{
			ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
			}
		}
	}

void Analyzer::NextStream(int len, const u_char* data, bool is_orig)
	{
	if ( skip )
		return;

	SupportAnalyzer* next_sibling = FirstSupportAnalyzer(is_orig);

	if ( next_sibling )
		next_sibling->NextStream(len, data, is_orig);

	else
		{
		try
			{
			DeliverStream(len, data, is_orig);
			}
		catch ( binpac::Exception const &e )
			{
			ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
			}
		}
	}

void Analyzer::NextUndelivered(uint64_t seq, int len, bool is_orig)
	{
	if ( skip )
		return;

	SupportAnalyzer* next_sibling = FirstSupportAnalyzer(is_orig);

	if ( next_sibling )
		next_sibling->NextUndelivered(seq, len, is_orig);

	else
		{
		try
			{
			Undelivered(seq, len, is_orig);
			}
		catch ( binpac::Exception const &e )
			{
			ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
			}
		}
	}

void Analyzer::NextEndOfData(bool is_orig)
	{
	if ( skip )
		return;

	SupportAnalyzer* next_sibling = FirstSupportAnalyzer(is_orig);

	if ( next_sibling )
		next_sibling->NextEndOfData(is_orig);
	else
		EndOfData(is_orig);
	}

void Analyzer::ForwardPacket(int len, const u_char* data, bool is_orig,
				uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	if ( output_handler )
		output_handler->DeliverPacket(len, data, is_orig, seq,
						ip, caplen);

	AppendNewChildren();

	// Pass to all children.
	analyzer_list::iterator next;
	for ( analyzer_list::iterator i = children.begin();
	      i != children.end(); i = next )
		{
		Analyzer* current = *i;
		next = ++i;

		if ( ! (current->finished || current->removing ) )
			current->NextPacket(len, data, is_orig, seq, ip, caplen);
		else
			DeleteChild(--i);
		}

	AppendNewChildren();
	}

void Analyzer::ForwardStream(int len, const u_char* data, bool is_orig)
	{
	if ( output_handler )
		output_handler->DeliverStream(len, data, is_orig);

	AppendNewChildren();

	analyzer_list::iterator next;
	for ( analyzer_list::iterator i = children.begin();
	      i != children.end(); i = next )
		{
		Analyzer* current = *i;
		next = ++i;

		if ( ! (current->finished || current->removing ) )
			current->NextStream(len, data, is_orig);
		else
			DeleteChild(--i);
		}

	AppendNewChildren();
	}

void Analyzer::ForwardUndelivered(uint64_t seq, int len, bool is_orig)
	{
	if ( output_handler )
		output_handler->Undelivered(seq, len, is_orig);

	AppendNewChildren();

	analyzer_list::iterator next;
	for ( analyzer_list::iterator i = children.begin();
	      i != children.end(); i = next )
		{
		Analyzer* current = *i;
		next = ++i;

		if ( ! (current->finished || current->removing ) )
			current->NextUndelivered(seq, len, is_orig);
		else
			DeleteChild(--i);
		}

	AppendNewChildren();
	}

void Analyzer::ForwardEndOfData(bool orig)
	{
	AppendNewChildren();

	analyzer_list::iterator next;
	for ( analyzer_list::iterator i = children.begin();
	      i != children.end(); i = next )
		{
		Analyzer* current = *i;
		next = ++i;

		if ( ! (current->finished || current->removing ) )
			current->NextEndOfData(orig);
		else
			DeleteChild(--i);
		}

	AppendNewChildren();
	}

bool Analyzer::AddChildAnalyzer(Analyzer* analyzer, bool init)
	{
	auto t = analyzer->GetAnalyzerTag();
	auto it = std::find(prevented.begin(), prevented.end(), t);
	auto prevent = (it != prevented.end());

	if ( HasChildAnalyzer(t) || prevent )
		{
		analyzer->Done();
		delete analyzer;
		return false;
		}

	// We add new children to new_children first.  They are then
	// later copied to the "real" child list.  This is necessary
	// because this method may be called while somebody is iterating
	// over the children and we might confuse the caller by modifying
	// the list.

	analyzer->parent = this;
	new_children.push_back(analyzer);

	if ( init )
		analyzer->Init();

	DBG_LOG(DBG_ANALYZER, "%s added child %s",
			fmt_analyzer(this).c_str(), fmt_analyzer(analyzer).c_str());
	return true;
	}

Analyzer* Analyzer::AddChildAnalyzer(const Tag& analyzer)
	{
	if ( HasChildAnalyzer(analyzer) )
		return nullptr;

	auto it = std::find(prevented.begin(), prevented.end(), analyzer);

	if ( it != prevented.end() )
		return nullptr;

	Analyzer* a = analyzer_mgr->InstantiateAnalyzer(analyzer, conn);

	if ( a && AddChildAnalyzer(a) )
		return a;

	return nullptr;
	}

bool Analyzer::RemoveChild(const analyzer_list& children, ID id)
	{
	for ( const auto& i : children )
		{
		if ( i->id != id )
			continue;

		if ( i->finished || i->removing )
			return false;

		DBG_LOG(DBG_ANALYZER, "%s disabling child %s",
		        fmt_analyzer(this).c_str(), fmt_analyzer(i).c_str());
		// We just flag it as being removed here but postpone
		// actually doing that to later. Otherwise, we'd need
		// to call Done() here, which then in turn might
		// cause further code to be executed that may assume
		// something not true because of a violation that
		// triggered the removal in the first place.
		i->removing = true;
		return true;
		}

	return false;
	}

bool Analyzer::RemoveChildAnalyzer(ID id)
	{
	return RemoveChild(children, id) || RemoveChild(new_children, id);
	}

bool Analyzer::Remove()
	{
	assert(parent);
	parent->RemoveChildAnalyzer(this);
	return removing;
	}

void Analyzer::PreventChildren(Tag tag)
	{
	auto it = std::find(prevented.begin(), prevented.end(), tag);

	if ( it != prevented.end() )
		return;

	prevented.emplace_back(tag);
	}

bool Analyzer::HasChildAnalyzer(Tag tag)
	{
	LOOP_OVER_CHILDREN(i)
		if ( (*i)->tag == tag )
			return true;

	LOOP_OVER_GIVEN_CHILDREN(i, new_children)
		if ( (*i)->tag == tag )
			return true;

	return false;
	}

Analyzer* Analyzer::FindChild(ID arg_id)
	{
	if ( id == arg_id )
		return this;

	LOOP_OVER_CHILDREN(i)
		{
		Analyzer* child = (*i)->FindChild(arg_id);
		if ( child )
			return child;
		}

	LOOP_OVER_GIVEN_CHILDREN(i, new_children)
		{
		Analyzer* child = (*i)->FindChild(arg_id);
		if ( child )
			return child;
		}

	return 0;
	}

Analyzer* Analyzer::FindChild(Tag arg_tag)
	{
	if ( tag == arg_tag )
		return this;

	LOOP_OVER_CHILDREN(i)
		{
		Analyzer* child = (*i)->FindChild(arg_tag);
		if ( child )
			return child;
		}

	LOOP_OVER_GIVEN_CHILDREN(i, new_children)
		{
		Analyzer* child = (*i)->FindChild(arg_tag);
		if ( child )
			return child;
		}

	return 0;
	}

Analyzer* Analyzer::FindChild(const char* name)
	{
	Tag tag = analyzer_mgr->GetComponentTag(name);
	return tag ? FindChild(tag) : 0;
	}

void Analyzer::DeleteChild(analyzer_list::iterator i)
	{
	Analyzer* child = *i;

	// Analyzer must have already been finished or marked for removal.
	assert(child->finished || child->removing);

	if ( child->removing )
		{
		child->Done();
		child->removing = false;
		}

	DBG_LOG(DBG_ANALYZER, "%s deleted child %s 3",
		fmt_analyzer(this).c_str(), fmt_analyzer(child).c_str());

	children.erase(i);
	delete child;
	}

void Analyzer::AddSupportAnalyzer(SupportAnalyzer* analyzer)
	{
	if ( HasSupportAnalyzer(analyzer->GetAnalyzerTag(), analyzer->IsOrig()) )
		{
		DBG_LOG(DBG_ANALYZER, "%s already has %s %s",
			fmt_analyzer(this).c_str(),
			analyzer->IsOrig() ? "originator" : "responder",
			fmt_analyzer(analyzer).c_str());

		analyzer->Done();
		delete analyzer;
		return;
		}

	SupportAnalyzer** head =
		analyzer->IsOrig() ? &orig_supporters : &resp_supporters;

	// Find end of the list.
	SupportAnalyzer* prev = 0;
	SupportAnalyzer* s;
	for ( s = *head; s; prev = s, s = s->sibling )
		;

	if ( prev )
		prev->sibling = analyzer;
	else
		*head = analyzer;

	analyzer->parent = this;

	analyzer->Init();

	DBG_LOG(DBG_ANALYZER, "%s added %s support %s",
			fmt_analyzer(this).c_str(),
			analyzer->IsOrig() ? "originator" : "responder",
			fmt_analyzer(analyzer).c_str());
	}

void Analyzer::RemoveSupportAnalyzer(SupportAnalyzer* analyzer)
	{
	DBG_LOG(DBG_ANALYZER, "%s disabled %s support analyzer %s",
			fmt_analyzer(this).c_str(),
			analyzer->IsOrig() ? "originator" : "responder",
			fmt_analyzer(analyzer).c_str());

	// We mark the analyzer as being removed here, which will prevent it
	// from being used further. However, we don't actually delete it
	// before the parent gets destroyed. While we woulc do that, it's a
	// bit tricky to do at the right time and it doesn't seem worth the
	// trouble.
	analyzer->removing = true;
	return;
	}

bool Analyzer::HasSupportAnalyzer(const Tag& tag, bool orig)
	{
	SupportAnalyzer* s = orig ? orig_supporters : resp_supporters;
	for ( ; s; s = s->sibling )
		if ( s->tag == tag )
			return true;

	return false;
	}

SupportAnalyzer* Analyzer::FirstSupportAnalyzer(bool orig)
	{
	SupportAnalyzer* sa = orig ? orig_supporters : resp_supporters;

	if ( ! sa )
		return 0;

	if ( ! sa->Removing() )
		return sa;

	return sa->Sibling(true);
	}

void Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig,
				uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	DBG_LOG(DBG_ANALYZER, "%s DeliverPacket(%d, %s, %" PRIu64", %p, %d) [%s%s]",
			fmt_analyzer(this).c_str(), len, is_orig ? "T" : "F", seq, ip, caplen,
			fmt_bytes((const char*) data, min(40, len)), len > 40 ? "..." : "");
	}

void Analyzer::DeliverStream(int len, const u_char* data, bool is_orig)
	{
	DBG_LOG(DBG_ANALYZER, "%s DeliverStream(%d, %s) [%s%s]",
			fmt_analyzer(this).c_str(), len, is_orig ? "T" : "F",
			fmt_bytes((const char*) data, min(40, len)), len > 40 ? "..." : "");
	}

void Analyzer::Undelivered(uint64_t seq, int len, bool is_orig)
	{
	DBG_LOG(DBG_ANALYZER, "%s Undelivered(%" PRIu64", %d, %s)",
			fmt_analyzer(this).c_str(), seq, len, is_orig ? "T" : "F");
	}

void Analyzer::EndOfData(bool is_orig)
	{
	DBG_LOG(DBG_ANALYZER, "%s EndOfData(%s)",
			fmt_analyzer(this).c_str(), is_orig ? "T" : "F");
	}

void Analyzer::FlipRoles()
	{
	DBG_LOG(DBG_ANALYZER, "%s FlipRoles()", fmt_analyzer(this).c_str());

	LOOP_OVER_CHILDREN(i)
		(*i)->FlipRoles();

	LOOP_OVER_GIVEN_CHILDREN(i, new_children)
		(*i)->FlipRoles();

	for ( SupportAnalyzer* a = orig_supporters; a; a = a->sibling )
		a->FlipRoles();

	for ( SupportAnalyzer* a = resp_supporters; a; a = a->sibling )
		a->FlipRoles();

	SupportAnalyzer* tmp = orig_supporters;
	orig_supporters = resp_supporters;
	resp_supporters = tmp;
	}

void Analyzer::ProtocolConfirmation(Tag arg_tag)
	{
	if ( protocol_confirmed )
		return;

	protocol_confirmed = true;

	if ( ! protocol_confirmation )
		return;

	EnumVal* tval = arg_tag ? arg_tag.AsEnumVal() : tag.AsEnumVal();
	Ref(tval);

	mgr.QueueEventFast(protocol_confirmation, {
		BuildConnVal(),
		tval,
		val_mgr->GetCount(id),
	});
	}

void Analyzer::ProtocolViolation(const char* reason, const char* data, int len)
	{
	if ( ! protocol_violation )
		return;

	StringVal* r;

	if ( data && len )
		{
		const char *tmp = copy_string(reason);
		r = new StringVal(fmt("%s [%s%s]", tmp,
					fmt_bytes(data, min(40, len)),
					len > 40 ? "..." : ""));
		delete [] tmp;
		}
	else
		r = new StringVal(reason);

	EnumVal* tval = tag.AsEnumVal();
	Ref(tval);

	mgr.QueueEventFast(protocol_violation, {
		BuildConnVal(),
		tval,
		val_mgr->GetCount(id),
		r,
	});
	}

void Analyzer::AddTimer(analyzer_timer_func timer, double t,
			int do_expire, TimerType type)
	{
	Timer* analyzer_timer = new
		AnalyzerTimer(this, timer, t, do_expire, type);

	timer_mgr->Add(analyzer_timer);
	timers.push_back(analyzer_timer);
	}

void Analyzer::RemoveTimer(Timer* t)
	{
	timers.remove(t);
	}

void Analyzer::CancelTimers()
	{
	// We are going to cancel our timers which, in turn, may cause them to
	// call RemoveTimer(), which would then modify the list we're just
	// traversing.  Thus, we first make a copy of the list which we then
	// iterate through.
	timer_list tmp(timers.length());
	std::copy(timers.begin(), timers.end(), back_inserter(tmp));

	// TODO: could be a for_each
	for ( auto timer : tmp )
		timer_mgr->Cancel(timer);

	timers_canceled = 1;
	timers.clear();
	}

void Analyzer::AppendNewChildren()
	{
	LOOP_OVER_GIVEN_CHILDREN(i, new_children)
		children.push_back(*i);
	new_children.clear();
	}

unsigned int Analyzer::MemoryAllocation() const
	{
	unsigned int mem = padded_sizeof(*this)
		+ (timers.MemoryAllocation() - padded_sizeof(timers));

	LOOP_OVER_CONST_CHILDREN(i)
		mem += (*i)->MemoryAllocation();

	for ( SupportAnalyzer* a = orig_supporters; a; a = a->sibling )
		mem += a->MemoryAllocation();

	for ( SupportAnalyzer* a = resp_supporters; a; a = a->sibling )
		mem += a->MemoryAllocation();

	return mem;
	}

void Analyzer::UpdateConnVal(RecordVal *conn_val)
	{
	LOOP_OVER_CHILDREN(i)
		(*i)->UpdateConnVal(conn_val);
	}

RecordVal* Analyzer::BuildConnVal()
	{
	return conn->BuildConnVal();
	}

void Analyzer::Event(EventHandlerPtr f, const char* name)
	{
	conn->Event(f, this, name);
	}

void Analyzer::Event(EventHandlerPtr f, Val* v1, Val* v2)
	{
	conn->Event(f, this, v1, v2);
	}

void Analyzer::ConnectionEvent(EventHandlerPtr f, val_list* vl)
	{
	conn->ConnectionEvent(f, this, vl);
	}

void Analyzer::ConnectionEvent(EventHandlerPtr f, val_list vl)
	{
	conn->ConnectionEvent(f, this, std::move(vl));
	}

void Analyzer::ConnectionEventFast(EventHandlerPtr f, val_list vl)
	{
	conn->ConnectionEventFast(f, this, std::move(vl));
	}

void Analyzer::Weird(const char* name, const char* addl)
	{
	conn->Weird(name, addl);
	}

SupportAnalyzer* SupportAnalyzer::Sibling(bool only_active) const
	{
	if ( ! only_active )
		return sibling;

	SupportAnalyzer* next = sibling;
	while ( next && next->Removing() )
		next = next->sibling;

	return next;
	}

void SupportAnalyzer::ForwardPacket(int len, const u_char* data, bool is_orig,
					uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	// We do not call parent's method, as we're replacing the functionality.

	if ( GetOutputHandler() )
		{
		GetOutputHandler()->DeliverPacket(len, data, is_orig, seq,
							ip, caplen);
		return;
		}

	SupportAnalyzer* next_sibling = Sibling(true);

	if ( next_sibling )
		// Pass to next in chain.
		next_sibling->NextPacket(len, data, is_orig, seq, ip, caplen);
	else
		// Finished with preprocessing - now it's the parent's turn.
		Parent()->DeliverPacket(len, data, is_orig, seq, ip, caplen);
	}

void SupportAnalyzer::ForwardStream(int len, const u_char* data, bool is_orig)
	{
	// We do not call parent's method, as we're replacing the functionality.

	if ( GetOutputHandler() )
		{
		GetOutputHandler()->DeliverStream(len, data, is_orig);
		return;
		}

	SupportAnalyzer* next_sibling = Sibling(true);

	if ( next_sibling )
		// Pass to next in chain.
		next_sibling->NextStream(len, data, is_orig);
	else
		// Finished with preprocessing - now it's the parent's turn.
		Parent()->DeliverStream(len, data, is_orig);
	}

void SupportAnalyzer::ForwardUndelivered(uint64_t seq, int len, bool is_orig)
	{
	// We do not call parent's method, as we're replacing the functionality.

	if ( GetOutputHandler() )
		{
		GetOutputHandler()->Undelivered(seq, len, is_orig);
		return;
		}

	SupportAnalyzer* next_sibling = Sibling(true);

	if ( next_sibling )
		// Pass to next in chain.
		next_sibling->NextUndelivered(seq, len, is_orig);
	else
		// Finished with preprocessing - now it's the parent's turn.
		Parent()->Undelivered(seq, len, is_orig);
	}


void TransportLayerAnalyzer::Done()
	{
	Analyzer::Done();
	}

void TransportLayerAnalyzer::SetContentsFile(unsigned int /* direction */,
						BroFile* /* f */)
	{
	reporter->Error("analyzer type does not support writing to a contents file");
	}

BroFile* TransportLayerAnalyzer::GetContentsFile(unsigned int /* direction */) const
	{
	reporter->Error("analyzer type does not support writing to a contents file");
	return 0;
	}

void TransportLayerAnalyzer::PacketContents(const u_char* data, int len)
	{
	if ( packet_contents && len > 0 )
		{
		BroString* cbs = new BroString(data, len, 1);
		Val* contents = new StringVal(cbs);
		Event(packet_contents, contents);
		}
	}
