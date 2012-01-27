
#ifndef THREADING_MSGTHREAD_H
#define THREADING_MSGTHREAD_H

#include <pthread.h>

#include "DebugLogger.h"

#include "BasicThread.h"
#include "Queue.h"

namespace threading {

class BasicInputMessage;
class BasicOutputMessage;
class HeartbeatMessage;

class MsgThread : public BasicThread
{
public:
	MsgThread(const string& name);

	void SendIn(BasicInputMessage* msg)	{ return SendIn(msg, false); }
	void SendOut(BasicOutputMessage* msg)	{ return SendOut(msg, false); }

	BasicOutputMessage* RetrieveOut();

	// Report an informational message, nothing that needs specific
	// attention.
	void Info(const char* msg);

	// Report a warning that may indicate a problem.
	void Warning(const char* msg);

	// Report a non-fatal error. Processing proceeds normally after the error
	// has been reported.
	void Error(const char* msg);

	// Report a fatal error. Bro will terminate after the message has been
	// reported.
	void FatalError(const char* msg);

	// Report a fatal error. Bro will terminate after the message has been
	// reported and always generate a core dump.
	void FatalErrorWithCore(const char* msg);

	// Report about a potential internal problem. Bro will continue
	// normally.
	void InternalWarning(const char* msg);

	// Report an internal program error. Bro will terminate with a core
	// dump after the message has been reported.
	void InternalError(const char* msg);

#ifdef DEBUG
	// Records a debug message for the given stream.
	void Debug(DebugStream stream, const char* msg);
#endif

	void Heartbeat();

	struct Stats
		{
		uint64_t sent_in;
		uint64_t sent_out;
		uint64_t pending_in;
		uint64_t pending_out;
		};

	void GetStats(Stats* stats);

protected:
	friend class HeartbeatMessage;

	virtual void Run();
	virtual void OnStop();

	virtual bool DoHeartbeat(double network_time, double current_time)	{ return true; }

private:
	friend class Manager;

	BasicInputMessage* RetrieveIn();

	void SendIn(BasicInputMessage* msg, bool force);
	void SendOut(BasicOutputMessage* msg, bool force);

	bool HasIn()	{ return queue_in.Ready(); }
	bool HasOut()	{ return queue_out.Ready(); }

	Queue_<BasicInputMessage *> queue_in;
	Queue_<BasicOutputMessage *> queue_out;

	uint64_t cnt_sent_in;
	uint64_t cnt_sent_out;
};

class Message
{
public:
	virtual ~Message();

	const string& Name() const { return name; }

	virtual bool Process() = 0; // Thread will be terminated if returngin false.

protected:
	Message(const string& arg_name)	{ name = arg_name; }

private:
	string name;
};

class BasicInputMessage : public Message
{
protected:
	BasicInputMessage(const string& name) : Message(name)	{}
};

class BasicOutputMessage : public Message
{
protected:
	BasicOutputMessage(const string& name) : Message(name)	{}
};

template<typename O>
class InputMessage : public BasicInputMessage
{
public:
	O* Object() const { return object; }

protected:
	InputMessage(const string& name, O* arg_object) : BasicInputMessage(name)
		{ object = arg_object; }

private:
	O* object;
};

template<typename O>
class OutputMessage : public BasicOutputMessage
{
public:
	O* Object() const { return object; }

protected:
	OutputMessage(const string& name, O* arg_object) : BasicOutputMessage(name)
		{ object = arg_object; }

private:
	O* object;
};

}


#endif
