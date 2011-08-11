// See the file "COPYING" in the main distribution directory for copyright.

#include "util.h"
#include "LogMgr.h"
#include "LogWriter.h"
#include "Reporter.h"

// DO NOT! initialize this variable.  Out of order initialization in the global scope could
// overwrite a successfully initialized writer map with whatever goes here.
LogWriterRegistrar::WriterMap *LogWriterRegistrar::writers;

WriteMessage& WriteMessage::operator= (const WriteMessage& target)
	{
	if(this == &target)
		return *this;
	ref = target.ref;
	num_fields = target.num_fields;
	fields = target.fields;
	vals = target.vals;
	return *this;
	}

WriteMessage::WriteMessage(const WriteMessage& target)
: ref(target.ref), num_fields(target.num_fields), fields(target.fields), vals(target.vals)
	{ }

bool BulkWriteMessage::process()
	{
	for(std::vector<WriteMessage>::iterator iter = messages.begin();
		iter != messages.end(); ++iter)
		{
		if(!iter->process())
			return false;
		}
	return true;
	}

bool RotationFinishedMessage::process()
	{
	return log_mgr->FinishedRotation(&ref, new_name, old_name, open, close, terminating);
	}

LogWriterRegistrar::LogWriterRegistrar(const bro_int_t type, const char *name, 
							bool(*init)(), LogWriterRegistrar::InstantiateFunction factory)
	{
	static bool needsInit = true;
	if(needsInit)
		{
		writers = new WriterMap;
		needsInit = false;
		}
	writers->insert(std::make_pair(type, LogWriterDefinition(type, factory, init, name)));
	}

LogEmissary *LogWriterRegistrar::LaunchWriterThread(std::string path, size_t num_fields, LogField * const *fields, const bro_int_t type)
	{
	WriterMapIterator iter = writers->find(type);
	if(iter == writers->end())
		{
		reporter->Error("Could not construct writer: unknown writer type");
		return NULL;
		}

	if(!iter->second.factory)
		{
		return NULL;
		}

	if(iter->second.init)
		{
			if(!iter->second.init())
				{
				reporter->Error("Writer initialization failed");
				iter->second.init = NULL;
				iter->second.factory = NULL;
				return NULL;
				}
			iter->second.init = NULL;
		}

	ThreadSafeQueue<MessageEvent *> *push_queue = new ThreadSafeQueue<MessageEvent *>;
	ThreadSafeQueue<MessageEvent *> *pull_queue = new ThreadSafeQueue<MessageEvent *>;
	LogEmissary* emissary = new LogEmissary(*push_queue, *pull_queue);
	LogWriter *writer_obj = iter->second.factory(*emissary, *push_queue, *pull_queue);
	emissary->BindWriter(writer_obj);
	writer_obj->start();
	emissary->Init(path, num_fields, fields); 
	return emissary;
	}

const char *LogWriter::Fmt (char * format, ...) const
	{
	va_list args;
	va_start (args, format);
	vsnprintf (strbuf, LOGWRITER_MAX_BUFSZ, format, args);
	va_end (args);
	return strbuf;
	}

void LogWriter::Error (const char *msg) 
	{
	putNotification(new ErrorReport(msg));
	}

LogEmissary::LogEmissary(QueueInterface<MessageEvent *>& push_queue, QueueInterface<MessageEvent *>& pull_queue)
: bound(NULL), push_queue(push_queue), pull_queue(pull_queue), path(""), fields(NULL), 
   num_fields(0), canInit(true), isActive(false)
	{
		bMessage = new BulkWriteMessage();
	}

void LogEmissary::Shutdown()
	{
	if(!isActive)
		{
		return;
		}
	Finish();
	push_queue.put(new TerminateThread(*bound));
	bound->join();
	Update();
	bound = NULL;
	isActive = false;
	}

LogEmissary::~LogEmissary()
	{
	assert(!isActive);  // If this emissary hasn't been shut down, there's a serious problem somewhere. . .
	assert(bMessage->size() == 0);
	for(int i = 0; i < num_fields; ++i)
		delete fields[i];
	delete [] fields;

	delete bound;
	//TODO: flushing the queues will probably need to work differently once IPC / network communication become important.
	while(push_queue.ready())
		{
			delete push_queue.get();
		}
	delete &push_queue;
	delete &pull_queue;
	}

void LogEmissary::BindWriter(LogWriter *writer)
{
	bound = writer;
	isActive = true;
}

bool LogEmissary::Init(string arg_path, int arg_num_fields,
		     LogField* const * arg_fields)
	{
	if(!canInit)
		{
		DBG_LOG(DBG_LOGGING, "Tried to initialize log (path='%s') multiple times!", arg_path.c_str());
		return false;
		}
	path = arg_path;
	num_fields = arg_num_fields;
	fields = arg_fields;

	assert(bound);
	push_queue.put(new InitMessage(*bound, arg_path, arg_num_fields, arg_fields));
	
	canInit = false;
	return true;
	}

LogEmissary& LogEmissary::operator= (const LogEmissary& target)
	{
	if(this == &target)
		return *this;
	bound = target.bound;
	push_queue = target.push_queue;
	pull_queue = target.pull_queue;
	path = target.path;
	num_fields = target.num_fields;
	fields = target.fields;
	bMessage = target.bMessage;
	canInit = target.canInit;
	isActive = target.isActive;
	return *this;
	}

bool LogEmissary::Write(int arg_num_fields, LogVal** vals)
	{
	if(!isActive)
		{
		DBG_LOG(DBG_LOGGING, "Tried to write to inactive LogEmissary");
		return false;
		}
	// Double-check that the arguments match. If we get this from remote,
	// something might be mixed up.
	if ( num_fields != arg_num_fields )
		{
		DBG_LOG(DBG_LOGGING, "Number of fields don't match in LogEmissary::Write() (%d vs. %d)",
			arg_num_fields, num_fields);

		LogMgr::DeleteVals(arg_num_fields, vals);
		return false;
		}

	for ( int i = 0; i < num_fields; ++i )
		{
		if ( vals[i]->type != fields[i]->type )
			{
			DBG_LOG(DBG_LOGGING, "Field type doesn't match in LogEmissary::Write() (%d vs. %d)",
				vals[i]->type, fields[i]->type);
			LogMgr::DeleteVals(arg_num_fields, vals);
			return false;
			}
		}

	assert(bound);
	
	WriteMessage w(*bound, num_fields, fields, vals);
	bMessage->add(w);

	if(bMessage->size() > LOG_QUEUE_SZ)
		{
		push_queue.put(bMessage);
		bMessage = new BulkWriteMessage();
		}
	
	// push_queue.put(new WriteMessage(*bound, num_fields, fields, vals));

	return true;
	}

bool LogEmissary::SetBuf(bool enabled)
	{
	assert(bound);
	if(!isActive)
		{
		DBG_LOG(DBG_LOGGING, "Tried to set buffer option for inactive LogEmissary");
		return false;
		}
	push_queue.put(new BufferMessage(*bound, enabled));
	return true;
	}

bool LogEmissary::Rotate(string rotated_path, double open, double close, bool terminating)
	{
	assert(bound);
	if(!isActive)
		{
		DBG_LOG(DBG_LOGGING, "Tried to rotate logs on inactive LogEmissary");
		return false;
		}

	push_queue.put(bMessage);
	push_queue.put(new RotateMessage(*bound, rotated_path, open, close, terminating));
	
	bMessage = new BulkWriteMessage();
	return true;
	}

// Need to flush both the local bulk write buffer and the log itself
bool LogEmissary::Flush()
	{
	assert(bound);
	if(!isActive)
		{
		DBG_LOG(DBG_LOGGING, "Tried to flush logs on inactive LogEmissary");
		return false;
		}
	push_queue.put(bMessage);
	push_queue.put(new FlushMessage(*bound));
	
	bMessage = new BulkWriteMessage();
	return true;
	}

void LogEmissary::Finish()
	{
	assert(bound);
	if(!isActive)
		{
		DBG_LOG(DBG_LOGGING, "Tried to finalize log for inactive LogEmissary");
		return;
		}
	push_queue.put(bMessage);
	push_queue.put(new FinishMessage(*bound));
	
	bMessage = new BulkWriteMessage();
	}

void LogWriter::DeleteVals(LogVal** vals, const int num_fields)
	{
	LogMgr::DeleteVals(num_fields, vals);
	}

bool LogWriter::FinishedRotation(string new_name, string old_name, double open,
				 double close, bool terminating)
	{
	putNotification(new RotationFinishedMessage(this->parent, new_name, old_name, open, close, terminating));
	return true;
	}

LogWriter& LogWriter::operator=(const LogWriter& target)
	{
	if(this == &target)
		return *this;
	parent = target.parent;
	buffered = target.buffered;
	return *this;
	}

