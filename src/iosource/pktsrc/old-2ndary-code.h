// Whether a PktSrc object is used by the normal filter structure or the
// secondary-path structure.
typedef enum {
	TYPE_FILTER_NORMAL,  // the normal filter
	TYPE_FILTER_SECONDARY,  // the secondary-path filter
} PktSrc_Filter_Type;

// {filter,event} tuples conforming the secondary path.
class SecondaryEvent {
public:
	SecondaryEvent(const char* arg_filter, Func* arg_event)
		{
		filter = arg_filter;
		event = arg_event;
		}

	const char* Filter()	{ return filter; }
	Func* Event()		{ return event; }

private:
	const char* filter;
	Func* event;
};

declare(PList,SecondaryEvent);
typedef PList(SecondaryEvent) secondary_event_list;

class SecondaryPath {
public:
	SecondaryPath();
	~SecondaryPath();

	secondary_event_list& EventTable()	{ return event_list; }
	const char* Filter()			{ return filter; }

private:
	secondary_event_list event_list;
	// OR'ed union of all SecondaryEvent filters
	char* filter;
};

// Main secondary-path object.
extern SecondaryPath* secondary_path;

// {program, {filter,event}} tuple table.
class SecondaryProgram {
public:
	SecondaryProgram(BPF_Program* arg_program, SecondaryEvent* arg_event)
		{
		program = arg_program;
		event = arg_event;
		}

	~SecondaryProgram();

	BPF_Program* Program()  { return program; }
	SecondaryEvent* Event()	{ return event; }

private:
	// Associated program.
	BPF_Program *program;

	// Event that is run in case the program is matched.
	SecondaryEvent* event;
};

declare(PList,SecondaryProgram);
typedef PList(SecondaryProgram) secondary_program_list;

