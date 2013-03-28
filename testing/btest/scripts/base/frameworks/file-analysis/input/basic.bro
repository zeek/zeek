# @TEST-EXEC: btest-bg-run bro bro -b $SCRIPTS/file-analysis-test.bro %INPUT
# @TEST-EXEC: btest-bg-wait 8
# @TEST-EXEC: btest-diff bro/.stdout
# @TEST-EXEC: diff -q bro/nYgPNGLrZf9-file input.log

redef exit_only_after_terminate = T;

redef test_get_file_name = function(info: FileAnalysis::Info): string
    {
    return fmt("%s-file", info$file_id);
    };

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	ns
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	4242
@TEST-END-FILE

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	FileAnalysis::data_stream(description$source, s);
	}

event Input::end_of_data(name: string, source: string) 
	{
	FileAnalysis::eof(source);
	}

event bro_init()
	{
	Input::add_event([$source="../input.log", $reader=Input::READER_BINARY,
	                  $mode=Input::MANUAL, $name="input", $fields=Val,
	                  $ev=line, $want_record=F]);
	Input::remove("input");
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=-10
	{
	if ( trig != FileAnalysis::TRIGGER_EOF ) return;
	terminate();
	}

