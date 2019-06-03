# @TEST-EXEC: btest-bg-run zeek zeek -b $SCRIPTS/file-analysis-test.zeek %INPUT
# @TEST-EXEC: btest-bg-wait 8
# @TEST-EXEC: btest-diff zeek/.stdout
# @TEST-EXEC: diff -q zeek/FK8WqY1Q9U1rVxnDge-file input.log

redef exit_only_after_terminate = T;

redef test_get_file_name = function(f: fa_file): string
    {
    return fmt("%s-file", f$id);
    };

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	ns
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	4242
@TEST-END-FILE

event zeek_init()
	{
	local source: string = "../input.log";
	Input::add_analysis([$source=source, $reader=Input::READER_BINARY,
	                     $mode=Input::MANUAL, $name=source]);
	Input::remove(source);
	}

event file_state_remove(f: fa_file) &priority=-10
	{
	terminate();
	}
