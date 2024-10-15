# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: sed -e 1d -e '/received termination/d' .stderr > .stderrwithoutfirstline
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderrwithoutfirstline

redef exit_only_after_terminate = T;
redef InputAscii::fail_on_invalid_lines = F;

@TEST-START-FILE input.log
#fields	a	b	c
#types	string	bool	bool
hello
hello
hello
hello
hello
hello
"hi"	T	F
hello
hello
hello
hello
hello
hello
hello
@TEST-END-FILE

type Key: record {
    a: string;
};

type Val: record {
    b: bool &log;
    c: bool &log;
};

global test_table: table[string] of Val = table();

event zeek_init() {
    Input::add_table([
        $source="../input.log", $name="test_table",
        $idx=Key, $val=Val, $destination=test_table,
        $mode=Input::REREAD
    ]);
}


event Input::end_of_data(name: string, source:string) {
    terminate();
}
