# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/.stderr
# @TEST-EXEC: btest-diff zeek/.stdout

@TEST-START-FILE denylist.txt
#separator \x09
#fields	ip	colors
192.168.17.1	Red,White
192.168.27.2	White,asdf
192.168.250.3	Blue
@TEST-END-FILE

# test.zeek
type Idx: record {
    ip: addr;
};

type Color: enum { Red, White, Blue, };

type Val: record {
    colors: set[Color];
};

global denylist: table[addr] of Val = table();

event zeek_init() {
    Input::add_table([$source="../denylist.txt", $name="denylist",
                      $idx=Idx, $val=Val, $destination=denylist]);
    Input::remove("denylist");
}

event Input::end_of_data(name: string, source: string) {
    print denylist;
}