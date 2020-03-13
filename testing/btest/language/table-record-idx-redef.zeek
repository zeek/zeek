# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type recrec: record {
	rr: count &default = 101;
};

type myrec: record {
	r: recrec &default=recrec();
	a: count &default=13;
};

global mr = myrec($a = 37);
global active: table[myrec] of count = table([mr] = 1);

redef record myrec += {
	b: count &default=28;
};

redef record recrec += {
	rrr: string &default="blue pill";
};

global check1: bool = myrec() in active;
global check2: bool = mr in active;
global check3: bool = myrec($a=37, $b=0) in active;

event zeek_init()
	{
	print check1, check2, check3;
	active[myrec()] = 42;
	print active;
	}
