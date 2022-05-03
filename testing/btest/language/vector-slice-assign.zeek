# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type testrec: record {
	seq: count;
};

function make_recs(seqs: vector of count): vector of testrec
{
	local r: vector of testrec;
	for (i in seqs)
		r += testrec($seq=seqs[i]);
	return r;
}

event zeek_init()
{
	local seqs: vector of count = {1, 2, 3, 4, 5, 6, 7};
	local v = make_recs(seqs);
	local tmp = v[0:2];
	v[0:2] = v[3:5];
	v[3:5] = tmp;
	print v;
}
