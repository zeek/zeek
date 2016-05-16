# @TEST-EXEC: bro -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn

redef Log::default_unrolling_sep = "_";