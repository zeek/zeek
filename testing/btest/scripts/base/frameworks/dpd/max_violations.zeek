# This test is somewhat awkward -- it's just using a baseline of an http.log
# that would have otherwise logged a few more "400 Bad Request" responses if
# we had not throttled the protocol violation limit to zero and disabled the
# analyzer right away.  But that's proof enough for this unit test that the
# DPD::max_violations option works.

# @TEST-EXEC: zeek -r $TRACES/http/methods.trace %INPUT
# @TEST-EXEC: btest-diff http.log

redef DPD::max_violations += { [Analyzer::ANALYZER_HTTP] = 0 };
