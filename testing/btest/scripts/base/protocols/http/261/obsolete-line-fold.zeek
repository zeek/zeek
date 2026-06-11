# @TEST-DOC: Line-folding was deprecated in RFC 7230 in 2014. We raise weirds today.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/261/variant-09-te_obs_fold.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid trans_depth method host uri http.log
# @TEST-EXEC: btest-diff-cut -m uid name addl notice source weird.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/notice/weird
