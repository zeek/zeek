# @TEST-DOC: Test the weird for maximum packet analyzer chain depth
#
# @TEST-EXEC: zeek -b -r $TRACES/pbb-recursive-frames.pcapng %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird
