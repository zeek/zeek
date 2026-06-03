# @TEST-DOC: A SYN carrying a window scale shift count above the RFC 7323 max of 14 should raise a TCP_scale_range weird and get clamped instead of overshifting in update_window().
#
# @TEST-EXEC: zeek -b -r $TRACES/tcp/window-scale-range.pcap %INPUT >out
# @TEST-EXEC: test ! -s out
# @TEST-EXEC: btest-diff-cut -m id.orig_h id.orig_p id.resp_h id.resp_p name addl weird.log

@load base/frameworks/notice/weird
