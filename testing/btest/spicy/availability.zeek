# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek %INPUT | grep -q yes
# @TEST-EXEC: zeek -b Zeek::Spicy %INPUT | grep -q yes
# @TEST-EXEC: if zeek -N Zeek::Spicy | grep -q built-in; then zeek -b %INPUT | grep -q yes; else  zeek -b %INPUT | grep -q no; fi
#
# @TEST-DOC: Confirms `Zeek::available` signals correctly whether the Spicy plugin is loaded and active.
#
# Note that bare mode, by default, doesn't activate the plugin.

@ifdef ( Spicy::available )
    print "yes";
@else
    print "no";
@endif
