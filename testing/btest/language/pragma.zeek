# @TEST-DOC: Test @pragma directive
# @TEST-EXEC: zeek -b %INPUT >out 2>&1; echo "exit_code=$?" >> out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# @TEST-START-FILE unbalanced-push.zeek
@pragma push ignore-deprecations
# @TEST-END-FILE

# @TEST-START-FILE unbalanced-pop.zeek
@pragma pop ignore-deprecations
# @TEST-END-FILE

# Missing pragma is an error
@pragma

# @TEST-START-NEXT

# Just an unknown pragma, warning but not an error.
@pragma unknown

# @TEST-START-NEXT

# Pushing without a value is an error
@pragma push
@pragma pop

# @TEST-START-NEXT

# Pushing something unknown is fine, though we'll warn.
@pragma push unknown
@pragma pop

# @TEST-START-NEXT

# Popping the wrong value is an error
@pragma push unknown
@pragma pop nwonknu

# @TEST-START-NEXT
# Not popping a value before the end of file is an error.
@pragma push ignore-deprecations

# @TEST-START-NEXT
# Popping something that was never pushed is an error.
@pragma pop ignore-deprecations

# @TEST-START-NEXT
# Popping anything that was never pushed is an error.
@pragma pop

# @TEST-START-NEXT
# Loading a file that's unbalanced causes an error
@load ./unbalanced-push.zeek

# @TEST-START-NEXT
# Nice try
@pragma push ignore-deprecations
@load ./unbalanced-pop.zeek

# @TEST-START-NEXT
# Extra spaces
@pragma push     ignore-deprecations
print "like extra spaces";
@pragma pop

# @TEST-START-NEXT
# Extra spaces (2)
@pragma push     ignore-deprecations
print "like extra spaces (2)";
@pragma pop      ignore-deprecations
