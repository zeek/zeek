# Test that zeekygen warnings are disabled by default and can be enabled
# with ZEEK_ENABLE_ZEEKYGEN_WARNINGS environment variable.
#
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; unset ZEEK_ENABLE_ZEEKYGEN_WARNINGS; zeek -X zeekygen.config %INPUT > default 2>&1
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; ZEEK_ENABLE_ZEEKYGEN_WARNINGS=1 zeek -X zeekygen.config %INPUT > with_warning 2>&1
#
# The above will reflect absolute paths in the output, which is no
# bueno in our baselines since it reflects the context of exactly
# where this test gets run. So strip them out:
#
# @TEST-EXEC: sed -i.bak 's| /.*zeek/testing/btest/doc/zeekygen| /.../doc/zeekygen|' default
# @TEST-EXEC: sed -i.bak 's| /.*zeek/testing/btest/doc/zeekygen| /.../doc/zeekygen|' with_warning
#
# @TEST-EXEC: btest-diff default
# @TEST-EXEC: btest-diff with_warning

## document this
@load misc/scan
