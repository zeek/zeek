# @TEST-DOC: Test Zeek parsing SET commands
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/set.trace base/protocols/redis %INPUT >output
# @TEST-EXEC: btest-diff output

event RESP::set_command(c: connection, is_orig: bool, command: RESP::SetCommand)
    {
    print fmt("Key: %s Value: %s", command$key, command$value);
    }
