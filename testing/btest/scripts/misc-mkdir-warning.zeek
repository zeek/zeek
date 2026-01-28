# @TEST-EXEC: zeek

event zeek_init()
    {
    local ok = mkdir("/root/should_fail");
    print ok;
    }

