#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
    {
    local result = get_tags_by_category("STORAGE_BACKEND");

    for (i in result)
        print result[i];
    }
