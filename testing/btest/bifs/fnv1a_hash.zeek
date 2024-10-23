# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

function output_hashes(val: any)
{
    print(fmt("Test vector: %s (%s)", val, type_name(val)));
    print(fmt("fnv1a32: 0x%x", fnv1a32(val)));
    print(fmt("fnv1a64: 0x%x", fnv1a64(val)));
}

event zeek_init()
{
    output_hashes("a");
    output_hashes("foobar");
    output_hashes("a very very long input sort of");
    output_hashes("123");
    output_hashes(123);
    output_hashes(123.0);
    output_hashes("T");
    output_hashes(T);
    output_hashes(F);

    local s: string;
    local bytes_from_hex: string;

    s = "666f6f626172";  # hex representation of foobar
    bytes_from_hex = hexstr_to_bytestring(s);
    output_hashes(bytes_from_hex);

    s = "01020304";  # hex representation of 4 bytes
    bytes_from_hex = hexstr_to_bytestring(s);
    output_hashes(bytes_from_hex);
}