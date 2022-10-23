# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

global default_alphabet: string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

global my_alphabet: string = "!#$%&/(),-.:;<>@[]^ `_{|}~abcdefghijklmnopqrstuvwxyz0123456789+?";

print encode_base64("bro");
print encode_base64("bro", default_alphabet);
print encode_base64("bro", ""); # should use default alphabet
print encode_base64("bro", my_alphabet);

print encode_base64("padding");
print encode_base64("padding1");
print encode_base64("padding12");
