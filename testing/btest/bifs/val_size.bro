#
# @TEST-EXEC: bro %INPUT > out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = 1;
	local b = T;

	print val_size(a);
	print val_size(b);
	}
