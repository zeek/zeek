# Sets some testing specific options.

@ifdef ( SMTP::never_calc_md5 )
        # MDD5s can depend on libmagic output.
	redef SMTP::never_calc_md5 = T;
@endif
