@if ( have_spicy_analyzers() )
@load ./spicy-events.zeek
@load-sigs ./dpd.sig
@load ./consts
@load ./main.zeek
@endif
