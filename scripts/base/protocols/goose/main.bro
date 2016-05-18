
module GOOSE;

event bro_init ()
{
	print "Initialization of GOOSE script";
}

event goose_message(len : count)
{
	print fmt("GOOSE message detected. Its lenght is %d bytes.", len);
	print "";
}

