##! This script is for optionally adding a body excerpt to the SMTP
##! entities log.

@load base/protocols/smtp/entities

module SMTP;

export {
	redef record SMTP::Entity+= {
		## The entity body excerpt.
		excerpt:    string &log &default="";
	};

	## This is the default value for how much of the entity body should be
	## included for all MIME entities.  The lesser of this value and
	## :bro:see:`default_file_bof_buffer_size` will be used.
	const default_entity_excerpt_len = 0 &redef;
}

event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "SMTP" ) return;
	if ( ! f?$bof_buffer ) return;
	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( ! c?$smtp ) next;

		if ( default_entity_excerpt_len > 0 )
			c$smtp$entity$excerpt = f$bof_buffer[0:default_entity_excerpt_len];
		}
	}
