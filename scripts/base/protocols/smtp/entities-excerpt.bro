##! This script is for optionally adding a body excerpt to the SMTP
##! entities log.

@load ./entities

module SMTP;

export {
	redef record SMTP::EntityInfo += {
		## The entity body excerpt.
		excerpt:    string &log &default="";
		
		## Internal tracking to know how much of the body should be included
		## in the excerpt.
		excerpt_len: count &optional;
	};
	
	## This is the default value for how much of the entity body should be
	## included for all MIME entities.
	const default_entity_excerpt_len = 0 &redef;
	
	## This table defines how much of various entity bodies should be 
	## included in excerpts.
	const entity_excerpt_len: table[string] of count = {} 
		&redef
		&default = default_entity_excerpt_len;
}

event mime_segment_data(c: connection, length: count, data: string) &priority=-1
	{
	if ( ! c?$smtp ) return;
	
	if ( c$smtp$current_entity$content_len == 0 )
		c$smtp$current_entity$excerpt_len = entity_excerpt_len[c$smtp$current_entity$mime_type];
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=-2
	{
	if ( ! c?$smtp ) return;
	
	local ent = c$smtp$current_entity;
	if ( ent$content_len < ent$excerpt_len )
		{
		if ( ent$content_len + length < ent$excerpt_len )
			ent$excerpt = cat(ent$excerpt, data);
		else
			{
			local x_bytes = ent$excerpt_len - ent$content_len;
			ent$excerpt = cat(ent$excerpt, sub_bytes(data, 1, x_bytes));
			}
		}
	}
