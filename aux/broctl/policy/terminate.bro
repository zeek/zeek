# $Id: terminate.bro 6811 2009-07-06 20:41:10Z robin $
#
# Just terminate Bro after it parsed its configuration.

event bro_init() &priority = -10
{
	terminate();
}



