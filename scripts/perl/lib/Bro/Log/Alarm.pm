package Bro::Log::Alarm;

use strict;
require 5.006_001;
use strict;

use vars qw( $VERSION
		%DATA_MAP );

# $Id: Alarm.pm 987 2005-01-08 01:04:43Z rwinslow $
$VERSION = 1.20;

# Map data descriptions to subroutine names
%DATA_MAP = ( t => \&timestamp,
			timestamp => \&timestamp,
			notice => \&notice_type,
			notice_type => \&notice_type,
			notice_act => \&notice_action,
			notice_action => \&notice_action,
			event_src => \&event_source,
			event_source => \&event_source,
			source_addr => \&source_addr,
			src_addr => \&source_addr,
			srcip => \&source_addr,
			source_ip => \&source_addr,
			src_port => \&source_port,
			source_port => \&source_port,
			destination_addr => \&destination_addr,
			dst_addr => \&destination_addr,
			dstip => \&destination_addr,
			destination_ip => \&destination_addr,
			dst_port => \&destination_port,
			destination_port => \&destination_port,
			user => \&user,
			filename => \&filename,
			sigid => \&sigid,
			method => \&method,
			URL => \&url,
			n => \&misc_integer,
			count => \&misc_integer,
			return_code => \&misc_integer,
			msg => \&message,
			message => \&message,
			sub_msg => \&sub_message,
			sub_message => \&sub_message,
			);

sub new
{
	my $sub_name = 'new';
	
	# This is the parser for tag based alarm and notice files.
	my $_log_line;
	my @_args = @_;
	my %alarm_parts;

	if( @_args == 1 )
	{
		$_log_line = $_args[0];
	}
	else
	{
		return( undef );
	}

	# Order of data in array
	# t = timestamp
	# no = notice_type
	# na = notice_action
	# es = event_src, event_source
	# sa = source_ip (source address)
	# sp = source_port
	# da = destination_ip (destination address)
	# dp = destination_port
	# user = user
	# file = filename or sigid
	# method = method
	# url = URL
	# num = count or number or return_code
	# msg = message
	# sub = sub_message
	# tag = tag
	
	# Is this a tag based log line delimited by spaces?
	if( $_log_line =~ m/^t\=/ )
	{
		my $i = 0;
		my $i2 = 0;
		my $len = length( $_log_line );
		my $p_idx = 0;
		my $buff_pos = 0;
		my $subtr_len = 0;
		my @log_parts;
		
		for( $i2 = 0; $i2 < $len; ++$i2 )
		{
			if( substr( $_log_line, $i2, 1 ) eq ' ' and
				substr( $_log_line, $p_idx, 1 ) ne "\\" )
			{
				if( $subtr_len < 1 )
				{
					# Skip over this entry, probably just leading space.
					# Regardless of what happened there is no useful data.
				}
				else
				{
					my $tag;
					my $tag_data;
					
					( $tag, $tag_data ) = extracttag( substr( $_log_line, $buff_pos, $subtr_len ) );
					if( exists( $alarm_parts{$tag} ) )
					{
						warn( __PACKAGE__ . "::$sub_name, Found duplicate tag '$tag', in data.  It will be ignored\n" );
					}
					else
					{
						$alarm_parts{$tag} = $tag_data;
					}
				}
				$subtr_len = 0;
				$p_idx = $i2 + 1;
				$buff_pos = $i2 + 1;
				++$i;
			}
			else
			{
				++$subtr_len;
				$p_idx = $i2;				
			}
		}

		# Get the last piece of data
		my $tag;
		my $tag_data;
		( $tag, $tag_data ) = extracttag( substr( $_log_line, $buff_pos, $subtr_len ) );
		
		# Make sure this is not a duplicate tag.
		if( exists( $alarm_parts{$tag} ) )
		{
			warn( __PACKAGE__ . "::$sub_name, Found duplicate tag '$tag', in data.  It will be ignored\n" );
		}
		else
		{
			# Remove any trailing newlines
			chomp( $tag_data );
			$alarm_parts{$tag} = $tag_data;
		}
	}
	# Is this a colon delimited log line?
	elsif( $_log_line =~ m/^[[:digit:]]{10}\.[[:digit:]]{6}/ and $_log_line =~ m/\:/ )
	{
		my $i = 0;
		my $i2 = 0;
		my $len = length( $_log_line );
		my $p_idx = 0;
		my $buff_pos = 0;
		my $subtr_len = 0;
		my @log_parts;
		
		for( $i2 = 0; $i2 < $len; ++$i2 )
		{
			if( substr( $_log_line, $i2, 1 ) eq ':' and
				substr( $_log_line, $p_idx, 1 ) ne "\\" )
			{
				if( $subtr_len < 1 )
				{
					$log_parts[$i] = '';
				}
				else
				{
					$log_parts[$i] = substr( $_log_line, $buff_pos, $subtr_len );
					$log_parts[$i] = unescape_colons( $log_parts[$i] );
				}
				$subtr_len = 0;
				$p_idx = $i2 + 1;
				$buff_pos = $i2 + 1;
				++$i;
			}
			else
			{
				++$subtr_len;
				$p_idx = $i2;				
			}
		}

		# Get the last piece of data
		$log_parts[$i] = unescape_colons( substr( $_log_line, $buff_pos, $subtr_len ) );
		
		# Remove any trailing newline that may have been left on
		chomp( $log_parts[$i] );
		
		$alarm_parts{t} = $log_parts[0];
		$alarm_parts{no} = $log_parts[1];
		$alarm_parts{na} = $log_parts[2];
		$alarm_parts{es} = $log_parts[3];
		$alarm_parts{sa} = $log_parts[4];
		$alarm_parts{sp} = $log_parts[5];
		$alarm_parts{da} = $log_parts[6];
		$alarm_parts{dp} = $log_parts[7];
		$alarm_parts{user} = $log_parts[8];
		$alarm_parts{file} = $log_parts[9];
		$alarm_parts{method} = $log_parts[10];
		$alarm_parts{url} = $log_parts[11];
		$alarm_parts{num} = $log_parts[12];
		$alarm_parts{msg} = $log_parts[13];
		$alarm_parts{sub} = $log_parts[14];
	}
	else
	{
		return( undef );
	}
	
	# Make sure that certain fields have values otherwise the data is invalid
	if( exists( $alarm_parts{t} ) )
	{
		return( \%alarm_parts );
	}
	else
	{
		return( undef );
	}
	
}

sub unescape
{
	my $sub_name = 'unescape';
	
	&unescape_spaces;
}

sub unescape_spaces
{
	my $sub_name = 'unescape_spaces';
	
	my $data = $_[0];
	
	if( ! defined( $data ) )
	{
		return( undef );
	}
	else
	{
		$data =~ s/\\ / /g;
		$data =~ s/\\\\/\\/g;
	}
	
	return( $data );
}

sub unescape_colons
{
	my $sub_name = 'unescape_colons';
	
	my $data = $_[0];
	
	if( ! defined( $data ) )
	{
		return( undef );
	}
	else
	{
		$data =~ s/\\:/:/g;
		$data =~ s/\\\\/\\/g;
	}
	
	return( $data );
}

sub extracttag
{
	my $sub_name = 'extracttag';
	
	# Seperate the tag from it's data and return them.  If there is a problem
	# this sub will return undef.  If a tag has no data then a zero length
	# string will be returned.
	
	my $__data = $_[0];
	my $ret_tag;
	my $ret_data;
	
	# Seperate out the tag from the data
	( $ret_tag, $ret_data ) = split( /\=/, $__data, 2 );
	
	if( length( $ret_tag ) > 0 )
	{
		if( defined( $ret_data ) )
		{
			$ret_data = unescape_spaces( $ret_data );
		}
		else
		{
			$ret_data = '';
		}
		
		return( $ret_tag, $ret_data );
	}
	else
	{
		return( undef );
	}
}

sub timestamp
{
	my $sub_name = 'timestamp';

	my $data = $_[0];
	my $format = $_[1];	# Maybe for future expansion.  Just thinking out loud.

	return( $data->{t} );
}

sub notice_type
{
	my $sub_name = 'notice_type';

	my $data = $_[0] || return( undef );

	return( $data->{no} );
}

sub notice_action
{
	my $sub_name = 'notice_action';

	my $data = $_[0] || return( undef );

	return( $data->{na} );
}

sub event_source
{
	my $sub_name = 'event_source';

	my $data = $_[0] || return( undef );
	
	if( exists( $data->{es} ) )
	{
		return( $data->{es} );
	}
	else
	{
		return( undef );
	}
}

sub source_addr
{
	my $sub_name = 'source_addr';

	my $data = $_[0] || return( undef );
	
	if( exists( $data->{sa} ) )
	{
		return( $data->{sa} );
	}
	else
	{
		return( undef );
	}
}

sub source_ip
{
	# This is for backwards compatibility and will be removed in the future
	&source_addr;
}

sub source_port
{
	my $sub_name = 'source_port';

	my $data = $_[0] || return( undef );

	if( exists( $data->{sp} ) )
	{
		return( $data->{sp} );
	}
	else
	{
		return( undef );
	}
}

sub destination_addr
{
	my $sub_name = 'destination_addr';

	my $data = $_[0] || return( undef );

	return( $data->{da} );
}

sub destination_ip
{
	# This is for backwards compatibility and will be removed in the future
	&destination_addr;
}

sub destination_port
{
	my $sub_name = 'destination_port';

	my $data = $_[0] || return( undef );
	
	if( exists( $data->{dp} ) )
	{
		return( $data->{dp} );
	}
	else
	{
		return( undef );
	}
}

sub user
{
	my $sub_name = 'user';

	my $data = $_[0] || return( undef );
	
	if( exists( $data->{user} ) )
	{
		return( $data->{user} );
	}
	else
	{
		return( undef );
	}
}

sub filename
{
	my $sub_name = 'filename';

	my $data = $_[0] || return( undef );
	
	if( exists( $data->{file} ) )
	{
		return( $data->{file} );
	}
	else
	{
		return( undef );
	}
}

sub sigid
{
	my $sub_name = 'sigid';
	
	&filename;
}

sub method
{
	my $sub_name = 'method';

	my $data = $_[0] || return( undef );

	if( exists( $data->{method} ) )
	{
		return( $data->{method} );
	}
	else
	{
		return( undef );
	}
}

sub url
{
	my $sub_name = 'url';

	my $data = $_[0] || return( undef );

	if( exists( $data->{url} ) )
	{
		return( $data->{url} );
	}
	else
	{
		return( undef );
	}
}

sub misc_integer
{
	my $sub_name = 'misc_integer';

	my $data = $_[0] || return( undef );

	if( exists( $data->{num} ) )
	{
		return( $data->{num} );
	}
	else
	{
		return( undef );
	}
}

sub count
{
	&misc_integer;
}

sub return_code
{
	&misc_integer;
}

sub message
{
	my $sub_name = 'message';

	my $data = $_[0] || return( undef );

	if( exists( $data->{msg} ) )
	{
		return( $data->{msg} );
	}
	else
	{
		return( undef );
	}
}

sub sub_message
{
	my $sub_name = 'sub_message';

	my $data = $_[0] || return( undef );

	if( exists( $data->{sub} ) )
	{
		return( $data->{sub} );
	}
	else
	{
		return( undef );
	}
}

sub tag
{
	my $sub_name = 'tag';
	
	my $data = $_[0] || return( undef );
	
	if( exists( $data->{tag} ) )
	{
		return( $data->{tag} );
	}
	else
	{
		return( undef );
	}
}

sub timerange
{
	my $sub_name = 'timerange';
	# Find the most likely beginning and ending times covered by a given
	# alarm file.

	my $filename = $_[0];
	my $start_time = 9999999999;
	my $end_time = -1;
	my $f_size = ( stat( $filename ) )[7];
	
	if( open( INFILE, $filename ) )
	{
		my $s_idx = 0;
		my $s_no_change = 0;

		# Find the smallest timestamp in the first 1000 lines.
		while( defined( my $ln = <INFILE> ) and
			( $s_idx < 1000 ) and
			( $s_no_change < 20 ) )
		{
			if( my $alarm_line = new( $ln ) )
			{
				my $w_timestamp = timestamp( $alarm_line );
				if( $w_timestamp < $start_time )
				{
					$start_time = $w_timestamp;
					$s_no_change = 0;
				}
				else
				{
					++$s_no_change;
				}
			}

			++$s_idx;
		}

		close( INFILE );

		# Find the largest timestamp in the last 1000 lines
		# Each connection with a status of "SF" will be counted as one line
		# Every line will be examined but the "SF" lines are the only ones
		# that give a good picture as to the time state of the file.
		if( sysopen( INFILE, $filename, 0 ) )
		{
			sysseek( INFILE, $f_size, 0 );
			my $cur_pos = sysseek( INFILE, 0, 1 );
			my $nl_pos = $cur_pos;
			my $line_count = 0;
			my $e_no_change = 0;

			# Get last 1000 lines
			while( $line_count < 1000 and $e_no_change < 20 )
			{
				my $new_line_found = 0;
				my $buf;
				sysread( INFILE, $buf, 1 );

				if( $cur_pos > -1 )
				{
					if( $buf eq $/ )
					{
						$new_line_found = 1;
					}
				}
				else
				{
					# Must have hit the beginning of the file
					if( $nl_pos > 20 )
					{
						$cur_pos = 0;
						sysseek( INFILE, 0, 0 );
						$new_line_found = 1;
					}
					else
					{
						last;
					}
				}

				if( $new_line_found )
				{
					my $cur_line = '';
					sysread( INFILE, $cur_line, $nl_pos - $cur_pos );
					if( my $alarm_line = new( $cur_line ) )
					{
						my $w_timestamp = timestamp( $alarm_line );
						if( $w_timestamp > $end_time )
						{
							$end_time = $w_timestamp;
						}
						else
						{
							++$e_no_change;
						}
					}
					$nl_pos = $cur_pos;
					++$line_count;
				}
				--$cur_pos;
				if( $cur_pos < 0 )
				{
					last;
				}
				sysseek( INFILE, $cur_pos, 0 );
			}

		}
		else
		{
			warn( __PACKAGE__ . "::$sub_name, Unable to open file '$filename' with sysread.\n" );
			return( undef );
		}

		close( INFILE );
	}
	else
	{
		warn( __PACKAGE__ . "::$sub_name, Unable to open file '$filename'.\n" );
		return( undef );
	}
	
	# Make sure that sane values were found for the start and end times
	if( $start_time == 9999999999 or $end_time == -1 )
	{
		# warn( __PACKAGE__ . "::$sub_name, There was an error determining the start and end ranges.\n" );
		# warn( "No valid values could be found.\n" );
		return( undef );
	}
	
	return( $start_time, $end_time );
}
