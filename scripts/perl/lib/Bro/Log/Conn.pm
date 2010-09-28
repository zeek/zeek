package Bro::Log::Conn;

require 5.006_001;
use strict;

use vars qw( $VERSION
		$NULL_VALUE
		$DEBUG );

# $Id: Conn.pm 1426 2005-09-30 00:19:18Z rwinslow $
$VERSION = 1.20;
$NULL_VALUE = -1;
$DEBUG = 0;

my $CONN_SPLIT_PATT = ' ';
# my $CONN_SPLIT_PATT = qr/ /o;

# Map data descriptions to subroutine names
my %DATA_MAP = ( timestamp => \&timestamp,
			duration => \&duration,
			source_ip => \&srcip,
			srcip => \&srcip,
			destination_ip => \&dstip,
			dstip => \&dstip,
			service => \&service,
			source_port => \&srcport,
			srcport => \&srcport,
			destination_port => \&dstport,
			dstport => \&dstport,
			protocol => \&protocol,
			source_bytes => \&srcbytes,
			srcbytes => \&srcbytes,
			destination_bytes => \&srcbytes,
			dstbytes => \&dstbytes,
			connection_status => \&connstat,
			connstat => \&connstat,
			source_network => \&srcnetwork,
			srcnetwork => \&srcnetwork,
			other => \&other,
			);

sub new
{
	my $_log_line = $_[0] || return( undef );	# string ref

	# Order of data in array
	# 0 = timestamp
	# 1 = duration
	# 2 = source ip
	# 3 = destination ip
	# 4 = service
	# 5 = source port
	# 6 = destination port
	# 7 = protocol
	# 8 = source bytes
	# 9 = destination bytes
	# 10 = connection status
	# 11 = source network
	# 12 = other

	my @log_parts = split( $CONN_SPLIT_PATT, $$_log_line, 13 );
	if( defined( $log_parts[11] ) )
	{
		return( \@log_parts );
	}
	else
	{
		return( undef );
	}
}

sub output
{
	my $sub_name = 'output';

	my $data = $_[0] || return undef;
	my $format = $_[1] || '';
	my @ret_data;

	if( ref( $format ) ne 'ARRAY' )
	{
		$format = [ 'timestamp',
				'duration',
				'srcip',
				'dstip',
				'service',
				'srcport',
				'dstport',
				'protocol',
				'srcbytes',
				'dstbytes',
				'connstat',
				'srcnetwork',
				'other',
				];
	}
	
	my $i = 0;
	foreach my $key( @{$format} )
	{
		if( exists( $DATA_MAP{$key} ) )
		{
			$ret_data[$i] = &{$DATA_MAP{$key}}( $data );
			++$i;
		}
		else
		{
			return( undef );
		}
	}
	
	if( wantarray )
	{
		return( @ret_data );
	}
	else
	{
		return( join( ' ', @ret_data ) );
	}
}

sub timestamp
{
	my $sub_name = 'timestamp';
	
	my $data = $_[0] || return( undef );
	
	return( $data->[0] );
}

sub duration
{
	my $sub_name = 'duration';

	my $data = $_[0] || return undef;
	my $arg1 = $_[1] || 0;

	if( $arg1 eq 'raw' )
	{
		return( $data->[1] );
	}
	elsif( $data->[1] eq '?' and defined( $NULL_VALUE ) )
	{
		return( $NULL_VALUE );
	}
	else
	{
		return( $data->[1] );
	}
}

sub source_ip
{
	&srcip;
}

sub srcip
{
	my $sub_name = 'srcip';

	return( $_[0]->[2] );
}

sub destination_ip
{
	&dstip;
}

sub dstip
{
	my $sub_name = 'dstip';

	return( $_[0]->[3] );
}

sub service
{
	my $sub_name = 'service';

	return( $_[0]->[4] );
}

sub source_port
{
	&srcport;
}

sub srcport
{
	my $sub_name = 'srcport';

	return( $_[0]->[5] );
}

sub destination_port
{
	&dstport
}

sub dstport
{
	my $sub_name = 'dstport';

	return( $_[0]->[6] );
}

sub protocol
{
	my $sub_name = 'protocol';

	return( $_[0]->[7] );
}

sub source_bytes
{
	&srcbytes;
}

sub srcbytes
{
	my $sub_name = 'srcbytes';

	my $data = $_[0] || return undef;
	my $arg1 = $_[1] || 0;

	if( $arg1 eq 'raw' )
	{
		return( $data->[8] );
	}
	elsif( $data->[8] eq '?' and defined( $NULL_VALUE ) )
	{
		return( $NULL_VALUE );
	}
	elsif( $data->[10] eq 'SF') 
	{
		# safest to only count sessions with normal termination
		return( $data->[8] );
	}
	else
	{
		return( $NULL_VALUE );
	}
}

sub destination_bytes
{
	&dstbytes;
}

sub dstbytes
{
	my $sub_name = 'dstbytes';

	my $data = $_[0] || return undef;
	my $arg1 = $_[1] || 0;

	if( $arg1 eq 'raw' )
	{
		return( $data->[9] );
	}
	elsif( $data->[9] eq '?' and defined( $NULL_VALUE ) )
	{
		return( $NULL_VALUE );
	}
	elsif( $data->[10] eq 'SF' )
	{
		# safest to only count sessions with normal termination
		return( $data->[9] );
	}
	else
	{
		return( $NULL_VALUE );
	}
}

sub connstat
{
	my $sub_name = 'connstat';

	my $data = $_[0] || return undef;
	
	return( $data->[10] );
}

sub source_network
{
	&srcnetwork;
}

sub srcnetwork
{
	my $sub_name = 'srcnetwork';

	my $data = $_[0] || return undef;
	chomp( $data->[11] );
	
	return( $data->[11] );
}

sub tag
{
	my $sub_name = 'tag';
	
	my $data = $_[0] || return( undef );
	my $other_field = $data->[12];
	my @ret_tag_ids;
	
	while( $other_field =~ s/(\@[[:digit:]]+)// )
	{
		push( @ret_tag_ids, $1 );
	}
	
	if( @ret_tag_ids > 0 )
	{
		if( wantarray )
		{
			return( @ret_tag_ids );
		}
		else
		{
			return( \@ret_tag_ids );
		}
	}
	else
	{
		return( undef );
	}
}

sub other
{
	my $sub_name = 'other';

	my $data = $_[0] || return undef;

	# Remove any newline character at the end
	chomp( $data->[12] );

	return( $data->[12] );
}

sub timerange
{
	my $sub_name = 'timerange';
	# Find the most likely beginning and ending times covered by a given
	# conn file.

	my $filename = $_[0];
	my $find_start_time = $_[1];
	my $find_end_time = $_[2];
	my $start_time = 9999999999;
	my $end_time = -1;
	my $max_start_lines = 10000;
	my $max_end_lines = 10000;
	my $max_line_length = 5000;
	my $f_size = ( stat( $filename ) )[7] || 0;
	my $default_start;
	my $default_end;
	
	if( $DEBUG > 2 )
	{
		warn( __PACKAGE__ . "::$sub_name, Filename: $filename\n" );
	}
	
	# If the file is zero size then don't even both continuing
	if( $f_size < 1 )
	{
		if( $DEBUG > 2 )
		{
			warn( __PACKAGE__ . "::$sub_name, File is zero size, skipping\n" );
		}
		return( undef );
	}
	
	# If $find_start_time and $find_end_time are defined then the the first
	# line that is greater than or equal to the timestamp in $find_start_time
	# will be read by seek and then set into $start_pos.
	# The last line that contains a timestamp less than or equal to 
	# $find_end_time will be read by seek and then set in $end_pos.
	eval {
	local $SIG{ALRM} = sub { die( "Alarm Timeout\n" ) };
	alarm 90;
	if( open( INFILE, $filename ) )
	{
		my $s_idx = 0;			# start line counter
		my $s_no_change = 0;	# start no change counter
		
		# Set the very first connection timestamp to $default_start
		while( ! $default_start and defined( my $line = <INFILE> ) )
		{
			if( my $conn_line = new( \$line ) )
			{
				$default_start = timestamp( $conn_line );
			}
		}
		
		# Find the smallest timestamp in the first 1000 lines where the
		# connection is complete (SF) or (REJ) and the duration is less
		# than .1 seconds
		while( ( $s_idx < $max_start_lines ) and
			( $s_no_change < 20 ) and
			defined( my $ln = <INFILE> ) )
		{
			if( my $conn_line = new( \$ln ) )
			{
				if( connstat( $conn_line ) =~ m/^(?:SF)|(?:REJ)$/ )
				{
					if( duration( $conn_line ) < 0.1 )
					{
						my $w_timestamp = timestamp( $conn_line );
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
				}
			}

			++$s_idx;
		}
		
		close( INFILE );
		
		# Find the largest timestamp in the last 20 lines
		# Each connection with a status of "SF" or "REJ" will be counted as
		# one line.  Every line will be examined but the "SF" or "REJ"
		# lines are the only ones that give a good picture as to the time
		# state of the file.
		if( sysopen( INFILE, $filename, 0 ) )
		{
			sysseek( INFILE, $f_size, 0 );
			my $cur_pos = sysseek( INFILE, 0, 1 );
			my $nl_pos = $cur_pos;
			my $matched_count = 0;
			my $line_count = 0;

			# Get last 20 lines
			while( $matched_count < 20 and
				$line_count < $max_end_lines )
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
					if( $nl_pos > 20 )	# supress things like blank lines
					{
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
					++$line_count;
					# Make sure that the line is not too large
					# Fix for some funky rsync errors that may occur
					if( $nl_pos - $cur_pos > $max_line_length )
					{
						# WAY too big, just mark new position and ignore
					}
					else
					{
						sysread( INFILE, $cur_line, $nl_pos - $cur_pos );
						if( my $conn_line = new( \$cur_line ) )
						{
							if( ! $default_end )
							{
								$default_end = timestamp( $conn_line );
							}
							
							if( duration( $conn_line ) < 0.1 and duration( $conn_line ) >= 0 )
							{
								my $w_timestamp = timestamp( $conn_line );
								if( $w_timestamp > $end_time )
								{
									$end_time = $w_timestamp;
								}
							}
							
							if( connstat( $conn_line ) =~ m/^(?:SF)|(?:REJ)$/ )
							{
								++$matched_count;
							}
						}
					}
					$nl_pos = $cur_pos;
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
			if( $DEBUG > 0 )
			{
				warn( __PACKAGE__ . "::$sub_name, Unable to open file '$filename' with sysread.\n" );
			}
			return( undef );
		}

		close( INFILE );
	}
	else
	{
		if( $DEBUG > 0 )
		{
			warn( __PACKAGE__ . "::$sub_name, Unable to open file '$filename'.\n" );
		}
		return( undef );
	}
	
	close( INFILE );
	};
	
	alarm 0;
	
	# Make sure that $start_time has something other than the filler value.
	if( $start_time == 9999999999 )
	{
		if( $default_start )
		{
			$start_time = $default_start;
			if( $DEBUG > 1 )
			{
				warn( __PACKAGE__ . "::$sub_name, No start_time was found, setting to a default of $default_start\n" );
			}
		}
		else
		{
			if( $DEBUG > 1 )
			{
				warn( __PACKAGE__ . "::$sub_name, No start_time was found and no default_start time was found\n" );
			}
		}
	}
	
	# Make sure that $end_time has something other than the filler value.
	if( $end_time == -1 )
	{
		if( $default_end )
		{
			$end_time = $default_end;
			if( $DEBUG > 1 )
			{
				warn( __PACKAGE__ . "::$sub_name, No end_time was found, setting to a default of $default_start\n" );
			}
		}
		else
		{
			if( $DEBUG > 1 )
			{
				warn( __PACKAGE__ . "::$sub_name, No end_time was found and no default_end time was found\n" );
			}
		}
	}
	
	if( $DEBUG > 2 )
	{
		warn( "  " . __PACKAGE__ . "::$sub_name, Start time: $start_time\n" );
		warn( "  " . __PACKAGE__ . "::$sub_name, End time: $end_time\n" );
	}
	
	if( $@ )
	{
		if( $@ =~ m/Alarm Timeout/ )
		{
			if( !( $start_time and $end_time ) )
			{
				if( $DEBUG > 0 )
				{
					warn( __PACKAGE__ . "::$sub_name, Error occurred in trying to read the file $filename\n" );
				}
				return( undef );
			}
			else
			{
				if( $DEBUG > 0 )
				{
					warn( __PACKAGE__ . "::$sub_name, Timed out during file read.  The first and last timestamps have been set as the range of time available\n" );
				}
			}
		}
		else
		{
			warn( $@ );
			return( undef );
		}
	}
	
	return( $start_time, $end_time );
}

sub containstag
{
	my $sub_name = 'containstag';
	
	my $data = shift || return( undef );
	my @tags_to_match = @_;
	my $conn_tags = tag( $data ) || return( 0 );
	my $matched_tag = 0;
	
	OUT_LOOP:
	{
		foreach my $tag_to_match( @tags_to_match )
		{
			foreach my $tag_id( @{$conn_tags} )
			{
				if( $tag_id eq $tag_to_match )
				{
					$matched_tag = $tag_id;
					last OUT_LOOP;
				}
			}
		}
	}	# end OUT_LOOP
	
	return( $matched_tag );
}

sub startposition
{
	my $sub_name = 'startposition';
	# Find the first file position where $timestamp is greater than or equal to
	# a timestamp in the file.
	my $timestamp = $_[0];
}

sub endposition
{
	my $sub_name = 'endposition';
	# Find the last file position where $timestamp is less than or equal to
	# a timestamp in a file.
	my $timestamp = $_[0];
}

sub connectsucceed
{
	my $sub_name = 'connectsucceed';
	
	my $data = $_[0] || return( undef );
	
	my $S_REGEX = qr/^S/o;
	my $S123_REGEX = qr/^S[123]$/o;
	my $connstat = connstat( $data );
	
	if( $connstat =~ $S_REGEX )
	{
		if( $connstat eq 'SF' )
		{
			return( 1 );
		}
		elsif( $connstat =~ $S123_REGEX )
		{
			if( srcbytes( $data ) > 0 && dstbytes( $data ) > 0 )
			{
				return( 1 );
			}
			else
			{
				return( 0 );
			}
		}
	}
	else
	{
		# connection failed
		return( 0 );
	}
}

sub range
{
	my $sub_name = 'range';
	
	my $data = $_[0] || return( undef );
	my $match_time = $_[1];
	my $error_margin = $_[2];
	my $start_time;
	my $end_time;
	my $duration;
	
	# Make sure that the error margin is greater than zero
	if( !( defined( $error_margin ) and $error_margin > 0 ) )
	{
		$error_margin = 0;
	}
	
	$start_time = timestamp( $data );
	$duration = duration( $data );
	
	if( $match_time )
	{
		if( $duration < 0 )
		{
			$duration = 10;
		}
	
		$end_time = $start_time + $duration + $error_margin;
		$start_time = $start_time - $error_margin;
		
		if( $match_time >= $start_time and
			$match_time <= $end_time )
		{
			return( 1 );
		}
		else
		{
			return( 0 );
		}
	}
	else
	{
		if( $duration > -1 )
		{
			$end_time = $start_time + $duration;
		}
		
		return( $start_time, $end_time );
	}
}

1;

# The args to Bro::Log::Conn::output are the connection array ref returned by
 # Bro::Log::Conn::new and an optional array ref of what order and fields
 # should be printed.

# EXAMPLE:
 # $array_ref = Bro::Log::Conn::new( $ln );
 # @output_parts = Bro::Log::Conn::output( $array_ref, [ 'srcip', 'dstip', 'timestamp' ] )
 #
 # The available fields are as follows:
 #	timestamp
 #	duration
 #	srcip
 #	dstip
 #	service
 #	srcport
 #	dstport
 #	protocol
 #	srcbytes
 #	dstbytes
 #	connstat
 #	srcnetwork
 #	other

# For convenience any data that is represented by a ? will be replaced by a -1
# This occurs for duration, srcbytes, and dstbytes
# This is adjustable by changing $NULL_VALUE
