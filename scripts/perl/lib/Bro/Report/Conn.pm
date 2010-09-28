package Bro::Report::Conn;

use strict;
require 5.006_001;
use Bro::Report qw( trimhostname iptoname swrite trimbytes );
use Bro::Log::Conn;

use vars qw( $VERSION
			$MAX_LOCAL_SERVICE_USERS );

# $Id: Conn.pm 1418 2005-09-29 18:25:09Z tierney $
$VERSION = 1.20;

$MAX_LOCAL_SERVICE_USERS = 50;

my %REPORT_MAP = ( 'top_sources' => { input => __PACKAGE__ . '::sourcecount',
							output => __PACKAGE__ . '::output_sourcecount' },
		'top_destinations' => { input => __PACKAGE__ . '::destcount',
							output => __PACKAGE__ . '::output_destcount' },
		'top_services' => { input => __PACKAGE__ . '::servicecount',
						output => __PACKAGE__ . '::output_servicecount', },
		'top_local_service_users' => { input => __PACKAGE__ . '::localserviceusers',
								output => __PACKAGE__ . '::output_localserviceusers', },
		'success_fail_stats' => { input => __PACKAGE__ . '::successfailcount',
							output => __PACKAGE__ . '::output_successfailcount', },
		'byte_transfer_pairs' => { input => __PACKAGE__ . '::bytetransferpairs',
						output => __PACKAGE__ . '::output_bytetransferpairs', },
		);

# Memory used in this variable will be deleted by functions which output
# the values stored for it's respective counting function.
my $RPT_CACHE;

sub sourcecount
{
	my $sub_name = 'sourcecount';
	
	# [0] CONN_COUNT
	# [1] BYTE_COUNT
	my $_conn_struc = $_[0] || return( undef );
	my $src_ip = Bro::Log::Conn::source_ip( $_conn_struc ) || return( undef );
	if( Bro::Log::Conn::connectsucceed( $_conn_struc ) )
	{
		my $bytes = Bro::Log::Conn::source_bytes( $_conn_struc );
		++$RPT_CACHE->{$sub_name}->{$src_ip}->[0];
		$RPT_CACHE->{$sub_name}->{$src_ip}->[1] += $bytes;
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub output_sourcecount
{
	my $sub_name = 'output_sourcecount';
	
	my $_max_output = $_[0] || 20;
	my $top_format = $_[1];
	my $format = $_[2];
	my $conn_sum = 0;
	my $cnt = 0;
	my $avg = 0;
	my $max_hostname_length = 31;
	my @results;
	my $ret_string;
	my @heading_names = ( 'Host', 'IP', 'Bytes', 'Conn. Count' );
	
	if( ! $top_format )
	{
		$top_format = <<'END'
  @||||||||||||||||||||||||||||||  @||||||||||||||  @|||||  @|||||||||||
  -------------------------------  ---------------  ------  ------------
END
	}
	
	if( ! $format )
	{
		$format = <<'END'
  @>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>  @<<<<<<<<<<<<<<  @>>>>>  @>>>>>>>>>>>
END
	}
	
	# Figure out what the average count is
	foreach my $count_struc( values( %{$RPT_CACHE->{sourcecount}} ) )
	{
		$conn_sum += $count_struc->[0];
		++$cnt
	}
	
	# If there are no connection counts then bail
	if( $cnt < 1 )
	{
		return( undef );
	}
	
	$avg = $conn_sum / $cnt;
	
	# remove anything which is way too small before sorting
	my $smallest_count = 2;
	my $percent_of_avg = .1;
	my $max_sort_size = $_max_output * 2;
	while( ( $cnt > $max_sort_size ) and ( $percent_of_avg < .3 ) )
	{
		while( my( $ip, $struc ) = each( %{$RPT_CACHE->{sourcecount}} ) and $cnt > $max_sort_size )
		{
			if( $struc->[0] < $smallest_count )
			{
				delete( $RPT_CACHE->{sourcecount}->{$ip} );
				--$cnt;
			}
			$smallest_count = int( $avg * $percent_of_avg );
		}
		$percent_of_avg += .1;
	}
	
	# Put the remaining data into a temp hash for sorting
	my %count_hash;
	foreach my $ip( keys( %{$RPT_CACHE->{sourcecount}} ) )
	{
		# connection count = $RPT_CACHE->{sourcecount}->{$ip}->[0];
		# byte count = $RPT_CACHE->{sourcecount}->{$ip}->[1];
		push( @{$count_hash{$RPT_CACHE->{sourcecount}->{$ip}->[0]}},
			[ $ip, $RPT_CACHE->{sourcecount}->{$ip}->[0], $RPT_CACHE->{sourcecount}->{$ip}->[1] ] );
	}
	
	my $output_cnt = 0;
	foreach my $num_conn( sort { $b <=> $a } keys( %count_hash ) )
	{
		foreach my $struc( @{$count_hash{$num_conn}} )
		{
			++$output_cnt;
			if( $output_cnt > $_max_output )
			{
				last;
			}
			else
			{
				push( @results, $struc );
			}
		}
		if( $output_cnt > $_max_output )
		{
			last;
		}
	}
	
	# clear out memory space
	delete( $RPT_CACHE->{sourcecount} );
	
	# Set the heading
	$ret_string .= swrite( $top_format, @heading_names );
	
	# Write the contents
	foreach my $line( @results )
	{
		my $ip = $line->[0];
		my $num_conn = $line->[1];
		my $num_bytes = trimbytes( $line->[2], 5 );
		my $name = trimhostname( iptoname( $ip ), $max_hostname_length, '>' );
		$ret_string .= swrite( $format, $name, $ip, $num_bytes, $num_conn );
	}
	
	return( $ret_string );
}

sub destcount
{
	my $sub_name = 'destcount';
	
	my $_conn_struc = $_[0] || return( undef );
	my $dst_ip = Bro::Log::Conn::destination_ip( $_conn_struc ) || return( undef );
	if( Bro::Log::Conn::connectsucceed( $_conn_struc ) )
	{
		my $bytes = Bro::Log::Conn::destination_bytes( $_conn_struc );
		++$RPT_CACHE->{$sub_name}->{$dst_ip}->[0];
		$RPT_CACHE->{$sub_name}->{$dst_ip}->[1] += $bytes;
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub output_destcount
{
	my $sub_name = 'output_destcount';
	
	my $_max_output = $_[0] || 20;
	my $top_format = $_[1];
	my $format = $_[2];
	my $conn_sum = 0;
	my $cnt = 0;
	my $avg = 0;
	my $max_hostname_length = 31;
	my @results;
	my $ret_string;
	my @heading_names = ( 'Host', 'IP', 'Bytes', 'Conn. Count' );
	
	if( ! $top_format )
	{
		$top_format = <<'END'
  @||||||||||||||||||||||||||||||  @||||||||||||||  @|||||  @|||||||||||
  -------------------------------  ---------------  ------  ------------
END
	}
	
	if( ! $format )
	{
		$format = <<'END'
  @>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>  @<<<<<<<<<<<<<<  @>>>>>  @>>>>>>>>>>>
END
	}
	
	# Figure out what the average count is
	foreach my $count_struc( values( %{$RPT_CACHE->{destcount}} ) )
	{
		$conn_sum += $count_struc->[0];
		++$cnt
	}
	
	# If there are no connection counts then bail
	if( $cnt < 1 )
	{
		return( undef );
	}
	
	$avg = $conn_sum / $cnt;
	
	# remove anything which is way too small before sorting
	my $smallest_count = 2;
	my $percent_of_avg = .1;
	my $max_sort_size = $_max_output * 2;
	while( ( $cnt > $max_sort_size ) and ( $percent_of_avg < .3 ) )
	{
		while( my( $ip, $struc ) = each( %{$RPT_CACHE->{destcount}} ) and $cnt > $max_sort_size )
		{
			if( $struc->[0] < $smallest_count )
			{
				delete( $RPT_CACHE->{destcount}->{$ip} );
				--$cnt;
			}
			$smallest_count = int( $avg * $percent_of_avg );
		}
		$percent_of_avg += .1;
	}
	
	# Put the remaining data into a temp hash for sorting
	my %count_hash;
	foreach my $ip( keys( %{$RPT_CACHE->{destcount}} ) )
	{
		# connection count = $RPT_CACHE->{destcount}->{$ip}->{CONN_COUNT};
		# byte count = $RPT_CACHE->{destcount}->{$ip}->{BYTE_COUNT};
		push( @{$count_hash{$RPT_CACHE->{destcount}->{$ip}->[0]}},
			[ $ip, $RPT_CACHE->{destcount}->{$ip}->[0], $RPT_CACHE->{destcount}->{$ip}->[1] ] );
	}
	
	my $output_cnt = 0;
	foreach my $num_conn( sort { $b <=> $a } keys( %count_hash ) )
	{
		foreach my $struc( @{$count_hash{$num_conn}} )
		{
			++$output_cnt;
			if( $output_cnt > $_max_output )
			{
				last;
			}
			else
			{
				push( @results, $struc );
			}
		}
		if( $output_cnt > $_max_output )
		{
			last;
		}
	}
	
	# clear out memory space
	delete( $RPT_CACHE->{destcount} );
	
	# Set the heading
	$ret_string .= swrite( $top_format, @heading_names );
	
	# Write the contents
	foreach my $line( @results )
	{
		my $ip = $line->[0];
		my $num_conn = $line->[1];
		my $num_bytes = trimbytes( $line->[2], 5 );
		my $name = trimhostname( iptoname( $ip ), $max_hostname_length, '>' );
		$ret_string .= swrite( $format, $name, $ip, $num_bytes, $num_conn );
	}
	
	return( $ret_string );
}

sub servicecount
{
	my $sub_name = 'servicecount';
	
	# [0] CONN_COUNT
	# [1] BYTES_IN
	# [2] BYTES_OUT
	
	my $_conn_struc = $_[0] || return( undef );
	my $service = Bro::Log::Conn::service( $_conn_struc ) || return( undef );
	if( Bro::Log::Conn::connectsucceed( $_conn_struc ) )
	{
		my $src_bytes = Bro::Log::Conn::source_bytes( $_conn_struc );
		my $dest_bytes = Bro::Log::Conn::destination_bytes( $_conn_struc );
		++$RPT_CACHE->{$sub_name}->{$service}->[0];
		if( Bro::Log::Conn::source_network( $_conn_struc ) eq 'L' )
		{
			$RPT_CACHE->{$sub_name}->{$service}->[1] += $dest_bytes;
			$RPT_CACHE->{$sub_name}->{$service}->[2] += $src_bytes;
		}
		else
		{
			$RPT_CACHE->{$sub_name}->{$service}->[1] += $src_bytes;
			$RPT_CACHE->{$sub_name}->{$service}->[2] += $dest_bytes;
		}
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub output_servicecount
{
	my $sub_name = 'output_servicecount';
	
	my $_max_output_count = $_[0] || 20;
	my $top_format;
	my $format;
	my @results;
	my @heading_names = ( 'Service', 'Conn. Count', '% of Total', 'Bytes In', 'Bytes Out' );
	my $ret_string;
	
	if( ! $top_format )
	{
		$top_format = <<'END'
  @<<<<<<<<<<<  @>>>>>>>>>>>  @>>>>>>>>>  @>>>>>>>>  @>>>>>>>>
  ------------  ------------  ----------  ---------  ---------
END
	}
	
	if( ! $format )
	{
		$format = <<'END'
  @<<<<<<<<<<<  @>>>>>>>>>>>  @>>>>>>>>>  @>>>>>>>>  @>>>>>>>>
END
	}
	
	my %count_hash;
	my $total_count = 0;
	while( my( $name, $struc ) = each( %{$RPT_CACHE->{servicecount}} ) )
	{
		$total_count += $struc->[0];
		push( @{$count_hash{$struc->[0]}}, 
			[ $name, $struc->[1], $struc->[2] ] );
	}
	
	my $ret_count = 0;
	foreach my $num( sort { $b <=> $a } keys( %count_hash ) )
	{
		if( $ret_count < $_max_output_count )
		{
			foreach my $struc( @{$count_hash{$num}} )
			{
				if( $ret_count < $_max_output_count )
				{
					my $avg_of_total = sprintf( "%.2f", $num / $total_count * 100 );
					my $service = $struc->[0];
					my $bytes_in = trimbytes( $struc->[1], 5 );
					my $bytes_out = trimbytes( $struc->[2], 5 );
					push( @results, [ $service, $num, $avg_of_total, $bytes_in, $bytes_out ] );
					++$ret_count;
				}
				else
				{
					last;
				}
			}
		}
		else
		{
			last;
		}
	}
	
	# Clean up some memory
	delete( $RPT_CACHE->{servicecount} );
	
	# Print the heading
	$ret_string .= swrite( $top_format, @heading_names );
	
	foreach my $line( @results )
	{
		$ret_string .= swrite( $format, @{$line} );
	}
	
	return( $ret_string );
}

sub localserviceusers
{
	my $sub_name = 'localserviceusers';
	
	my $_conn_struc = $_[0] || return( undef );
	my $service_name = $_[1] || 'smtp';
	
	my $service = Bro::Log::Conn::service( $_conn_struc );
	
	if( $service eq $service_name )
	{
		my $src_net = Bro::Log::Conn::source_network( $_conn_struc );
		
		if( $src_net eq 'L' and Bro::Log::Conn::connectsucceed( $_conn_struc ) )
		{
			my $source_ip = Bro::Log::Conn::source_ip( $_conn_struc );
			++$RPT_CACHE->{$sub_name}->{$service_name}->{$source_ip};
		}
	}
	
	return( 1 );
}

sub output_localserviceusers
{
	my $sub_name = 'output_localserviceusers';
	
	my $service_name = $_[0] || return( undef );
	my $max_count = $_[1] || $MAX_LOCAL_SERVICE_USERS;
	my $top_format;
	my $format;
	my @results;
	my $ret_string;
	my @heading_names = ( 'Hostname', 'IP', 'Conn. Count' );
	my $total_count = keys( %{$RPT_CACHE->{localserviceusers}->{$service_name}} );
	my $max_hostname_length = 39;
	my $actual_count = 0;

	if( ! $top_format )
	{
		$top_format = <<'END'
  @||||||||||||||||||||||||||||||||||||||  @||||||||||||||  @>>>>>>>>>>>
  ---------------------------------------  ---------------  ------------
END
	}
	
	if( ! $format )
	{
		$format = <<'END'
  @>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>  @<<<<<<<<<<<<<<  @>>>>>>>>>>>
END
	}
	
	my %count_hash;
	while( my( $key, $val ) = each( %{$RPT_CACHE->{localserviceusers}->{$service_name}} ) )
	{
		push( @{$count_hash{$val}}, $key );
	}
	
	foreach my $num( sort { $b <=> $a } keys( %count_hash ) )
	{
		foreach my $ip( @{$count_hash{$num}} )
		{
			if( $actual_count + 1 > $max_count )
			{
				last;
			}
			$results[$actual_count] = [ $ip, $num ];
			++$actual_count;
		}
	}
	
	# Clean up some memory usage
	delete( $RPT_CACHE->{localserviceusers}->{$service_name} );
	
	# Set the heading
	$ret_string .= swrite( $top_format, @heading_names );
	
	# Write the contents
	foreach my $line( @results )
	{
		# my $ip = $line->[0];
		# my $num_conn = $line->[1];
		my $name = trimhostname( iptoname( $line->[0] ), $max_hostname_length, '>' );
		$ret_string .= swrite( $format, $name, $line->[0], $line->[1] );
	}
	
	if( $actual_count > 0 )
	{
		if( $total_count > $max_count )
		{
			my $not_listed = $total_count - $max_count;
			$ret_string .= <<"END";

  A maximum of $max_count entries are show.
  There are another $not_listed that are not displayed.
END
		}
	}
	else
	{
		$ret_string = "\n  No data to report for this section\n";
	}
	
	return( $ret_string );
}

sub successfailcount
{
	my $sub_name = 'successfailcount';
	
	my $_conn_struc = $_[0] || return( undef );
	
	if( Bro::Log::Conn::connectsucceed( $_conn_struc ) )
	{
		++$RPT_CACHE->{$sub_name}->{SUCCESS};
	}
	else
	{
		# connection is failed
		++$RPT_CACHE->{$sub_name}->{FAIL};
	}
}

sub output_successfailcount
{
	my $sub_name = 'output_successfailcount';
	
	my $format = $_[0];
	my $ret_string;
	
	if( ! $format )
	{
		$format = <<'END'
    Successful:   @<<<<<<<<<<<<<<<
    Unsuccessful: @<<<<<<<<<<<<<<<
    Ratio: @<<<<<<
END
	}
	
	# Success and fail counts must be greater than zero
	if( $RPT_CACHE->{successfailcount}->{FAIL} < 1 or
		$RPT_CACHE->{successfailcount}->{SUCCESS} < 1 )
	{
		return( 'undef' );
	}
	my $ratio = $RPT_CACHE->{successfailcount}->{FAIL} / $RPT_CACHE->{successfailcount}->{SUCCESS};
	
	$ret_string = swrite( $format, 
		$RPT_CACHE->{successfailcount}->{SUCCESS},
		$RPT_CACHE->{successfailcount}->{FAIL},
		"1:$ratio" );
	
	return( $ret_string );
}

sub bytetransferpairs
{
	my $sub_name = 'bytetransferpairs';
	
	# This report can be very memory expensive.  It can also be very processor
	# intesive as the hash tables can get very large and take longer and 
	# longer to traverse.
	
	my $conn_struc = $_[0] || return( undef );
	
	my $local_host;
	my $remote_host;
	my $local_bytes;
	my $remote_bytes;
	
	if( Bro::Log::Conn::source_network( $conn_struc ) eq 'L' )
	{
		$local_host = Bro::Log::Conn::source_ip( $conn_struc );
		$remote_host = Bro::Log::Conn::destination_ip( $conn_struc );
		$local_bytes = Bro::Log::Conn::source_bytes( $conn_struc );
		$remote_bytes = Bro::Log::Conn::destination_bytes( $conn_struc );
	}
	else
	{
		$remote_host = Bro::Log::Conn::source_ip( $conn_struc );
		$local_host = Bro::Log::Conn::destination_ip( $conn_struc );
		$remote_bytes = Bro::Log::Conn::source_bytes( $conn_struc );
		$local_bytes = Bro::Log::Conn::destination_bytes( $conn_struc );
	}
	
	if( $local_bytes > 0 and $remote_bytes > 0 )
	{
		$RPT_CACHE->{bytetransferpairs}->{$local_host}->{$remote_host}->{LOCAL_BYTES} += $local_bytes;
		$RPT_CACHE->{bytetransferpairs}->{$local_host}->{$remote_host}->{REMOTE_BYTES} += $remote_bytes;
		++$RPT_CACHE->{bytetransferpairs}->{$local_host}->{$remote_host}->{CONN_COUNT};
		return( 1 );
	}
	elsif( exists( $RPT_CACHE->{bytetransferpairs}->{$local_host} ) and
		exists( $RPT_CACHE->{bytetransferpairs}->{$local_host}->{$remote_host} ) )
	{
		$RPT_CACHE->{bytetransferpairs}->{$local_host}->{$remote_host}->{LOCAL_BYTES} += $local_bytes || 0;
		$RPT_CACHE->{bytetransferpairs}->{$local_host}->{$remote_host}->{REMOTE_BYTES} += $remote_bytes || 0;
		++$RPT_CACHE->{bytetransferpairs}->{$local_host}->{$remote_host}->{CONN_COUNT};
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub output_bytetransferpairs
{
	my $sub_name = 'output_bytetransferpairs';
        my $max_hostname_length = 22;
	
	my $max_output = $_[0] || 20;
	
	my $ret_string;
	my $_base = $RPT_CACHE->{bytetransferpairs};
	my %reversed_hash;
	my @ordered_list;
	my $top_format;
	my $format;
	
	$top_format = <<"END";
Hot Report - Top $max_output
                                                    Local      Remote    Conn.
     Local Host               Remote Host           Bytes      Bytes     Count
-----------------------  -----------------------  ---------  ---------  -------
END
	
	$format = <<'END';
@<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<<<<<<<<  @>>>>>>>>  @>>>>>>>>  @<<<<<<<<
END

	foreach my $l_host( keys( %{$_base} ) )
	{
		foreach my $r_host( keys( %{$_base->{$l_host}} ) )
		{
			my $big_bytes;
			if( $_base->{$l_host}->{$r_host}->{LOCAL_BYTES} > $_base->{$l_host}->{$r_host}->{REMOTE_BYTES} )
			{
				$big_bytes = $_base->{$l_host}->{$r_host}->{LOCAL_BYTES};
			}
			else
			{
				$big_bytes = $_base->{$l_host}->{$r_host}->{REMOTE_BYTES};
			}
			
			push( @{$reversed_hash{$big_bytes}}, { REF => $_base->{$l_host}->{$r_host},
										LOCAL_HOST => $l_host,
										REMOTE_HOST => $r_host, } );
		}
	}
	
	my @ordered_list = sort( { $b<=>$a } keys( %reversed_hash ) );
	
	my $i = 0;
	while( defined( my $key = shift( @ordered_list ) ) and $i < $max_output )
	{
		foreach my $data( @{$reversed_hash{$key}} )
		{
			my $local_bytes = trimbytes( $data->{REF}->{LOCAL_BYTES}, 6 );
			my $remote_bytes = trimbytes( $data->{REF}->{REMOTE_BYTES}, 6 );
			my $conn_count = $data->{REF}->{CONN_COUNT};
		        my $local_name = trimhostname( iptoname( $data->{LOCAL_HOST} ), $max_hostname_length, '>' );
		        my $remote_name = trimhostname( iptoname( $data->{REMOTE_HOST} ), $max_hostname_length, '>' );
			
			$ret_string .= swrite( $format, 
						$local_name,
						$remote_name, 
						$local_bytes,
						$remote_bytes,
						$conn_count );
			
			++$i;
			if( !( $i < $max_output ) )
			{
				last;
			}
		}
	}
	
	# Free up some memory
	$_base = undef;
	%reversed_hash = ();
	delete( $RPT_CACHE->{bytetransferpairs} );
	
	if( length( $ret_string ) < 32 )
	{
		$ret_string = $top_format . "  No data to report\n";
	}
	else
	{
		$ret_string = $top_format . $ret_string . "\n";
	}
	
	return( $ret_string );
}

sub output_successcount
{
	my $sub_name = 'output_successcount';
	my $ret_val = $RPT_CACHE->{successfailcount}->{SUCCESS};
	
	# Clean up some memory
	delete( $RPT_CACHE->{successfailcount}->{SUCCESS} );
	
	return( $ret_val );
}

sub output_failcount
{
	my $sub_name = 'output_failcount';
	my $ret_val = $RPT_CACHE->{successfailcount}->{FAIL};
	
	# Clean up some memory
	delete( $RPT_CACHE->{successfailcount}->{FAIL} );
	
	return( $ret_val );
}

sub availablereports
{
	my $sub_name = 'availablereports';
	
	my @ret_list = keys( %REPORT_MAP );
	
	return( @ret_list );
}

sub reportinputfunc
{
	my $sub_name = 'reportinputfunc';
	
	my $report_name = $_[0] || return( undef );
	
	if( exists( $REPORT_MAP{$report_name} ) )
	{
		return( $REPORT_MAP{$report_name}->{'input'} );
	}
	else
	{
		return( undef );
	}
}

sub reportoutputfunc
{
	my $sub_name = 'reportoutputfunc';
	
	my $report_name = $_[0] || return( undef );
	
	if( exists( $REPORT_MAP{$report_name} ) )
	{
		return( $REPORT_MAP{$report_name}->{'output'} );
	}
	else
	{
		return( undef );
	}
}

1;
