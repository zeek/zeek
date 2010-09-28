# $Id: Signature.pm 987 2005-01-08 01:04:43Z rwinslow $
# Read and parse a Bro signature from a string or array reference
package Bro::Signature;

use strict;
require 5.006_001;
use Bro::Config qw( $BRO_CONFIG );
require Exporter;
use vars qw( $VERSION
			@ISA
			@EXPORT_OK
			%SKIP_OPT
			%ACTIONS
			$DEBUG );

$VERSION = 1.20;
@EXPORT_OK = qw( findkeyblocks filelist getrules utctimenow );
@ISA = qw( Exporter );
$DEBUG = 0;

# These conditions, actions, meta data will be skipped when comparing two
# signature objects for differences.  Reasons are given.
%SKIP_OPT = ( 'active' => 1,			# evaluated seperately
			'__raw_data__' => 1,	# internal data
			'__value__' => 1,		# internal data
			'sig_id' => 1,			# not evaluated
			'.revision' => 1,		# evaluated seperately
			'.version' => 1,		# evaluated seperately
			'.location' => 1,		# reserved for editor use as a temporary field
			);

# Hash of valid actions in a signature.  Currently there is only one.
%ACTIONS = ( 'event' => 1, );


sub new
{
	my $sub_name = 'new';

	my $self;
	my $proto = shift;
	my $class = ref( $proto ) || $proto;
	my %args = @_;
	my $sig_data = {};
	
	if( defined( $args{string} ) )
	{
		if( !( $sig_data = parsesig( $args{string} ) ) )
		{
			return( undef );
		}
	}
	else
	{
		warn( __PACKAGE__ . "::$sub_name, Signature must be passed in as a string for now.  Direct" .
			" object creation is not supported yet\n" );
		return( undef );
	}

	$self = $sig_data;
	bless( $self, $class );
	
	if( $DEBUG > 1 )
	{
		warn( $self->output() . "\n" );
	}
	return( $self );

}

sub parsesig
{
	my $sub_name = 'parsesig';

	my $sig_block = shift || return( undef );
	my $sig_data;
	my $ret_data = {};

	# Check on the storage of the data
	if( ref( $sig_block ) eq 'ARRAY' )
	{
		$sig_data = join( "\n", @{$sig_block} );
	}
	else
	{
		# Otherwise it gets treated as a string
		$sig_data = $sig_block;
	}
	
	# remove any leading or trailing white space
	$sig_data =~ s/^[[:space:]]*//;
	$sig_data =~ s/[[:space:]]*$//;
	
	my $parse_err = 0;

	if( $sig_data =~
		m/^signature[[:space:]]+([[:alnum:]_-]+)[[:space:]]*\{[[:space:]\n]+	# signature declaration
		(.+?)		# signature data
		[[:space:]]*\}$/xs )	# end of block
	{
		my $sig_id = $1;
		my $sig_options = $2;

		$ret_data->{sig_id} = $sig_id;

		my @raw_data;
		my $i = 0;

		foreach my $line( split( /\n/, $sig_options ) )
		{
			# Each line of the signature is stored in an
			 # array to maintain the order and any comments.
			 # The actual data is stored in a hash.
			 # Access of the data should be done through the methods
			 # to output the whole signature along with comments.

			# remove any leading spaces
			$line =~ s/^[[:space:]]*//;

			# Put the line into the raw_data array
			$raw_data[$i] = $line;

			# Strip any comments from the line
			$line =~ s/(?:[[:space:]]+|)#.+$//;

			my( $key, $value ) = split( /[[:space:]]+/, $line, 2 );
			# if there is still data in the line then process
			if( defined( $value ) )
			{
				# Remove any leading spaces
				$value =~ s/^[[:space:]]*//;
				# place a reference to the raw_data array for this attribute
				# set the value for this attribute instance
				push( @{$ret_data->{$key}}, { 
						'__raw_data_pos__' => $i,
						'__value__' => $value, },
				);
			}

			++$i;
		}

		$ret_data->{'__raw_data__'} = \@raw_data;
	}
	else
	{
		if( $DEBUG > 0 )
		{
			warn( __PACKAGE__ . "::$sub_name, Signature read error. Could not find a valid signature block\n" );
		}
		$parse_err = 1;
	}

	if( $parse_err )
	{
		return( undef );
	}
	else
	{
		return( $ret_data );
	}
}

sub findkeyblocks
{
	my $sub_name = 'findkeyblocks';

	my $string = $_[0];
	my $keyword = 'signature';
	my $key_len = length( $keyword );
	my @ret_blocks;
	my $block_idx = 0;			# Current idx of the keyword blocks that will be returned
	my $open_brace_count = 0;	# Number of open braces encountered
	my $close_brace_count = 0;	# number of close braces encountered
	my $len = length( $string );	# length of string passed in
	my $pos_idx = 0;			# current position of substring
	my $st_blk_pos = 0;			# string position of a new block
	my $blk_len = 0;			# length of code block
	my $found_key_start = 0;		# flag that a new keyword block has started
	my $comment_line = 0;		# flag if comments are in effect
	my $quoted;			# flag if quoting is active. contents are the quote character

	# make sure the string is of non-zero length.  Add one more so our
	 # loop below works
	if( $len > 0 )
	{
		++$len;
	}
	else
	{
		return( undef );
	}

	# Push a newline onto the front of the string.  This just helps in
	 # starting the pattern matching.  It's easier than writting a
	 # bunch more lines of code.
	$string = "\n" . $string;
	++$len;

	while( $pos_idx < $len )
	{
		# If the two numbers match then a complete block has been found.
		if( $open_brace_count == $close_brace_count and
			$open_brace_count > 0 )
		{
			$ret_blocks[$block_idx] = substr( $string, $st_blk_pos, $blk_len );
			
			if( $DEBUG > 2 )
			{
				my $end_pos = $st_blk_pos + $blk_len;
				warn( __PACKAGE__ . "::$sub_name, Found signature block between bytes $st_blk_pos and $end_pos\n" );
				warn( $ret_blocks[$block_idx] . "\n" );
			}
			
			++$block_idx;
			$open_brace_count = 0;
			$close_brace_count = 0;
			$found_key_start = 0;
			$st_blk_pos = $pos_idx;
			$blk_len = 0;
		}
		elsif( $close_brace_count > $open_brace_count )
		{
			# Looks like there was a syntax error perhaps the
			 # file contains a keyword but no valid block
			 # Reset the counters and backup to $st_blk_pos + 1
			if( $DEBUG > 0 )
			{
				warn( __PACKAGE__ . "::$sub_name, Error in parsing $keyword, found closed brace",
					" for a block but no open brace at char position $pos_idx\n" );
			}
			$open_brace_count = 0;
			$close_brace_count = 0;
			$found_key_start = 0;
			$pos_idx = $st_blk_pos + 1;
			$st_blk_pos = '';
			$blk_len = 0;
			next;
		}

		# Make sure that substr returns a value
		if( defined( my $wc = substr( $string, $pos_idx, 1 ) ) )
		{
			if( $quoted
				and $found_key_start )
			{
				if( $wc eq $quoted
					and substr( $string, $pos_idx - 1, 1 ) ne '\\' )
				{
					$quoted = undef;
				}
			}
			# check for comment '#' character which is active until the 
			 # start of a newline
			elsif( ! $comment_line and 
				$wc eq '#' and
				substr( $string, $pos_idx - 1, 1 ) ne '\\' )
			{
				$comment_line = 1;
			}
			# Check if the comment flag is set
			elsif( $comment_line )
			{
				# If the current character is a newline then reset the comment flag
				if( $wc =~ m/\n/ )
				{
					$comment_line = 0;
				}
			}
			# start this if not currently working in a block and not a comment
			elsif( ! $found_key_start and ! $comment_line )
			{
				# check if the keyword is found 
				if( $pos_idx + $key_len + 1 < $len
				and substr( $string, $pos_idx, $key_len ) eq $keyword )
				{
					# check to make sure that the keyword is followed by a space
					if( substr( $string, $pos_idx + $key_len, 1 ) =~
						m/[[:space:]]/ )
					{
						$found_key_start = 1;
						$st_blk_pos = $pos_idx;
					}
				}
			}
		# Need to re-think this one at some point though it's not going to kill things
		  # to leave it out right now.
		
		# Check if a nested block has started.
		#	elsif( $pos_idx + $key_len + 1 < $len
		#		and $found_key_start
		#		and substr( $string, $pos_idx, $key_len ) eq $keyword )
		#	{
		#		if( substr( $string, $pos_idx + $key_len, 1 ) =~
		#				m/[[:space:]]/ )
		#		{
		#			if( $DEBUG > 0 )
		#			{
		#				warn( __PACKAGE__ . "::$sub_name, New $keyword keyword found inside of another $keyword block",
		#					" at char position $pos_idx\n" );
		#
		#				#print "STRING => $string\n";
		#			}
		#
		#			# Reset the search params
		#			$open_brace_count = 0;
		#			$close_brace_count = 0;
		#			$found_key_start = 0;
		#			++$pos_idx;
		#			$st_blk_pos = '';
		#			$blk_len = 0;
		#			next;
		#		}
		#	}
			elsif( $wc eq '{' and 
				substr( $string, $pos_idx - 1, 1 ) ne '\\'
				and substr( $string, $pos_idx + 1, 1 ) =~ m/[[:space:]\n]/ )
			{
				++$open_brace_count;
			}
			elsif( $wc eq '}' and
				substr( $string, $pos_idx - 1, 1 ) ne '\\'
				and substr( $string, $pos_idx - 1, 1 ) =~ m/[[:space:]\n]/ )
			{
				++$close_brace_count;
			}
			elsif( ! $quoted
				and ! $comment_line
				and $found_key_start )
			{
				if( $wc eq '"'
					and substr( $string, $pos_idx - 1, 1 ) ne '\\' )
				{
					$quoted = $wc;
				}
			}
			else
			{

			}

			# Only append chars to the working string if in a $keyword block
			if( $found_key_start )
			{
				++$blk_len;
			}
			++$pos_idx;
		}
		else
		{
			warn( __PACKAGE__ . "::$sub_name, Failed to pull data out using substr at position $pos_idx\n" );
			++$pos_idx;
		}
	}

	if( wantarray )
	{
		return( @ret_blocks );
	}
	else
	{
		return( \@ret_blocks );
	}
}

sub addcomment
{
	my $sub_name = 'addcomment';

	my $self = shift || return( undef );
	my $comment = shift || return( undef );

	# Make sure the comment starts with a '#'
	if( $comment !~ m/^[[:space:]]*#/ )
	{
		$comment = '#' . $comment;
	}

	if( $self->{'__raw_data__'} )
	{
		my $next_idx = $#{$self->{'__raw_data__'}} + 1;
		$self->{'__raw_data__'}->[$next_idx] = $comment;
	}
	else
	{
		return( undef );
	}

	return( 1 );
}

sub option
{
	my $sub_name = 'option';

	my $self = shift || return( undef );
	my $sig_option = shift || return( undef );
	my $ret_data;

	if( $self->{$sig_option} )
	{
		foreach my $data( @{$self->{$sig_option}} )
		{
			push( @{$ret_data}, $data->{'__value__'} );
		}
	}
	else
	{
		return( undef );
	}

	if( @{$ret_data} > 1 )
	{
		return( @{$ret_data} );
	}
	else
	{
		return( $ret_data->[0] );
	}
}

sub addoption
{
	my $sub_name = 'addoption';

	my $self = shift || return( undef );
	my $option = shift || return( undef );
	my $option_data = shift || return( undef );

	if( $self->{'__raw_data__'} )
	{
		my $next_idx = $#{$self->{'__raw_data__'}} + 1;
		$self->{'__raw_data__'}->[$next_idx] = $option . ' ' . $option_data;
		push( @{$self->{$option}}, 
			{ '__raw_data_pos__' => $next_idx,
			'__value__' => $option_data, } );
	}
	else
	{
		return( undef );
	}

	return( 1 );
}

sub modoption
{
	my $sub_name = 'modoption';
	
	# If successful the value which was replaced is returned.
	# If failure then an undefined value is returned.
	
	my $self = shift || return( undef );
	my $match_option = shift || return( undef );
	my $new_data = shift || return( undef );
	my $match_data = shift;	#optional
	my $replaced_data;
	
	if( exists( $self->{$match_option} ) )
	{				
		if( @{$self->{$match_option}} > 1 )
		{
			# This won't work if $match_data is not defined
			if( ! defined( $match_data ) )
			{
				if( $DEBUG > 0 )
				{
					warn( __PACKAGE__ .
					"::$sub_name, Failed to modify option $match_option.  Data which to match against is required for options with more than one instance.\n" );
				}
				return( undef );
			}
			
			foreach my $opt_inst( @{$self->{$match_option}} )
			{
				if( $opt_inst->{'__value__'} eq $match_data )
				{
					$replaced_data = $opt_inst->{'__value__'};
					$opt_inst->{'__value__'} = $new_data;
					$self->{'__raw_data__'}->[$opt_inst->{'__raw_data_pos__'}] = "$match_option $new_data";
				}
			}
		}
		else
		{
			$replaced_data = $self->{$match_option}->[0]->{'__value__'};
			
			if( defined( $match_data ) and $match_data ne $replaced_data )
			{
				return( undef );
			}
			else
			{
				$self->{$match_option}->[0]->{'__value__'} = $new_data;
				$self->{'__raw_data__'}->[$self->{$match_option}->[0]->{'__raw_data_pos__'}] = "$match_option $new_data";
			}
		}
	}
	else
	{
		# no matching option found
		return( undef );
	}
	
	return( $replaced_data );
}

sub deloption
{
	my $sub_name = 'deloption';
	# Accepts at a minimum the object and an option to remove
	# For options that have multivalues the value can be passed in as 
	 # option_data to remove only the one value from the object.
	# If an option has multivalues and no option_data is given then all
	 # options are removed.


	my $self = shift || return( undef );
	my $match_option = shift || return( undef );
	my $match_data = shift;	#optional
	my $success = 0;
	my @raw_data_pos;

	if( defined( $match_data ) )
	{
		if( $DEBUG > 4 )
		{
			warn( __PACKAGE__ . "::$sub_name, Method $sub_name has been asked to delete option '" .
				$match_option . "', value '" . $match_data . "'\n" );
		}
		# Must match on both the option key and it's value
		if( exists( $self->{$match_option} ) )
		{				
			if( ref( $self->{$match_option} ) eq 'ARRAY' )
			{
				if( $DEBUG > 4 )
				{
					warn( __PACKAGE__ . "::$sub_name, Found a match on $match_option in signature\n" );
				}

				my $__found = 0;
				my @good_data;
				foreach my $opt_value( @{$self->{$match_option}} )
				{
					if( $opt_value->{'__value__'} eq $match_data )
					{
						++$__found;
						$success = 1;
						push( @raw_data_pos, $opt_value->{'__raw_data_pos__'} );
					}
					elsif( defined( my $tt = $opt_value->{'__value__'} ) )
					{
						push( @good_data, $opt_value );
					}

				}

				if( $success )
				{
					if( defined( $good_data[0] ) )
					{
						# Replace the object's old data with the good data
						$self->{$match_option} = [ @good_data ];
					}
					else
					{
						delete $self->{$match_option};
					}
				}
			}
		}
	}
	elsif( exists( $self->{$match_option} ) )
	{
		if( $DEBUG > 4 )
		{
			warn( __PACKAGE__ . "::$sub_name, Method $sub_name has been asked to delete all data with" .
				" an option name of $match_option\n" );
		}

		foreach my $opt_data( @{$self->{$match_option}} )
		{
			push( @raw_data_pos, $opt_data->{'__raw_data_pos__'} );
		}
		delete $self->{$match_option};
		$success = 1;
	}


	if( $success )
	{
		# cleanup the __raw_data__ storage in the object
		# get the last index of the __raw_data__ array
		foreach my $idx( @raw_data_pos )
		{
			$self->{'__raw_data__'}->[$idx] = undef;
		}

		# Delete the 
	}

	return( $success );

}

sub meta
{
	my $sub_name = 'meta';
	
	my $self = shift || return( undef );
	my $meta_name = shift || return( undef );
	
	return( $self->option( $BRO_CONFIG->{META_DATA_PREFIX} . $meta_name ) );
	
}

sub output
{
	my $sub_name = 'output';

	my $self = shift || return( undef );
	my %args = @_;
	my $ret_string;
	my $prefix = '';
	my $comments = 0;

	# Make a few checks on the signature to make sure it has all the
	# mandatory parts before outputting.
	$self->active();
	
	# Check on options
	if( $args{sigprefix} )
	{
		$prefix = $args{sigprefix};
	}

	if( defined( $args{comments} ) )
	{
		$comments = $args{comments};
	}
	else
	{
		$comments = 1;
	}
	
	if( defined( $args{live} ) )
	{
		
	}
	elsif( defined( $args{meta} ) )
	{
		
	}
	else
	{
		# opening to a Bro signature block
		$ret_string = 'signature ' . $prefix . $self->{sig_id} . ' {' . "\n";

		if( $comments )
		{
			foreach my $line( @{$self->{'__raw_data__'}} )
			{
				if( defined( $line ) )
				{
					$ret_string = $ret_string . '  ' . $line . "\n";
				}
			}
		}
		else
		{
			while( my( $option, $opt_array ) = each( %{$self} ) )
			{
				if( $option ne '__raw_data__' and $option ne 'sig_id' )
				{
					foreach my $opt_data( @{$opt_array} )
					{
						$ret_string = $ret_string . 
						'  ' .
						$option .
						' ' .
						$opt_data->{'__value__'} .
						"\n";
					}
				}
			}
		}

		# closing of the Bro signature block
		$ret_string = $ret_string . '}';
	}

	return( $ret_string );
}

sub sigid
{
	# This is the entire Bro signature id as parsed in from a 
	 # signature block
	my $sub_name = 'sigid';

	my $self = shift || return( undef );

	if( $self->{sig_id} )
	{
		return( $self->{sig_id} );
	}
	else
	{
		return( undef );
	}
}

sub active
{
	my $sub_name = 'active';
	
	# If passed with an argument then the new value will be set if it is valid.
	# If the new value is set properly then 2 is returned otherwise return -1
	# If no args called then 0 returned if value is false and 1 returned if
	# value is true.
	
	my $self = shift || return( undef );
	my $new_status;
	
	if( @_ > 0 )
	{
		$new_status = shift;
		
		# The default is true, set it now if it doesn't already exist.
		if( ! defined( $self->option( 'active' ) ) )
		{
			$self->addoption( 'active', 'true' );
		}
	
		# Make sure that $new_status contains valid data
		if( $new_status =~ m/^(?:1|true)$/ )
		{
			$new_status = 'true';
		}
		elsif( $new_status =~ m/^(?:0|false)$/ )
		{
			$new_status = 'false';
		}
		else
		{
			return( undef );
		}
		
		$self->modoption( 'active', $new_status );
		return( 2 );
	}
	
	if( ! defined( $self->option( 'active' ) ) or
		$self->option( 'active' ) eq 'true' )
	{
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub version
{
	my $sub_name = 'version';
	
	my $self = shift || return( undef );
	
	my $ver = $self->meta( 'version' );
	if( defined( $ver ) and $ver =~ m/^[[:digit:]]+$/ )
	{
		return( $ver );
	}
	else
	{
		return( '' );
	}
}

sub revision
{
	my $sub_name = 'revision';
	
	my $self = shift || return( undef );
	
	my $rev = $self->meta( 'revision' );
	if( defined( $rev ) and $rev =~ m/^[[:digit:]]+$/ )
	{
		return( $rev );
	}
	else
	{
		return( '' );
	}
}

sub filelist
{
	my $sub_name = 'filelist';
	
	my @args = @_;	# optional arguments
	my @file_list;
	my @signature_dirs;
	my @extra_sig_dirs;
	my $sigfile_suffix = $BRO_CONFIG->{BRO_SIG_SUFFIX};
	
	# valid modes are add and override, default is add
	my $extra_dir_mode = 'add';
	
	# If there are args figure out what to do with them.
	if( @args > 0 )
	{
		if( $args[0] eq 'mode' )
		{
			shift @args;
			$extra_dir_mode = shift @args;
		}
		
		push( @extra_sig_dirs, @args );
	}
	
	# Verify that a valid mode was specified
	if( $extra_dir_mode ne 'add' and $extra_dir_mode ne 'override' )
	{
		warn( __PACKAGE__ . "::$sub_name, Invalid method of '$extra_dir_mode' set.\n" );
		return( undef );
	}
	
	if( $extra_dir_mode eq 'override' )
	{
		@signature_dirs = @extra_sig_dirs;
	}
	elsif( defined( $BRO_CONFIG->{BRO_SIG_DIR} ) or defined( $BRO_CONFIG->{BROPATH} ) )
	{
		my $rule_path;
		
		# if/else ladder is to allow for backwards compatability and will eventually
		# be removed.
		if( defined( $BRO_CONFIG->{BRO_SIG_DIR} ) and defined( $BRO_CONFIG->{BROPATH} ) )
		{
			$rule_path = join( ':', $BRO_CONFIG->{BRO_SIG_DIR}, $BRO_CONFIG->{BROPATH} );
		}
		elsif( defined( $BRO_CONFIG->{BROPATH} ) )
		{
			$rule_path = $BRO_CONFIG->{BROPATH};
		}
		else
		{
			$rule_path = $BRO_CONFIG->{BRO_SIG_DIR};
		}
		
		if( $rule_path =~ m/:/ )
		{
			@signature_dirs = split( /:/, $rule_path );
		}
		else
		{
			$signature_dirs[0] = $rule_path;
		}
		
		# If mode is add then add the additional directories into @signature_dirs
		if( $extra_dir_mode eq 'add' )
		{
			push( @signature_dirs, @extra_sig_dirs );
		}
	}
		
	foreach my $sig_dir( @signature_dirs )
	{
		if( -d $sig_dir and -r $sig_dir and $sig_dir =~ m/^([[:print:]]+)$/ )
		{
			# Taint clean the directory name
			$sig_dir = $1;

			if( opendir( INDIR, $sig_dir ) )
			{
				foreach my $file_name( readdir( INDIR ) )
				{
					if( $file_name =~ m/^([[:print:]]+$sigfile_suffix)$/ )
					{
						# Taint clean the file name
						$file_name = $1;
						push( @file_list, join( '/', $sig_dir, $file_name ) );
					}
				}
			}
			else
			{
				warn( __PACKAGE__ . "::$sub_name, Unable to read directory $sig_dir\n" );
				next;
			}

			closedir( INDIR );
		}
	}
	return( @file_list );
}

sub getrules
{
	my $sub_name = 'getrules';
	# Given a Bro rule file it will return a reference to a list of 
	# Bro::Signature objects in scalar contents and a regular list
	# in list context.
	
	my $rule_file = shift || return( undef );
	
	my $sig_file_data;
	my @sig_blocks;
	my @sig_objs;

	if( open( INFILE, $rule_file ) )
	{
		local $/ = undef;
		$sig_file_data = <INFILE>;
		@sig_blocks = findkeyblocks( $sig_file_data );
	}
	else
	{
		warn( "Failed to open Bro rule file at $rule_file\n" );
	}

	close( INFILE );

	# clean up some memory
	undef $sig_file_data;

	foreach my $sig_block( @sig_blocks )
	{
		if( my $rule_obj = Bro::Signature->new( string => $sig_block ) )
		{
			push( @sig_objs, $rule_obj );
		}
	}
	
	if( @sig_objs > 0 )
	{
		if( wantarray )
		{
			return( @sig_objs );
		}
		else
		{
			return( \@sig_objs );
		}
	}
}

sub compare
{
	my $sub_name = 'compare';
	# Given two signature objects compare them and return whether they are
	# the same or if there is difference.
	# If there are no changes then this returns undef.
	# Valid return values for changes are:
	# condition - There is a difference between the conditions ( ex. http, payload, dst-ip, etc. )
	# action - There is a difference in the actions ( ex. event )
	# active - There is a difference in the active status ( ex. true, false )
	# meta - There is a difference in the metadata ( ex. .version, .date-created, etc. )
	my $first_obj = shift || return( undef );
	my $second_obj = shift || return( undef );
	
	my $meta_prefix = $BRO_CONFIG->{META_DATA_PREFIX};
	$meta_prefix =~ s/\./\\./g;
	my $m_p = qr/^$meta_prefix.+/;	# Meta prefix
	my %f_meta;
	my %f_cond;
	my %f_act;
	my %s_meta;
	my %s_cond;
	my %s_act;
	my %results;
	
	# If the version number is different then there is definetly an action
	# and/or a condition difference
	if( $first_obj->version() ne $second_obj->version() )
	{
		$results{'condition'} = 1;
	}
	
	# Compare the active status
	if( $first_obj->active() ne $second_obj->active() )
	{
		$results{'active'} = 1;
	}
	
	# Seperate out all of the option data from meta data for the first obj
	foreach my $key( keys( %{$first_obj} ) )
	{
		if( exists( $SKIP_OPT{$key} ) )
		{
			# Ignore the key
		}
		elsif( $key =~ $m_p )
		{
			@{$f_meta{$key}} = $first_obj->option( $key );
		}
		elsif( exists( $ACTIONS{$key} ) )
		{
			@{$f_act{$key}} = $first_obj->option( $key );
		}
		else
		{
			# the data is part of a condition which is used
			# by Bro to define how a signature matches.
			@{$f_cond{$key}} = $first_obj->option( $key );
		}
	}
	
	# Seperate out all of the option data from meta data for the second obj
	foreach my $key( keys( %{$second_obj} ) )
	{
		if( exists( $SKIP_OPT{$key} ) )
		{
			# Ignore the key
		}
		elsif( $key =~ $m_p )
		{
			@{$s_meta{$key}} = $second_obj->option( $key );
		}
		elsif( exists( $ACTIONS{$key} ) )
		{
			@{$s_act{$key}} = $second_obj->option( $key );
		}
		else
		{
			# the data is part of a condition which is used
			# by Bro to define how a signature matches.
			@{$s_cond{$key}} = $second_obj->option( $key );
		}
	}
	
	# Compare the conditions
	foreach my $key( keys( %f_cond ) )
	{
		if( exists( $results{'condition'} ) )
		{
			last;
		}
		
		if( exists( $s_cond{$key} ) )
		{
			if( @{$f_cond{$key}} != @{$s_cond{$key}} )
			{
				$results{'condition'} = 1;
			}
		}
		else
		{
			$results{'condition'} = 1;
		}
		
		foreach my $val( @{$f_cond{$key}} )
		{
			if( exists( $results{'condition'} ) )
			{
				last;
			}
			
			my $did_match = 0;
			foreach my $val2( @{$s_cond{$key}} )
			{
				if( $val eq $val2 )
				{
					$did_match = 1;
					last;
				}
			}
			
			if( ! $did_match )
			{
				$results{'condition'} = 1;
			}
		}
	}
	foreach my $key( keys( %s_cond ) )
	{
		if( exists( $results{'condition'} ) )
		{
			last;
		}
		
		if( ! exists( $f_cond{$key} ) )
		{
			$results{'condition'} = 1;
		}
		
		foreach my $val( @{$s_cond{$key}} )
		{
			if( exists( $results{'condition'} ) )
			{
				last;
			}
			
			my $did_match = 0;
			foreach my $val2( @{$f_cond{$key}} )
			{
				if( $val eq $val2 )
				{
					$did_match = 1;
					last;
				}
			}
			
			if( ! $did_match )
			{
				$results{'condition'} = 1;
			}
		}
	}
	
	# Compare the actions
	foreach my $key( keys( %f_act ) )
	{
		if( exists( $results{'action'} ) )
		{
			last;
		}
		
		if( exists( $s_act{$key} ) )
		{
			if( @{$f_act{$key}} != @{$s_act{$key}} )
			{
				$results{'action'} = 1;
			}
		}
		else
		{
			$results{'action'} = 1;
		}
				
		foreach my $val( @{$f_act{$key}} )
		{
			if( exists( $results{'action'} ) )
			{
				last;
			}
			
			my $did_match = 0;
			foreach my $val2( @{$s_act{$key}} )
			{
				if( $val eq $val2 )
				{
					$did_match = 1;
					last;
				}
			}
			
			if( ! $did_match )
			{
				$results{'action'} = 1;
			}
		}
	}
	foreach my $key( keys( %s_act ) )
	{
		if( exists( $results{'action'} ) )
		{
			last;
		}
		
		if( ! exists( $f_act{$key} ) )
		{
			$results{'action'} = 1;
		}
		
		foreach my $val( @{$s_act{$key}} )
		{
			if( exists( $results{'action'} ) )
			{
				last;
			}
			
			my $did_match = 0;
			foreach my $val2( @{$f_act{$key}} )
			{
				if( $val eq $val2 )
				{
					$did_match = 1;
					last;
				}
			}
			
			if( ! $did_match )
			{
				$results{'action'} = 1;
			}
		}
	}
	
	# If the revision numbers are differnet then there is definetly a
	# meta data difference
	if( $first_obj->revision() ne $second_obj->revision() )
	{
		$results{'meta'} = 1;
	}
	
	# Compare the meta data
	foreach my $key( keys( %f_meta ) )
	{
		if( exists( $results{'meta'} ) )
		{
			last;
		}
		
		if( exists( $s_meta{$key} ) )
		{
			if( @{$f_meta{$key}} != @{$s_meta{$key}} )
			{
				$results{'meta'} = 1;
			}
		}
		else
		{
			$results{'meta'} = 1;
		}
				
		foreach my $val( @{$f_meta{$key}} )
		{
			if( exists( $results{'meta'} ) )
			{
				last;
			}
			
			my $did_match = 0;
			foreach my $val2( @{$s_meta{$key}} )
			{
				if( $val eq $val2 )
				{
					$did_match = 1;
					last;
				}
			}
			
			if( ! $did_match )
			{
				$results{'meta'} = 1;
			}
		}
	}
	foreach my $key( keys( %s_meta ) )
	{
		if( exists( $results{'meta'} ) )
		{
			last;
		}
		
		if( ! exists( $f_meta{$key} ) )
		{
			$results{'meta'} = 1;
		}
		
		foreach my $val( @{$s_meta{$key}} )
		{
			if( exists( $results{'meta'} ) )
			{
				last;
			}
			
			my $did_match = 0;
			foreach my $val2( @{$f_meta{$key}} )
			{
				if( $val eq $val2 )
				{
					$did_match = 1;
					last;
				}
			}
			
			if( ! $did_match )
			{
				$results{'meta'} = 1;
			}
		}
	}
		
	if( keys( %results ) > 0 )
	{
		return( \%results );
	}
	else
	{
		return( 0 );
	}
}

sub utctimenow
{
	my $sub_name = 'utctimenow';
	
	my @tp = gmtime();
	
	my $ret_time = sprintf( "%4d-%02d-%02dT%02d:%02d:%02dZ", 
					$tp[5] + 1900, $tp[4] + 1, $tp[3], $tp[2], $tp[1], $tp[0] );
	
	return( $ret_time );
}

1;

# List of reserved meta-data keywords for use by signature manipulation tools
# and the number of instances which may exist in each signature.

# date-created		max: 1
# version-date		max: 1
# revision-date	max: 1
# category		max: unlimited
# from-file		max: 1		reserved for use during editing, not used in actual signatures
# version			max: 1		version supplied by signature creator.
#							This number will be rolled if any of the 
#							matching content changes, not meta-data.
# rev			max: 1		This number will be rolled if changes to
#							meta-data are made.  No matching content
#							changes.
# 