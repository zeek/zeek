package Bro::Config;

use strict;
use Config::General;
require Exporter;

use vars qw( $VERSION
			$DEBUG
			@ISA
			@EXPORT_OK
			%DEFAULTS
			$DEFAULT_CONFIG_FILE
			$BRO_CONFIG );

# $Id: Config.pm 987 2005-01-08 01:04:43Z rwinslow $
$VERSION = 1.20;
$DEBUG = 0;

@ISA = ( 'Exporter' );
@EXPORT_OK = qw( $BRO_CONFIG );
%DEFAULTS = ( BROHOME => '/usr/local/bro',
			BRO_POLICY_SUFFIX => '.bro',
			BRO_SIG_SUFFIX => '.sig',
			META_DATA_PREFIX => '.',
			);
			
$DEFAULTS{CONFIG_FILE} = $DEFAULTS{BROHOME} . '/etc/bro.cfg';

sub parse
{
	my $sub_name = 'parse';
	
	my %args = @_;
	my $config_file;
	my $brohome;
	my $conf;
	my $ret_hash;
	
	# Check for a config-path that may override the default
	if( exists( $args{'File'} ) )
	{
		$config_file = $args{'File'};
	}
	else
	{
		$config_file = $DEFAULT_CONFIG_FILE;
	}
	
	# Check for the existance and readability of the config file
	if( !( -f $config_file and -r $config_file ) )
	{
		warn( __PACKAGE__ . "::$sub_name, The Bro config file at $config_file is not readable\n" );
		return( undef );
	}
	
	$conf = Config::General->new( -ConfigFile => $config_file,
						-MergeDuplicateOptions => 1,
						-AutoTrue => 1,
					);
	%{$ret_hash} = $conf->getall;
	
	return( $ret_hash );
}

sub Configure
{
	my $sub_name = 'Configure';
	
	my %args = @_;
		
	if( exists( $args{File} ) )
	{
		if( $args{File} !~ m/[\;\|\?\*\&\{\}]/ and $args{File} =~ m/^([[:print:]]+)$/ )
		{
			my $clean_name = $1;
			if( -f $clean_name and -r $clean_name )
			{
				$DEFAULT_CONFIG_FILE = $clean_name;
			}
			else
			{
				warn( __PACKAGE__ . "::$sub_name, Unable to read config file at $clean_name\n" );
				return( undef );
			}
		}
		else
		{
			warn( __PACKAGE__ . "::$sub_name, Filename contains invalid characters\n" );
			return( undef );
		}
	}
	
	$BRO_CONFIG = parse();
	
	# Set other defaults that have been omitted or don't exist in the config file
	setdefaults();
	
	return( 1 );
}

sub setdefaults
{
	my $sub_name = 'setdefaults';
	
	my $override = $_[0] || 0;
	my @variables_changed;
	
	foreach my $key( keys( %DEFAULTS ) )
	{
		if( $override or !( exists( $BRO_CONFIG->{$key} ) ) )
		{
			$BRO_CONFIG->{$key} = $DEFAULTS{$key};
			push( @variables_changed, $key )
		}
	}
	
	return( @variables_changed );
}

1;