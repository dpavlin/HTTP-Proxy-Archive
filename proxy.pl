#!/usr/bin/perl
#
# http proxy for archives
#
use strict;
use warnings;
use HTTP::Proxy qw ( :log );
use HTTP::Proxy::BodyFilter::save;
use HTTP::Proxy::BodyFilter::simple;
use HTTP::Proxy::HeaderFilter::simple;

use Data::Dump qw(dump);

sub var_save {
	my ( $dir, $name, $value ) = @_;
	$value ||= "\n";
	mkdir "var/$dir" unless -e "var/$dir";
	open(my $fh, '>>', "var/$dir/$name") || die $!;
	print $fh $value;
	close($fh);
}


#
# logger.pl
#

use CGI::Util qw( unescape );

$|++; # STDOUT

# get the command-line parameters
my %args = (
   peek    => [],
   header  => [],
   mime    => 'text/*',
);
{
    my $args = '(' . join( '|', keys %args ) . ')';
    for ( my $i = 0 ; $i < @ARGV ; $i += 2 ) {
        if ( $ARGV[$i] =~ /$args/o ) {
            if ( ref $args{$1} ) {
                push @{ $args{$1} }, $ARGV[ $i + 1 ];
            }
            else {
                $args{$1} = $ARGV[ $i + 1 ];
            }
            splice( @ARGV, $i, 2 );
            redo if $i < @ARGV;
        }
    }
}

# the headers we want to see
my @srv_hdr = (
    qw( Content-Type Set-Cookie Set-Cookie2 WWW-Authenticate Location ),
    @{ $args{header} }
);
my @clt_hdr =
  ( qw( Cookie Cookie2 Referer Referrer Authorization ), @{ $args{header} } );

# NOTE: Body request filters always receive the request body in one pass
my $post_filter = HTTP::Proxy::BodyFilter::simple->new(
    begin  => sub { $_[0]->{binary} = 0; },
    filter => sub {
        my ( $self, $dataref, $message, $protocol, $buffer ) = @_;
        print STDOUT "\n", $message->method, " ", $message->uri, "\n";
        print_headers( $message, @clt_hdr );

        if ( $self->{binary} || $$dataref =~ /\0/ ) {
            $self->{binary} = 1;
            print STDOUT "    (not printing binary data)\n";
            return;
        }

        # this is from CGI.pm, method parse_params()
        my (@pairs) = split( /[&;]/, $$dataref );
        for (@pairs) {
            my ( $param, $value ) = split( '=', $_, 2 );
            $param = unescape($param);
            $value = unescape($value);
            printf STDOUT "    %-20s => %s\n", $param, $value;
        }
    }
);

my $get_filter = HTTP::Proxy::HeaderFilter::simple->new(
    sub {
        my ( $self, $headers, $message ) = @_;
        my $req = $message->request;
        if ( $req->method ne 'POST' ) {
            print STDOUT "\n", $req->method, " ", $req->uri, "\n";
            print_headers( $req, @clt_hdr );
        }
        print STDOUT $message->status_line, "\n";
	print_headers( $message, @srv_hdr );

	if ( my $cookie = $message->header( 'Set-Cookie' ) ) {
		my $host = $req->uri->host;
		warn "COOKIE: $cookie from $host\n";
		var_save 'cookie' => $host;
	}
    }
);

sub print_headers {
    my $message = shift;
    for my $h (@_) {
        if ( $message->header($h) ) {
            print STDOUT "    $h: $_\n" for ( $message->header($h) );
        }
    }
}

# create and start the proxy
my $proxy = HTTP::Proxy->new(@ARGV);

# if we want to look at SOME sites
if (@{$args{peek}}) {
    for (@{$args{peek}}) {
        $proxy->push_filter(
            host    => $_,
            method  => 'POST',
            request => $post_filter
        );
        $proxy->push_filter(
            host     => $_,
            response => $get_filter,
            mime     => $args{mime},
        );
    }
}
# otherwise, peek at all sites
else {
    $proxy->push_filter(
        method  => 'POST',
        request => $post_filter
    );
    $proxy->push_filter( response => $get_filter, mime => $args{mime} );
}

#
# pdf.pl
#

my $saved;
$proxy->push_filter(
    # you should probably restrict this to certain hosts as well
    path => qr/\.pdf$/,
    mime => 'application/pdf',
    # save the PDF
    response => HTTP::Proxy::BodyFilter::save->new(
        template => "%f",
        prefix   => 'pdf'
    ),
    # send a HTML message instead
    response => HTTP::Proxy::BodyFilter::simple->new(
        begin => sub {
            my ( $self, $message ) = @_;    # for information, saorge
            $saved = 0;
        },
#        filter => sub {
#            my ( $self, $dataref, $message, $protocol, $buffer ) = @_;
#            $$dataref = $saved++ ? "" 
#              : sprintf '<p>Saving PDF file. Go <a href="%s">back</a></p>',
#                        $message->request->header('referer');
#        }
    ),
    # change the response Content-Type
    response => HTTP::Proxy::HeaderFilter::simple->new(
        sub {
            my ( $self, $headers, $response ) = @_;
#            $headers->content_type('text/html');
        }
    ),
);

#
# admin interface
#

sub debug_on { -e 'var/debug' }
sub debug_dump { -e 'var/debug' && warn "## ", dump( @_ ) }

my $admin_filter = HTTP::Proxy::HeaderFilter::simple->new( sub {
   my ( $self, $headers, $message ) = @_;
warn "XXX [", $headers->header('x-forwarded-for'), '] ', $message->uri, "\n";

	print $message->headers_as_string if debug_on;

	my $host = $message->uri->host;
	var_save 'hits' => $host;
	return unless $host eq $proxy->host;

	if ( my $q = $message->uri->query ) {
		if ( $q =~ m{debug} ) {
			-e 'var/debug' ? unlink 'var/debug' : open(my $touch,'>','var/debug');
		}
	}
	debug_dump( $headers, $message );

	my $host_port = $proxy->host . ':' . $proxy->port;

	my $res = HTTP::Response->new( 200 );

	if ( $message->uri->path =~ m/(proxy.pac|wpad.dat)/ ) {
		$res->content_type('application/x-ns-proxy-autoconfig');
		$res->content(qq|

function FindProxyForURL(url, host) {
//	if (shExpMatch(url, "*.example.com:*/*"))               {return "DIRECT";}

	if (shExpMatch(url, "*.js")) return "DIRECT";
	if (shExpMatch(url, "*.css")) return "DIRECT";
	if (shExpMatch(url, "*.gif")) return "DIRECT";
	if (shExpMatch(url, "*.png")) return "DIRECT";
	if (shExpMatch(url, "*.ico")) return "DIRECT";
	if (shExpMatch(url, "*.jpg")) return "DIRECT";
 
//	 if (isInNet(host, "10.0.0.0",  "255.255.248.0"))    {
//		return "PROXY fastproxy.example.com:8080";
//	}

	// we don't want to see this traffic! 
	if (shExpMatch(url, "*.google.*")) return "DIRECT";

	return "PROXY $host_port; DIRECT";
}

		|);
		$self->proxy->response( $res );
		return;
	}

	$res->content_type('text/html');
	$res->content(qq|

<h1>HTTP Proxy Archive</h1>

<div style="background: #ff0; padding: 1em;">

Copy following url into automatic proxy configuration and enable it:
<p>
<a href="http://$host_port/proxy.pac">http://$host_port/proxy.pac</a>

</div>

	| 
	. qq|<a href=/>/</a> <a href="?debug">debug</a>|
	);

	$self->proxy->response( $res );
} );
$proxy->push_filter( request => $admin_filter );


#
# start
#

warn "listen on host ", $proxy->host, " port ", $proxy->port, "\n";

$proxy->start;

