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
	mkdir 'var' unless -e 'var';
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
    path => qr/\.pdf\b/,
    mime => 'application/pdf',
    # save the PDF
    response => HTTP::Proxy::BodyFilter::save->new(
	timestamp => 1,
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
# proxy-auth.pl
#

my $username = 'http';
my $passwd   = 'proxy';
my $realm    = 'HTTP::Proxy';

$realm = 'testrealm@host.com';

my $auth = 'Basic'; # XXX unsecure!!
$auth = 'Digest';

use HTTP::Proxy qw( :log );
use MIME::Base64 qw( encode_base64 );
use Carp qw/carp/;
use Data::UUID ();

# the encoded user:password pair
my $token = "Basic " . encode_base64( "$username:$passwd", '' );

our $digest_cache;
our $opaque;

sub auth_response {
	my $response = HTTP::Response->new(407);
	my $header = qq{$auth realm="$realm"};

	if ( $auth eq 'Digest' ) {

		my $nonce;

		if ( ! $opaque ) {
			$opaque = Data::UUID->new->create_b64;
			chomp $opaque;
			$nonce = Data::UUID->new->create_b64;
			chomp $nonce;
			warn "## new opaque $opaque nonce $nonce\n";
		}

		$digest_cache->{ $opaque } ||= {
			algorithm => 'MD5',
			nonce => $nonce,
			opaque => $opaque,
			nounce_count => '0x0',
			qpop => 'auth,auth-int',
		};

		$header .= ',' . join(',', map {
			qq|$_="$digest_cache->{$opaque}->{$_}"|
		} keys %{ $digest_cache->{$opaque} } );

		$header =~ s{\s+}{ }gs;

		warn "digest_cache ",dump( $digest_cache );

	}

	$response->header( Proxy_Authenticate => $header );
	warn ">>>> 407 $header\n";
	return $response;
}

# the authentication filter
my $auth_filter = $auth eq 'Basic' ? 
	sub {
		my ( $self, $headers, $request ) = @_;

		warn "WARNING: Basic HTTP authentification isn't secure!";

		# check the token against all credentials
		my $ok = 0;
		$_ eq $token && $ok++
			for $self->proxy->hop_headers->header('Proxy-Authorization');

		# no valid credential
		return $self->proxy->response( auth_response ) if ! $ok;
	}
:
	 sub {
		my ( $self, $headers, $request ) = @_;

		foreach my $authorization ( $self->proxy->hop_headers->header('Proxy-Authorization') ) {

			warn "<<<< Proxy-Authorization: $authorization";

			if ( $authorization !~ m{^Digest} ) {
				warn "skip $authorization\n";
				next;
			}

			my %res = map {
				my @key_val = split /=/, $_, 2;
				$key_val[0] = lc $key_val[0];
				$key_val[1] =~ s{"}{}g;    # remove the quotes
				@key_val;
			} split /,\s?/, substr( $authorization, 7 );    #7 == length "Digest "

			warn "res ",dump( \%res );

			$opaque = $res{opaque}
			|| return $self->proxy->response( auth_response );

			my $nonce  = $digest_cache->{ $opaque };

			if ( ! $nonce ) {
				warn "no $opaque in ",dump( $digest_cache );
				next;
			}

			warn '# Checking authentication parameters.';

			my $uri         = $request->uri->path_query || die "uri";
			my $algorithm   = $res{algorithm} || 'MD5';
			my $nonce_count = '0x' . ( $res{nc} || 0 );

			my $check = $uri eq $res{uri}
				&& ( exists $res{username} )
				&& ( $res{username} eq $username )
				&& ( exists $res{qop} )
				&& ( exists $res{cnonce} )
				&& ( exists $res{nc} )
				&& $algorithm eq $nonce->{algorithm}
				&& hex($nonce_count) > hex( $nonce->{nonce_count} )
				&& $res{nonce} eq $nonce->{nonce};	# TODO: set Stale instead

			return $self->proxy->response( auth_response ) unless $check;

			warn "# Checking authentication response ";

			# everything looks good, let's check the response
			# calculate H(A2) as per spec
			my $ctx = Digest::MD5->new;
			$ctx->add( join( ':', $request->method, $res{uri} ) );
			if ( $res{qop} eq 'auth-int' ) {
				my $digest =
					Digest::MD5::md5_hex( $request->body );	# not sure here
				$ctx->add( ':', $digest );
			}
			my $A2_digest = $ctx->hexdigest;

			for my $r ( 0 .. 1 ) {
				# calculate H(A1) as per spec
				my $A1_digest = $r ? $passwd : do {
					$ctx = Digest::MD5->new;
					$ctx->add( join( ':', $username, $realm->name, $passwd ) );
					$ctx->hexdigest;
				};
				if ( $nonce->{algorithm} eq 'MD5-sess' ) {
					$ctx = Digest::MD5->new;
					$ctx->add( join( ':', $A1_digest, $res{nonce}, $res{cnonce} ) );
					$A1_digest = $ctx->hexdigest;
				}

				my $digest_in = join( ':',
						$A1_digest, $res{nonce},
						$res{qop} ? ( $res{nc}, $res{cnonce}, $res{qop} ) : (),
						$A2_digest );
				my $rq_digest = Digest::MD5::md5_hex($digest_in);
				$nonce->{nonce_count} = $nonce_count;
				$digest_cache->{ $nonce->{opaque} } = $nonce;

warn "digest_cache ", dump( $digest_cache );

				if ($rq_digest eq $res{response} ) {
					return;
				} else {
					warn "XXX $rq_digest not $res{response}";
				}
			}
		}
		$self->proxy->response( auth_response );
	}
;

warn "auth_filter $auth_filter";

$proxy->push_filter( request => HTTP::Proxy::HeaderFilter::simple->new( $auth_filter ) );

#
# admin interface
#

sub debug_on { -e 'var/debug' }
sub debug_dump { -e 'var/debug' && warn "## ", dump( @_ ) }

my $admin_filter = HTTP::Proxy::HeaderFilter::simple->new( sub {
   my ( $self, $headers, $message ) = @_;
warn "\n[", $headers->header('x-forwarded-for'), '] ', $message->uri, "\n";

	print $message->headers_as_string if debug_on;

	my $host = $message->uri->host;
	var_save 'hits' => $host;
	return unless $host eq $proxy->host && $message->uri->port == $proxy->port;

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
 
	if (isInNet(host, "127.0.0.0",  "255.0.0.0"))
		return "DIRECT";

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

warn "user interface at http://", $proxy->host, ":", $proxy->port, "\n";

$proxy->start;

