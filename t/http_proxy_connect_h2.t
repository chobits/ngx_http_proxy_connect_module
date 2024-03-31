#!/usr/bin/perl

# (C) Xiaochen Wang

# Tests for HTTP/2 protocol with proxy_connect module.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ SOL_SOCKET SO_RCVBUF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# SRV record, not used
my %route_map;

# A record
my %aroute_map = (
    'localhost' => [[300, "127.0.0.1"]],
);

my $t = Test::Nginx->new()->has(qw/http http_ssl http_v2 socket_ssl_alpn/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_8981_UDP%% ipv6=off;      # NOTE: cannot connect ipv6 address ::1 in mac os x.

    server {
        listen       127.0.0.1:8080 http2 ssl;
        server_name  localhost;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        lingering_close off;

        proxy_connect;
        proxy_connect_allow all;
        proxy_connect_connect_timeout 10s;
        proxy_connect_data_timeout 10s;

        location / { }
    }

    server {
        listen       127.0.0.1:8081;
        return 200 "OK\n";
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('index.html', '');
$t->write_file('tbig.html',
        join('', map { sprintf "XX%06dXX", $_ } (1 .. 500000)));

$t->run_daemon(\&dns_daemon, port(8981), $t);
$t->waitforfile($t->testdir . '/' . port(8981));

open OLDERR, ">&", \*STDERR; close STDERR;
$t->run();
open STDERR, ">&", \*OLDERR;

plan(skip_all => 'no ALPN negotiation') unless defined getconn();
$t->plan(5);

###############################################################################

SKIP: {
skip 'LibreSSL too old', 1
	if $t->has_module('LibreSSL')
	and not $t->has_feature('libressl:3.4.0');
skip 'OpenSSL too old', 1
	if $t->has_module('OpenSSL')
	and not $t->has_feature('openssl:1.1.0');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.21.4');

ok(!get_ssl_socket(['unknown']), 'alpn rejected');

}

}

like(http_get('/', socket => get_ssl_socket(['http/1.1'])),
	qr/200 OK/, 'alpn to HTTP/1.1 fallback');

my $s = getconn(['http/1.1', 'h2']);
my $sid = $s->new_stream();
my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'alpn to HTTP/2');
# h2c preface on ssl-enabled socket is rejected as invalid HTTP/1.x request,
# ensure that HTTP/2 auto-detection doesn't kick in

like(http("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), qr/Bad Request/,
	'no h2c on ssl socket');

# client cancels last stream after HEADERS has been created,
# while some unsent data was left in the SSL buffer
# HEADERS frame may stuck in SSL buffer and won't be sent producing alert

$s = getconn(['http/1.1', 'h2']);
$s->{socket}->setsockopt(SOL_SOCKET, SO_RCVBUF, 1024*1024) or die $!;

# for proxy_connect
$sid = $s->new_stream({ headers => [
        { name => ':method', value => 'CONNECT', mode => 1 },
        { name => ':authority', value => 'localhost:'.port(8081), mode => 1 } ]});
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;

TODO: {
    local $TODO = 'not yet';
    is($frame->{headers}->{':status'}, 200, 'CONNECT - connection established');
}

$t->stop();

###############################################################################

sub getconn {
	my ($alpn) = @_;
	$alpn = ['h2'] if !defined $alpn;

	my $sock = get_ssl_socket($alpn);
	my $s = Test::Nginx::HTTP2->new(undef, socket => $sock)
		if $sock->alpn_selected();
}

sub get_ssl_socket {
	my ($alpn) = @_;
	my $s;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(8);
		$s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1',
			PeerPort => port(8080),
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
			SSL_alpn_protocols => $alpn,
			SSL_error_trap => sub { die $_[1] }
		);
		alarm(0);
	};
	alarm(0);

	if ($@) {
		log_in("died: $@");
		return undef;
	}

	return $s;
}

###############################################################################

sub reply_handler {
	my ($recv_data, $port, $state, %extra) = @_;

	my (@name, @rdata);

	use constant NOERROR	=> 0;
	use constant FORMERR	=> 1;
	use constant SERVFAIL	=> 2;
	use constant NXDOMAIN	=> 3;

	use constant A		=> 1;
	use constant CNAME	=> 5;
	use constant DNAME	=> 39;

	use constant IN		=> 1;

	# default values

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 3600);

	# decode name

	my ($len, $offset) = (undef, 12);
	while (1) {
		$len = unpack("\@$offset C", $recv_data);
		last if $len == 0;
		$offset++;
		push @name, unpack("\@$offset A$len", $recv_data);
		$offset += $len;
	}

	$offset -= 1;
	my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);

	my $name = join('.', @name);

        if (($type == A) && exists($aroute_map{$name})) {

            my @records = @{$aroute_map{$name}};

            for (my $i = 0; $i < scalar(@records); $i++) {
                my ($ttl, $origin_addr) = @{$records[$i]};
                push @rdata, rd_addr($ttl, $origin_addr);

                #print("dns reply: $name $ttl $class $type $origin_addr\n");
            }
        }

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
	my ($ttl, $addr) = @_;

	my $code = 'split(/\./, $addr)';

	return pack 'n3N', 0xc00c, A, IN, $ttl if $addr eq '';

	pack 'n3N nC4', 0xc00c, A, IN, $ttl, eval "scalar $code", eval($code);
}

sub dns_daemon {
	my ($port, $t, %extra) = @_;

        print("+ dns daemon: try to listen on 127.0.0.1:$port\n");

	my ($data, $recv_data);
	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto => 'udp',
	)
		or die "Can't create listening socket: $!\n";

	my $sel = IO::Select->new($socket);
	my $tcp = 0;

	if ($extra{tcp}) {
		$tcp = port(8983, socket => 1);
		$sel->add($tcp);
	}

	local $SIG{PIPE} = 'IGNORE';

	# track number of relevant queries

	my %state = (
		cnamecnt	=> 0,
		twocnt		=> 0,
		ttlcnt		=> 0,
		ttl0cnt		=> 0,
		cttlcnt		=> 0,
		cttl2cnt	=> 0,
		manycnt		=> 0,
		casecnt		=> 0,
		idcnt		=> 0,
		fecnt		=> 0,
	);

	# signal we are ready

	open my $fh, '>', $t->testdir() . '/' . $port;
	close $fh;

	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if ($tcp == $fh) {
				my $new = $fh->accept;
				$new->autoflush(1);
				$sel->add($new);

			} elsif ($socket == $fh) {
				$fh->recv($recv_data, 65536);
				$data = reply_handler($recv_data, $port,
					\%state);
				$fh->send($data);

			} else {
				$fh->recv($recv_data, 65536);
				unless (length $recv_data) {
					$sel->remove($fh);
					$fh->close;
					next;
				}

again:
				my $len = unpack("n", $recv_data);
				$data = substr $recv_data, 2, $len;
				$data = reply_handler($data, $port, \%state,
					tcp => 1);
				$data = pack("n", length $data) . $data;
				$fh->send($data);
				$recv_data = substr $recv_data, 2 + $len;
				goto again if length $recv_data;
			}
		}
	}
}

###############################################################################
