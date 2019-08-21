package Net::POP3::XOAuth2;

use Carp;
use Net::POP3;
use MIME::Base64;

*Net::POP3::_AUTH = sub { shift->command('AUTH', $_[0])->response() == CMD_OK };
*Net::POP3::xoauth2 = sub {
    @_ >= 1 && @_ <= 3 or croak 'usage: $pop3->xoauth2( USER, TOKEN )';
    my ($me, $user, $token) = @_;
    my $xoauth2_token = encode_base64("user=$user\001auth=Bearer $token\001\001");
    $xoauth2_token =~ s/[\r\n]//g;

    return unless ($me->_AUTH("XOAUTH2 $xoauth2_token"));

    $me->_get_mailbox_count();
};

1;
