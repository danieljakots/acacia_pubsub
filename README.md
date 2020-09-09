# Acacia pubsub

*What if a RCE was actually a feature*

This software connects to Redis pubsub with (non-optional) mTLS and listen on
the configured channel(s). Once there is a message it runs the associated
command for the channel with the message as the argument. The command(s) will
be executed with the same user than the one configured (if no user was
configured, then it's the same who started the program).

The program should be run as root with a configured user. This way it will
start as root and once it has loaded the certificate/key/ca for TLS, it will
re-exec itself with the configured user.

The program also provides a basic web page to indicates if it's connected to
Redis (for monitoring purpose).

# Installation

Compile the code and put the resulting binary somewhere™. Create an
unprivileged user if wanted. Under OpenBSD, this user should have
`/sbin/nologin` as shell and `/var/empty` as home.

# Configuration

Take `acacia.json.sample` and put it somewhere else™ (without ".sample").

# Run it

If you didn't put the configuration in `/etc/acacia.json`, you need to give the
path as the argument when you run the binary.

~~~
$ /path/to/binary [/path/to/config]
~~~

# FAQ

## Can I disable mTLS?

No you can't. The program is dangerous (as it enables remote code execution) so
there is as many safeguards (read too few) as possible.

## Couldn't you find a worse file format for the configuration file than json?

I wanted to keep the !stdlib dependencies as few as possible. While stdlib
also has `encoding/csv`, this was deemed unpractical.

## Do you have an OpenBSD's rc(8) script for it?

I do!

~~~
#!/bin/ksh
#
# $OpenBSD: rc.template,v 1.12 2018/01/11 19:30:18 rpe Exp $

daemon="/usr/share/scripts/acacia_pubsub"
daemon_flags="/etc/acacia.json"

. /etc/rc.d/rc.subr

rc_reload=NO
rc_bg=YES

rc_cmd $1
~~~

## It doesn't work, how do I debug it?

Logs go to syslog, in the *daemon* facility. Currently all the messages have
*INFO* priority.

## How can I monitor it?

Check the http endpoint /status for the text "connected".

For instance with nrpe:

~~~

command[check_acacia_pubsub]=/usr/local/libexec/nagios/check_http -H localhost -p 8091 -u /status -r 'state: connected'
~~~


