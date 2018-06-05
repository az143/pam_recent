pam\_recent is a small PAM module for making iptables' recent match more useful

# overview

This is a pam module for linux systems to adjust an iptables recent list,
which makes the rate limiting of connections from unknown locations
easier.

The idea is that one uses this module with iptables' recent module to
rate-limit connections to authenticated services (eg. ssh and ftp)
without penalizing successful logins.

if your good clients are all known anyway (static ip etc.), then you
have no problem and do not need this module. if however, you have
unknown clients who you don't want to rate-limit if they manage a
correct login, then this module allows you to clear the client's ip
address after the login has succeeded. you can also set/clear the
client's ip address using this module in different pam phases, e.g.
set in the authenticate phase and clear iff things progress to
session.

pam\_recent works with both ipv4 and v6 addresses, if you have a
reasonably modern kernel whose xt_recent match is compiled for both ip
v4 anv v6. in dual-stack scenarios the recent 'files' are shared
between v4 and v6, so you can use the same single match name with
ip6tables, iptables and pam\_recent.

caveat: pam generally does not report the raw ip address of the
client, but the client's hostname - pam\_recent therefore has to
perform a forward lookup, and mark/unmark ALL ip addresses that were
returned.

#  installation

* verify that your kernel has CONFIG\_NETFILTER\_XT\_MATCH\_RECENT
* get the required pam libraries and headers (libpam0g-dev in debian)
* compile and link the module:
  `gcc -shared -fPIC -Xlinker -x -o pam_recent.so pam_recent.c -lpam`
* copy it to the relevant place where the other pam modules live:
  `cp pam_recent.so /lib/x86_64-linux-gnu/security/`
  (on older systems the pam modules might be in `/lib/security/`.)

#  configuration:

## scenario one, firewall sets and checks, pam\_recent only clears

get your firewall to rate limit, the example here is for ssh and ftp
and assumes that these rules will only be applied to new connection
packets (so handle existing exchanges somewhere before these). the
example also uses a custom chain called limited to show how multiple
services may be conveniently grouped together in one rate-limited set.

	# ...somewhere after handling packets that belong to existing conns:
	iptables -A INPUT -p tcp --dport 22 -j limited # ssh
	iptables -A INPUT -p tcp --dport 21 -j limited # ftp

	iptables -A limited -m recent --name MYLIMIT --rcheck --hitcount 2 \
  	--seconds 60 -j DROP
	iptables -A sshlimited -m recent --name MYLIMIT --set -j ACCEPT

this allows up to two new ssh or ftp connections per 60 seconds and
records time stamps in /proc/net/ipt\_recent/MYLIMIT (or
/proc/net/xt\_recent/... in more recent kernels).  then add the usual
stanza to the relevant pam config files (here /etc/pam.d/ssh and ftp)
in the right place (order matters!):

	session optional pam_recent.so - MYLIMIT

and every successful login will clear this client's ip history, if pam
was invoked with sufficient privileges (as root) or if you have
modified the permissions of the ipt\_recent files in proc. This can be
done globally via ipt\_recent's module parameters (see the iptables
manpage) or by simply chown/chmod'ing the files in
/proc/net/ipt\_recent after loading your firewall config (but this
method works only for 2.6 series kernels).

the first argument to pam\_recent must be "-" or "+", the second arg
is the name of the iptables recent list. if you give no second
argument, the recent list "DEFAULT" will be used.  if you give any
other arguments, you will get a syslogged error message - as will
happen on errors.

## scenario two, pam\_recent sets and clears, firewall only enforces

if you call pam\_recent with "+" as first argument, then it will
add an entry for this client ip address.

putting the following entries in a service's pam config (order
relative to other components is essential!) will make pam\_recent
first add an entry (before the normal authentication steps commence)
and clear it if and only if authentication succeeds.

	 # put the account line BEFORE any real authentication module calls!
	 auth     required	    pam_recent.so + TESTY
	 # put the session line AFTER all required session modules
	 # you might also use the "account" pam phase here, see caveat below
	 session  required	    pam_recent.so - TESTY

a simple/single iptables rule like

	iptables -A limited -m recent --name TESTY --rcheck --hitcount 2 \
	--seconds 60 -j DROP

will then take care of enforcing your login rate limiting. this is
especially useful for services which don't terminate the network
connection after an unsuccessful login, e.g. many IMAP servers.

caveat: not all applications use all pam phases; pam\_recent logs its
activity (with the phase) so it's not too hard to determine whether
your service uses account or session.

# further info
* [my original article](http://snafu.priv.at/mystuff/recent-plus-pam.html);
  you might also want to search [my site](http://snafu.priv.at/)
  for `pam_recent` for the changes since then

* man iptables-extensions (at least on debian)

* `iptables -m recent --help`
