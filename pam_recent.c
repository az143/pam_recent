/*
 * $Id: pam_recent.c,v 1.3 2007/05/20 04:22:18 az Exp az $
 * 
 * File:		pam_recent.c
 * Date:		Wed Jun 14 16:06:11 2006
 * Author:		Alexander Zangerl (az)
 * Licence:		GPL version 1 or version 2
 
 a pam module for linux systems to adjust an iptables recent list,
 which makes the rate limiting of connections from unknown locations
 easier.

 the idea is that one uses this module with iptables' recent module to
 rate-limit connections to authenticated services (eg. ssh and ftp) 
 without penalizing successful logins.
 
 if your good clients are all known anyway (static ip etc.), then you
 have no problem and do not need this module. if however, you have
 unknown clients who you don't want to rate-limit if they manage a
 correct login, then this module allows you to clear the client's ip
 address after the login has succeeded.

 installation:
  gcc -shared -fPIC -Xlinker -x -o pam_recent.so pam_recent.c  
  cp pam_recent.so /lib/modules/security/

 configuration: get your firewall to rate limit, the example here 
 is for ssh and ftp and assumes that these rules will only be 
 applied to new connection packets (so handle existing exchanges 
 somewhere before these). the example also uses a custom chain
 called limited to show how multiple services may be conveniently
 grouped together in one rate-limited set.

  # ...somewhere after handling packets that belong to existing conns:
 iptables -A INPUT -p tcp --dport 22 -j limited # ssh
 iptables -A INPUT -p tcp --dport 21 -j limited # ftp

 iptables -A limited -m recent --name MYLIMIT --rcheck --hitcount 2 \
  	--seconds 60 -j DROP
 iptables -A sshlimited -m recent --name MYLIMIT --set -j ACCEPT 

 this allows up to two new ssh or ftp connections per 60 seconds 
 and records time stamps in /proc/net/ipt_recent/MYLIMIT. 
 then add the usual stanza to the relevant pam config files 
 (here /etc/pam.d/ssh and ftp) in the right place (order matters!):

  session optional pam_recent.so - MYLIMIT

 and every successful login will clear this client's ip history,
 if pam was invoked with sufficient privileges (as root)
 or if you have modified the permissions of the ipt_recent files 
 in proc. This can be done globally via ipt_recent's module parameters
 (see the iptables manpage) or by simply chown/chmod'ing the 
 files in /proc/net/ipt_recent after loading your firewall config
 (but this method works only for 2.6 series kernels).

 if you give "+" as first argument, then pam_recent will add an entry
 for this client ip address.  if you give no second argument, the
 recent list "DEFAULT" will be used.  if you give any other arguments,
 you will get a syslogged error message - as will happen on errors.

 one final caveat: ipt_recent does not work for ipv6 addresses,
 so this module can not support ipv6 either.

 changelog: at the end of the file
*/

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/_pam_macros.h>


/* internal defines */
#define ACTION_REMOVE "-"
#define ACTION_ADD "+"
#define NAME "DEFAULT"
#define MODNAME "pam_recent"
#define LOC "/proc/net/ipt_recent"

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
   return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
   int remove,r;
   char fname[PATH_MAX], *rhostname,address[128];
   const char *dbname;
   FILE *f;
   struct hostent *rhost;

   openlog(MODNAME,0,LOG_AUTHPRIV);

   if (argc<1 || argc>2)
   {
      syslog(LOG_ERR,"expected 1 or 2 arguments but got %d\n",argc);
      return PAM_SESSION_ERR;
   }

   if (!strcmp(argv[0],ACTION_ADD))
      remove=0;
   else
   {
      if (!strcmp(argv[0],ACTION_REMOVE))
	 remove=1;
      else
      {
	 syslog(LOG_ERR,"expected \"%s\" or \"%s\" as argument, got \"%s\"",
		ACTION_REMOVE,ACTION_ADD,argv[0]);
	 return PAM_SESSION_ERR;
      }
   }
   
   dbname=(argc==2)?argv[1]:NAME;
      
   /* optional second arg: what recent db to add/remove from */
   snprintf(fname,sizeof(fname),"%s/%s",
	    LOC,dbname);
   
   /* lets find out the proper ip address */
   r=pam_get_item(pamh, PAM_RHOST, (void *)&rhostname);
   if (r != PAM_SUCCESS )
   {
      syslog(LOG_ERR,"could not get PAM_RHOST: %s",pam_strerror(pamh,r));
      return PAM_SESSION_ERR;
   }
   rhost=gethostbyname(rhostname);
   /* rfc1884, 2.2.3: ipv4 addresses in ipv6 mixed notation
      6 colon entries (all zero or 5 zeros, then ffff), 
      then the usual dotted-quad,
      or ::1.2.3.4 or ::ffff:1.2.3.4
      but somehow glibc's gethostbyname doesn't grok these,
      so we extract the ipv4 part by hand. gah.
    */
   if (!rhost && strchr(rhostname,':'))
   {
      char *p=NULL;
      if (!strncmp(rhostname,"::",2))
      {
	 p=rhostname+2;
	 if (!strncasecmp(p,"ffff:",5))
	    p+=5;
      }
      else if (!strncasecmp(rhostname,"0:0:0:0:0:",10))
      {
	 p=rhostname+10;
	 if (!strncasecmp(p,"0:",2))
	    p+=2;
	 else if (!strncasecmp(p,"ffff:",5))
	    p+=5;
      }
      if (p)
	 rhost=gethostbyname(p);
   }
   if (!rhost)
   {
      syslog(LOG_ERR,"could not lookup address for %s: %d",rhostname,h_errno);
      return PAM_SESSION_ERR;
   }

   if (inet_ntop(rhost->h_addrtype,
		 rhost->h_addr_list[0],
		 address,sizeof(address))!=address)
   {
      syslog(LOG_ERR,"address conversion error: %s",strerror(errno));
      return PAM_SESSION_ERR;
   }

   /* and write to the pseudo-file */
   if (!(f=fopen(fname,"w")))
   {
      syslog(LOG_ERR,"can't open %s: %s",fname,strerror(errno));
      return PAM_SESSION_ERR;
   }

   fprintf(f,"%s%s\n",
	   remove?ACTION_REMOVE:ACTION_ADD,address);
   fclose(f);
   syslog(LOG_DEBUG,(remove?"removed %s/%s from list %s":"added %s/%s to list %s"),
		     rhostname,address,dbname);
   return PAM_SUCCESS;
}


/* version history:

   $Log: pam_recent.c,v $
   Revision 1.3  2007/05/20 04:22:18  az
   fixed the handling of ipv4 addresses in ipv6 syntax, applied
   some documentation updates and extended the documentation somewhat.
   thanks to Tony Nelson (tonynelson at georgeanelson.com) for the
   problem report and the patch.


   revision 1.2	2006/06/15 05:00:02	az
   updated/reformatted docs

   revision 1.1 2006/06/14 06:24:24	az
   Initial revision
*/
