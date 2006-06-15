/*
 * $Id: pam_recent.c,v 1.1 2006/06/14 06:24:24 az Exp az $
 * 
 * File:		pam_recent.c
 * Date:		Wed Jun 14 16:06:11 2006
 * Author:		Alexander Zangerl (az)
 * Licence:		GPL version 1 or version 2
 
 a pam module for linux systems to adjust an iptables recent list,
 which makes rate limiting connections not penalize successful logins
 from unknown locations.

 the idea is that one uses the iptables recent match to rate-limit
 connections (eg. ssh), but does not want to penalize people who
 successfully log in.
 
 if your good clients are all known anyway (static ip etc.), then you
 have no problem and do not need this module. if however, you have
 unknown clients who you don't want to rate-limit if they manage a
 correct login, then this module allows you to clear the client's ip
 address after the login has succeeded.

 installation:
  gcc -shared -Xlinker -x -o pam_recent.so pam_recent.c  
  cp pam_recent.so /lib/modules/security/

 configuration: get your firewall to rate limit, the example here is
 ssh and assumes that these rules will only be applied to new
 connection packets (so handle existing exchanges somewhere before
 these).
	 
  iptables -A INPUT -m recent --name SSH --rcheck --hitcount 2 \
  	--seconds 60 -j DROP
  iptables -A INPUT -m recent --name SSH --set -j ACCEPT

 this allows up to two ssh connections per 60 seconds and records time
 stamps in /proc/net/ipt_recent/SSH.  then add the usual stanza to the
 pam config (here /etc/pam.d/ssh) and in the right place...

  session optional pam_recent.so - SSH

  and every successful login will clear this client's ip history.


if you give "+" as first argument, then pam_recent will add an entry
for this client ip address.  if you give no second argument, the
recent list "DEFAULT" will be used.  if you give any other arguments,
you will get a syslogged error message - as will happen on errors.

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
	 syslog(LOG_ERR,"expected \"%s\" or \"%s\" as argument, got \"%s\" %d",
		ACTION_REMOVE,ACTION_ADD,argv[0],r);
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


