/*
 * $Id: pam_recent.c,v 1.8 2009/05/11 02:33:41 az Exp az $
 * 
 * File:		pam_recent.c
 * Date:		Wed Jun 14 16:06:11 2006
 * Author:		Alexander Zangerl (az)
 * Licence:		GPL version 1 or version 2
 
 this is a pam module for linux systems to adjust an iptables recent list,
 which makes the rate limiting of connections from unknown locations
 easier.

 the idea is that one uses this module with iptables' recent module to
 rate-limit connections to authenticated services (eg. ssh and ftp) 
 without penalizing successful logins.
 
 if your good clients are all known anyway (static ip etc.), then you
 have no problem and do not need this module. if however, you have
 unknown clients who you don't want to rate-limit if they manage a
 correct login, then this module allows you to clear the client's ip
 address after the login has succeeded. you can also set/clear the
 client's ip address using this module in different pam phases, e.g.
 set in the authenticate phase and clear iff things progress to session.

 installation:
  * get the required pam libraries and headers (libpam0g-dev in debian)
  * compile the module:
  	gcc -shared -fPIC -Xlinker -x -o pam_recent.so pam_recent.c  
  * copy it to the relevant place
	cp pam_recent.so /lib/modules/security/

 configuration: 
 
 * scenario one, firewall sets and checks, pam_recent only clears

 get your firewall to rate limit, the example here 
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
 and records time stamps in /proc/net/ipt_recent/MYLIMIT (or
 /proc/net/xt_recent/... in more recent kernels).
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

 the first argument to pam_recent must be  "-" or "+", the second 
 arg is the name of the iptables recent list. if you give no second 
 argument, the recent list "DEFAULT" will be used.  
 if you give any other arguments, you will get a syslogged error 
 message - as will happen on errors.

 * scenario two, pam_recent sets and clears, firewall only enforces

 if you call pam_recent with "+" as first argument, then it will 
 add an entry for this client ip address.

 putting the following entries in a service's pam config (order relative
 to other components is essential!) will make pam_recent first
 set an entry and clear it if and only if authentication succeeds.
 
  # put the account line BEFORE any real authentication module calls!
  account  required	    pam_recent.so + TESTY
  # put the session line after all required session modules
  session  required	    pam_recent.so - TESTY

 a simple/single iptables rule like

  iptables -A limited -m recent --name TESTY --rcheck --hitcount 2
   --seconds 60 -j DROP

 will then take care of enforcing your login rate limiting. this is
 especially useful for services which don't terminate the network 
 connection after an unsuccessful login, e.g. many IMAP servers.

 caveat: not all applications use all pam phases; pam_recent logs
 its activity (with the phase) so it's not too hard to determine 
 whether your service uses account or session.

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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/_pam_macros.h>


/* internal defines */
#define ACTION_REMOVE "-"
#define ACTION_ADD "+"
#define NAME "DEFAULT"
#define MODNAME "pam_recent"
#define LOCOLD "/proc/net/ipt_recent"
#define LOCNEW "/proc/net/xt_recent"

/* pam 1.x has pam_syslog, older pam libs don't */
#if __LINUX_PAM__ >= 1
#include <security/pam_ext.h>
#define LOGIT(...) {pam_syslog(pamh,__VA_ARGS__);}
#else
#define LOGIT(...) {syslog(__VA_ARGS__);}
#endif


/* this is where it all happens... */
static int recent(pam_handle_t *pamh, int flags,
	   int argc, const char **argv)
{
   int remove,r;
   char fname[PATH_MAX], *rhostname,address[128];
   const char *dbname;
   FILE *f;
   struct hostent *rhost;

   if (argc<1 || argc>2)
   {
      LOGIT(LOG_ERR,"expected 1 or 2 arguments but got %d\n",argc);
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
	 LOGIT(LOG_ERR,
		    "expected \"%s\" or \"%s\" as argument, got \"%s\"",
		    ACTION_REMOVE,ACTION_ADD,argv[0]);
	 return PAM_SESSION_ERR;
      }
   }

   /* optional second arg: what recent db to add/remove from */   
   dbname=(argc==2)?argv[1]:NAME;
      
   /* kernel <2.6.28? ipt_recent, afterwards xt_recent */
   snprintf(fname,sizeof(fname),"%s/%s",
	    LOCNEW,dbname);
   if (access(fname,F_OK))
   {
      snprintf(fname,sizeof(fname),"%s/%s",
	    LOCOLD,dbname);
   }
   
   /* lets find out the proper ip address */
   r=pam_get_item(pamh, PAM_RHOST, (void *)&rhostname);
   if (r != PAM_SUCCESS )
   {
      LOGIT(LOG_ERR,"could not get PAM_RHOST: %s",
		 pam_strerror(pamh,r));
      return PAM_SESSION_ERR;
   }
   
   /* hmm, no rhost? seems this pam stack is misconfigured and
      we're being run for non-networked logins... */
   if (rhostname == NULL) 
   {
      LOGIT( LOG_ERR, "no PAM_RHOST, not a network login");
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
      LOGIT(LOG_ERR,
		 "could not lookup address for %s: %d",rhostname,h_errno);
      return PAM_SESSION_ERR;
   }

   if (inet_ntop(rhost->h_addrtype,
		 rhost->h_addr_list[0],
		 address,sizeof(address))!=address)
   {
      LOGIT(LOG_ERR,"address conversion error: %s",strerror(errno));
      return PAM_SESSION_ERR;
   }

   /* and write to the pseudo-file */
   if (!(f=fopen(fname,"w")))
   {
      LOGIT(LOG_ERR,"can't open %s: %s",fname,strerror(errno));
      return PAM_SESSION_ERR;
   }

   fprintf(f,"%s%s\n",
	   remove?ACTION_REMOVE:ACTION_ADD,address);
   fclose(f);
   LOGIT(LOG_DEBUG,
	      (remove?"removed %s/%s from list %s":"added %s/%s to list %s"),
	      rhostname,address,dbname);
   return PAM_SUCCESS;
}

/* pam entry points */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{    
   return recent(pamh,flags,argc,argv);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,int argc, const char **argv)
{    
   return recent(pamh,flags,argc,argv);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,int argc, const char **argv)
{    
   return recent(pamh,flags,argc,argv);
}



/* helper functions that don't apply to pam_recent but which need to be provided regardless  */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
   return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
   return PAM_SUCCESS;
}


/* version history:

   $Log: pam_recent.c,v $
   Revision 1.8  2009/05/11 02:33:41  az
   added backwards-compatibility for logging: pam 1+ use pam_syslog, older ones use syslog straight.

   Revision 1.7  2009/05/06 01:58:02  az
   fixed stupid mistake regarding fallback for kernels < 2.6.28

   Revision 1.6  2009/03/20 02:16:58  az
   Thomas Kula (tkula at umich.edu) suggested a bit more robustness for
   situations where pam_recent is run (uselessly) for non-networked logins,
   and to use pam_syslog.

   Revision 1.5  2009/02/25 11:16:35  az
   Till Elsner (Till.Elsner at uni-duesseldorf.de) suggested some doc fixes and
   another header inclusion that seems to be necessary on ubuntu boxes.

   also added support for ipt_recent in 2.6.28+, which uses a different /proc directory by default
   (but staying backwards-compatible).

   Revision 1.4  2007/12/11 11:32:54  az
   Robert Scheck (robert at fedoraproject.org) suggested I get rid of
   a compiler warning by doing less silly things. I hereby comply :-)

   (the code syslogged a nonsensical variable in case of bad arguments.)

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
