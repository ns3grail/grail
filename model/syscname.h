/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

/*
 * This file contains mappings from symbolic Linux constants' identifiers to strings of the symbolic name.
 * CASESC is the main utility macro here, it converts a symbol to its string.
 * This file contains mappings for several groups of symbols, such as:
 *  System calls:       syscname()
 *  IOCTL commands:     ioctlname()
 *  Socket options:     sockoptname()
 *  ... (and much more, see below)
 */

#ifndef __SYSCNAME_H__
#define __SYSCNAME_H__

#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/wireless.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>

#define CASESC(sc_name) case sc_name: return #sc_name;

inline std::string syscname(int syscall) {
  switch(syscall) {
    CASESC(SYS_execve);
    CASESC(SYS_brk);
    CASESC(SYS_mprotect);
    CASESC(SYS_getpid);
    CASESC(SYS_fstat);
    CASESC(SYS_access);
    CASESC(SYS_open);
    CASESC(SYS_mmap);
    CASESC(SYS_munmap);
    CASESC(SYS_getrlimit);
    CASESC(SYS_getcwd);
    CASESC(SYS_lseek);
    CASESC(SYS_readahead);
    CASESC(SYS_set_tid_address);
    CASESC(SYS_set_robust_list);
    CASESC(SYS_get_robust_list);
    CASESC(SYS_arch_prctl);
    CASESC(SYS_rt_sigaction);
    CASESC(SYS_rt_sigprocmask);
    CASESC(SYS_futex);
    CASESC(SYS_gettid);
    CASESC(SYS_tgkill);
    CASESC(SYS_uname);
    CASESC(SYS_close);
    CASESC(SYS_ioctl);
    CASESC(SYS_dup);
    CASESC(SYS_read);
    CASESC(SYS_stat);
    CASESC(SYS_fcntl);
    CASESC(SYS_exit_group);
    CASESC(SYS_getsockname);
    CASESC(SYS_write);
    CASESC(SYS_socket);
    CASESC(SYS_sendto);
    CASESC(SYS_recvfrom);
    CASESC(SYS_recvmsg);
    CASESC(SYS_sendmsg);
    CASESC(SYS_nanosleep);
    CASESC(SYS_bind);
    CASESC(SYS_poll);
    CASESC(SYS_getrandom);
    CASESC(SYS_getuid);
    CASESC(SYS_geteuid);
    CASESC(SYS_getgid);
    CASESC(SYS_getegid);
    CASESC(SYS_setsockopt);
    CASESC(SYS_select);
    CASESC(SYS_pipe2);
    CASESC(SYS_clone);
    CASESC(SYS_time);
    CASESC(SYS_gettimeofday);
    CASESC(SYS_prlimit64);
    CASESC(SYS_listen);
    CASESC(SYS_clock_gettime);
    CASESC(SYS_getrusage);
    CASESC(SYS_connect);
    CASESC(SYS_getsockopt);
    CASESC(SYS_accept);
    CASESC(SYS_getpeername);
    CASESC(SYS_unlink);
    CASESC(SYS_ftruncate);
    CASESC(SYS_openat);
    CASESC(SYS_clock_getres);
    CASESC(SYS_readlink);
  }
  std::stringstream ss;
  ss << syscall;
  return ss.str();
}
inline std::string ioctlname(int n) {
  switch(n) {
    CASESC(SIOCGIFFLAGS);
    CASESC(SIOCSIFFLAGS);
    CASESC(SIOCGIWNAME);
    CASESC(SIOCGIFADDR);
    CASESC(SIOCGIFBRDADDR);
    CASESC(SIOCGIFMTU);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string sockoptname(int n) {
  switch(n) {
    CASESC(SO_PRIORITY);
    
    CASESC(SO_DEBUG);        // 1
    CASESC(SO_REUSEADDR);    // 2
    CASESC(SO_TYPE);         // 3
    CASESC(SO_ERROR);        // 4
    CASESC(SO_DONTROUTE);    // 5
    CASESC(SO_BROADCAST);    // 6
    CASESC(SO_RCVBUF);       // 8
    CASESC(SO_SNDBUF);       // 8
    CASESC(SO_KEEPALIVE);    // 9
    CASESC(SO_OOBINLINE);    // 10
    CASESC(SO_LINGER);       // 13
    CASESC(SO_REUSEPORT);    // 15
    CASESC(SO_RCVLOWAT);     // 18
    CASESC(SO_SNDLOWAT);     // 19
    CASESC(SO_RCVTIMEO);     // 20
    CASESC(SO_SNDTIMEO);     // 21
    CASESC(SO_BINDTODEVICE); // 25
    CASESC(SO_ACCEPTCONN);   // 30
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string tcpsockoptname(int n) {
  switch(n) {
    CASESC(TCP_CONGESTION);
    CASESC(TCP_MAXSEG);
    CASESC(TCP_INFO);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string fcntlname(int n) {
  switch(n) {
    CASESC(F_DUPFD);
    CASESC(F_DUPFD_CLOEXEC);
    CASESC(F_GETFD);
    CASESC(F_SETFD);
    CASESC(F_GETFL);
    CASESC(F_SETFL);
    CASESC(F_SETLK);
    CASESC(F_SETLKW);
    /* CASESC(); */
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string socksendflagname(int n) {
  switch(n) {
    CASESC(MSG_CONFIRM);
    CASESC(MSG_DONTROUTE);
    CASESC(MSG_DONTWAIT);
    CASESC(MSG_EOR);
    CASESC(MSG_MORE);
    CASESC(MSG_NOSIGNAL);
    CASESC(MSG_OOB);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string netlinkname(int n) {
  switch(n) {
    CASESC(RTM_GETLINK);
    CASESC(RTM_NEWLINK);
    CASESC(RTM_DELLINK);
    CASESC(RTM_GETROUTE);
    CASESC(RTM_NEWROUTE);
    CASESC(RTM_DELROUTE);
    CASESC(RTM_GETADDR);
    CASESC(RTM_NEWADDR);
    CASESC(RTM_DELADDR);
    CASESC(NLMSG_DONE);
    CASESC(NLMSG_ERROR);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string afname(int n) {
  switch(n) {
    CASESC(AF_INET); // == AF_LOCAL
    CASESC(AF_UNIX);
    CASESC(AF_NETLINK);
    CASESC(AF_INET6);
    CASESC(AF_IPX);
    CASESC(AF_PACKET);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string rttypename(int n) {
  switch(n) {
    CASESC(RTN_UNSPEC);
    CASESC(RTN_UNICAST);
    CASESC(RTN_LOCAL);
    CASESC(RTN_BROADCAST);
    CASESC(RTN_ANYCAST);
    CASESC(RTN_MULTICAST);
    CASESC(RTN_BLACKHOLE);
    CASESC(RTN_UNREACHABLE);
    CASESC(RTN_PROHIBIT);
    CASESC(RTN_THROW);
    CASESC(RTN_NAT);
    CASESC(RTN_XRESOLVE);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string rtaname(int n) {
  switch(n) {
    CASESC(RTA_UNSPEC);
    CASESC(RTA_DST);
    CASESC(RTA_SRC);
    CASESC(RTA_IIF);
    CASESC(RTA_OIF);
    CASESC(RTA_GATEWAY);
    CASESC(RTA_PRIORITY);
    CASESC(RTA_PREFSRC);
    CASESC(RTA_METRICS);
    CASESC(RTA_MULTIPATH);
    CASESC(RTA_PROTOINFO);
    CASESC(RTA_FLOW);
    CASESC(RTA_CACHEINFO);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string rttablename(int n) {
  switch(n) {
    CASESC(RT_TABLE_UNSPEC);
    CASESC(RT_TABLE_DEFAULT);
    CASESC(RT_TABLE_MAIN);
    CASESC(RT_TABLE_LOCAL);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string rtprotoname(int n) {
  switch(n) {
    CASESC(RTPROT_UNSPEC);
    CASESC(RTPROT_REDIRECT);
    CASESC(RTPROT_KERNEL);
    CASESC(RTPROT_BOOT);
    CASESC(RTPROT_STATIC);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}
inline std::string rtscopename(int n) {
  switch(n) {
    CASESC(RT_SCOPE_UNIVERSE);
    CASESC(RT_SCOPE_SITE);
    CASESC(RT_SCOPE_LINK);
    CASESC(RT_SCOPE_HOST);
    CASESC(RT_SCOPE_NOWHERE);
  }
  std::stringstream ss;
  ss << n;
  return ss.str();
}

#endif //__SYSCNAME_H__
