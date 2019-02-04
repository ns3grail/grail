/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "netlink.h"

#include "syscname.h"

#include <linux/rtnetlink.h>
#include <asm/types.h>
#include <sys/socket.h>

#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/node.h"
#include "ns3/wifi-net-device.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/loopback-net-device.h"
#include "ns3/network-module.h"

NS_LOG_COMPONENT_DEFINE ("GrailNetlink");

// converts a BSD socket API address to an ns-3 address
// note: does NOT read memory from tracee
std::shared_ptr<ns3::Address> NetlinkSocket::BsdToNs3Address(struct sockaddr* addr)
{
  if(addr->sa_family != AF_INET) {
    NS_LOG_ERROR("[EE] only AF_INET is supported, requsted address family was: "
                 << afname(addr->sa_family));
    return NULL;
  }
  unsigned short port = ntohs(((struct sockaddr_in*)addr)->sin_port);
  char addr_str[16];
  inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, addr_str, 16);

  auto ns3Addr = ns3::InetSocketAddress(ns3::Ipv4Address(addr_str),port);

  NS_LOG_LOGIC(pid << ": [EE] read address " << addr_str << ":" << port);

  return std::make_shared<ns3::Address>(ns3Addr);
}
std::shared_ptr<ns3::Ipv4Address> NetlinkSocket::BsdInAddr4ToNs3Address(struct in_addr* addr)
{
  char addr_str[16];
  inet_ntop(AF_INET, addr, addr_str, 16);

  auto ns3Addr = ns3::Ipv4Address(addr_str);

  NS_LOG_LOGIC(pid << ": [EE] read ipv4 address " << addr_str);

  return std::make_shared<ns3::Ipv4Address>(ns3Addr);
}

SyscallHandlerStatusCode NetlinkSocket::HandleBind(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
  struct sockaddr_nl _addr;
  MemcpyFromTracee(pid, &_addr, addr, sizeof(sockaddr_nl));

  if(_addr.nl_pid == 0) {
    NS_LOG_LOGIC(pid << ": [EE] [NL] zero nl_pid, substitutung");
    nl_pid = pid;
  }
  else {
    NS_LOG_LOGIC(pid << ": [EE] [NL] nl_pid is " << nl_pid);
    nl_pid = _addr.nl_pid;
  }

  NS_LOG_LOGIC(pid << ": [EE] [NL] groups is " << _addr.nl_groups);
  nl_groups = _addr.nl_groups;

  FAKE(0);
  
  return SYSC_SUCCESS;
}

SyscallHandlerStatusCode NetlinkSocket::HandleGetSockName(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
  struct sockaddr_nl _addr;

  // Linux/amd64 layout:
  // struct sockaddr_nl
  // {
  //   sa_family_t    nl_family;  /* AF_NETLINK   */
  //   unsigned short nl_pad;     /* zero         */
  //   __u32          nl_pid;     /* process pid */
  //   __u32          nl_groups;  /* mcast groups mask */
  // } nladdr;

  NS_ASSERT(addr);
  NS_ASSERT(addrlen);

  socklen_t _addrlen;
  MemcpyFromTracee(pid, &_addrlen, addrlen, sizeof(socklen_t));
  
  _addr.nl_family = AF_NETLINK;
  _addr.nl_pad = 0;
  _addr.nl_pid = nl_pid;
  _addr.nl_groups = 0;

  socklen_t copysize = (socklen_t)std::min(sizeof(_addr),(size_t)_addrlen);
  MemcpyToTracee(pid, addr, &_addr, copysize);
  MemcpyToTracee(pid, addrlen, &copysize, sizeof(socklen_t));

  FAKE(0);
  return SYSC_SUCCESS;
}

SyscallHandlerStatusCode NetlinkSocket::HandleRecvMsg(int sockfd, struct msghdr *message, int flags)
{
  //NS_ASSERT(!reply_queue.empty() && "received unexpected >recvmsg< on empty netlink reply queue!");
  if(reply_queue.empty()) {
    FAKE(-1);
    return SYSC_FAILURE;
  }
  
  nl_msg* reply = reply_queue.front();

  nlmsghdr* replyhdr = nlmsg_hdr(reply);
  size_t replylen = replyhdr->nlmsg_len;

  struct msghdr _message;
  MemcpyFromTracee(pid, &_message, message, sizeof(struct msghdr));

  // load iovec from message
  struct iovec iov;
  MemcpyFromTracee(pid, &iov, _message.msg_iov, sizeof(struct iovec));
  size_t len = iov.iov_len;
  NS_ASSERT(len >= replylen && "not enough buffer space available");
  
  MemcpyToTracee(pid, iov.iov_base, replyhdr, replylen);

  reply_queue.pop();
  nlmsg_free(reply);

  // return length
  FAKE(replylen);

  NS_LOG_LOGIC(pid << ": [EE] [NL] sent reply from queue");

  return SYSC_SUCCESS;
}

SyscallHandlerStatusCode NetlinkSocket::HandleSendMsg(int sockfd, struct msghdr *message,
                                                      int flags)
{
  struct msghdr msg;
  MemcpyFromTracee(pid, &msg, message, sizeof(msghdr));

  NS_LOG_LOGIC(pid << ": [EE] [NL] msghdr for protocol " << protocol << ":");
  NS_LOG_LOGIC(pid << ": [EE] [NL] msghdr: " << msg.msg_iovlen);

  size_t total_bytes = 0;
  
  for(size_t i=0; i<msg.msg_iovlen; i++) {
    struct iovec iov;
    MemcpyFromTracee(pid, &iov, msg.msg_iov+i, sizeof(struct iovec));
    size_t len = iov.iov_len;
    total_bytes += len;
    void* buf = malloc(len);
    MemcpyFromTracee(pid, buf, iov.iov_base, len);

    struct nlmsghdr* hdr = (nlmsghdr*)buf;
    while(nlmsg_ok(hdr, len)) {
      NS_LOG_LOGIC(pid << ": [EE] [NL] read a message");
      ProcessNlmsghdr(hdr);
      hdr = nlmsg_next(hdr, (int*)&len);
    }

    free(buf);
  }
  FAKE(total_bytes);
  return SYSC_SUCCESS; 
}

SyscallHandlerStatusCode NetlinkSocket::HandleSendTo(int sockfd, void *buf, size_t len,
                                                     int flags,
                                                     struct sockaddr *dest_addr,
                                                     socklen_t addrlen)
{
  NS_LOG_LOGIC(pid << ": [EE] [NL] socket with sockfd: " << sockfd);
  NS_LOG_LOGIC(pid << ": [EE] [NL] socket with buf: " << buf);
  NS_LOG_LOGIC(pid << ": [EE] [NL] socket with len: " << len);
  NS_LOG_LOGIC(pid << ": [EE] [NL] socket with flags: " << flags);
  NS_LOG_LOGIC(pid << ": [EE] [NL] socket with dest_addr: " << dest_addr);
  NS_LOG_LOGIC(pid << ": [EE] [NL] socket with addrlen: " << addrlen);
  
  uint8_t* _buf[len];
  MemcpyFromTracee(pid, _buf, buf, len);
  
  NS_ASSERT(flags == 0 && "NOT IMPLEMENTED");

  struct nlmsghdr* hdr = (nlmsghdr*)_buf;

  while(nlmsg_ok(hdr, len)) {
    NS_LOG_LOGIC(pid << ": [EE] [NL] read a message");
    ProcessNlmsghdr(hdr);
    hdr = nlmsg_next(hdr, (int*)&len);
  }

  FAKE(len);
  
  return SYSC_SUCCESS;
}

void NetlinkSocket::ProcessNlmsghdr(nlmsghdr* hdr) {
  switch(hdr->nlmsg_type) {
  case RTM_GETLINK:
    {
      NS_LOG_LOGIC(pid << ": [EE] [NL] " << netlinkname(hdr->nlmsg_type));
      NS_ASSERT(hdr->nlmsg_flags & NLM_F_ROOT && "NOT IMPLEMENTED");
      
      uint32_t nDevices = parentApp->GetNode()->GetNDevices();
      NS_LOG_LOGIC(pid << ": [EE] [NL] number of interfaces: " << nDevices);
      uint32_t wlani = 0, ethi = 0, loi = 0;
      for(uint32_t i=0; i<nDevices; i++) {
        struct nl_msg* reply;
        /* Allocate a default sized netlink message */
        if (!(reply = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_MULTI))) {
          NS_ASSERT(false);
        }
        struct ifinfomsg ancillary_hdr;
        ancillary_hdr.ifi_family = AF_UNSPEC;
        ancillary_hdr.ifi_type = 0;
        ancillary_hdr.ifi_index = i;
        ancillary_hdr.ifi_flags = 0;
        ancillary_hdr.ifi_change = 0;
        char ifname[16];
        if(parentApp->GetNode()->GetDevice(i)->GetObject<ns3::LoopbackNetDevice>()) {
          // loX
          sprintf(ifname, "lo%d",loi++);
        }
        else if(parentApp->GetNode()->GetDevice(i)->GetObject<ns3::WifiNetDevice>()) {
          // wlanX
          sprintf(ifname, "wlan%d",wlani++);
        }
        else if(parentApp->GetNode()->GetDevice(i)->GetObject<ns3::PointToPointNetDevice>()) {
          // ethX
          sprintf(ifname, "eth%d",ethi++);
        }
        else {
          NS_ASSERT(false && "Unsupported network interface type detected");
        }
        nlmsg_append(reply,&ancillary_hdr,sizeof(struct ifinfomsg),NLMSG_ALIGNTO);
        nla_put(reply,IFLA_IFNAME,strlen(ifname)+1,ifname);
        reply_queue.push(reply);
        if(i+1 == nDevices) {
          struct nl_msg* finalizer;
          // finalize message
          if (!(finalizer = nlmsg_alloc_simple(NLMSG_DONE, 0))) {
            NS_ASSERT(false);
          }
          reply_queue.push(finalizer);
        }
      }
      if(has_recv_callback) recv_callback();
    }
    break;
  case RTM_GETADDR:
    {
      NS_LOG_LOGIC(pid << ": [EE] [NL] " << netlinkname(hdr->nlmsg_type));
      NS_ASSERT(hdr->nlmsg_flags & NLM_F_ROOT && "NOT IMPLEMENTED");
      
      uint32_t nDevices = parentApp->GetNode()->GetNDevices();
      NS_LOG_LOGIC(pid << ": [EE] [NL] number of interfaces: " << nDevices);
      // uint32_t wlani = 0, ethi = 0, loi = 0;
      for(uint32_t i=0; i<nDevices; i++) {
        struct nl_msg* reply;
        /* Allocate a default sized netlink message */
        if (!(reply = nlmsg_alloc_simple(RTM_NEWADDR, NLM_F_MULTI))) {
          NS_ASSERT(false);
        }

        auto dev = parentApp->GetNode()->GetDevice(i);
        auto ipv4 = parentApp->GetNode()->GetObject<ns3::Ipv4>();
        uint32_t if_idx = ipv4->GetInterfaceForDevice(dev);
        ns3::Ipv4InterfaceAddress iaddr = ipv4->GetAddress (if_idx,0);
        ns3::Ipv4Address ipAddr = iaddr.GetLocal ();
        ns3::Ipv4Mask ipMask = iaddr.GetMask ();
        
        struct ifaddrmsg ancillary_hdr;
        ancillary_hdr.ifa_family = AF_INET;
        ancillary_hdr.ifa_prefixlen = ipMask.GetPrefixLength ();
        ancillary_hdr.ifa_flags = 0;
        ancillary_hdr.ifa_scope = RT_SCOPE_HOST;
        ancillary_hdr.ifa_index = i;

        nlmsg_append(reply,&ancillary_hdr,sizeof(struct ifinfomsg),NLMSG_ALIGNTO);
        uint32_t ip = ipAddr.Get();
        nla_put(reply,IFA_ADDRESS,4,&ip);
        reply_queue.push(reply);
        if(i+1 == nDevices) {
          struct nl_msg* finalizer;
          // finalize
          if (!(finalizer = nlmsg_alloc_simple(NLMSG_DONE, 0))) {
            NS_ASSERT(false);
          }
          reply_queue.push(finalizer);
        }
      }
      if(has_recv_callback) recv_callback();
    }
    break;
  case RTM_NEWROUTE:
    {
      NS_LOG_LOGIC(pid << ": [EE] [NL] " << netlinkname(hdr->nlmsg_type));

      // Message layout:
      // struct rtmsg {
      //   unsigned char rtm_family;   /* Address family of route */
      //   unsigned char rtm_dst_len;  /* Length of destination */
      //   unsigned char rtm_src_len;  /* Length of source */
      //   unsigned char rtm_tos;      /* TOS filter */
      //   unsigned char rtm_table;    /* Routing table ID */
      //   unsigned char rtm_protocol; /* Routing protocol; see below */
      //   unsigned char rtm_scope;    /* See below */
      //   unsigned char rtm_type;     /* See below */
      //   unsigned int  rtm_flags;
      // };

      NS_ASSERT(hdr->nlmsg_len > sizeof(struct nlmsghdr) && "missing netlink ancillary data");
      struct rtmsg* amsg = (rtmsg*)NLMSG_DATA(hdr);
      NS_LOG_LOGIC(pid << " route entry:");
      NS_LOG_LOGIC(pid << "   family: " << afname(amsg->rtm_family));
      NS_LOG_LOGIC(pid << "   dstlen: " << (int)amsg->rtm_dst_len);
      NS_LOG_LOGIC(pid << "   srclen: " << (int)amsg->rtm_src_len);
      NS_LOG_LOGIC(pid << "   tos   : " << (int)amsg->rtm_tos);
      NS_LOG_LOGIC(pid << "   table : " << rttablename(amsg->rtm_table));
      NS_LOG_LOGIC(pid << "   proto : " << rtprotoname(amsg->rtm_protocol));
      NS_LOG_LOGIC(pid << "   scope : " << rtscopename(amsg->rtm_scope));
      NS_LOG_LOGIC(pid << "   type  : " << rttypename(amsg->rtm_type));
      NS_LOG_LOGIC(pid << "   flags : " << (unsigned)amsg->rtm_flags);
      if(amsg->rtm_flags & RTM_F_NOTIFY) {
        NS_LOG_LOGIC(pid << "     RTM_F_NOTIFY");
        NS_ASSERT(false && "RTM_F_NOTIFY not supported");
      }
      if(amsg->rtm_flags & RTM_F_CLONED)   NS_LOG_LOGIC(pid << "     RTM_F_CLONED");
      if(amsg->rtm_flags & RTM_F_EQUALIZE) NS_LOG_LOGIC(pid << "     RTM_F_EQUALIZE");
      struct rtattr* cur_attr = (struct rtattr*)(amsg+1);
      size_t rbuflen = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(rtmsg));
      std::shared_ptr<ns3::Ipv4Address> dst, gw;
      uint8_t dst_len;
      int oif, iif, priority;
      while(RTA_OK(cur_attr, rbuflen)) {
        NS_LOG_LOGIC(pid << "   found attribute");
        switch(cur_attr->rta_type) {
        case RTA_DST:
          NS_LOG_LOGIC(pid << "   RTA_DST");
          dst = BsdInAddr4ToNs3Address((struct in_addr*)RTA_DATA(cur_attr));
          dst_len = (int)amsg->rtm_dst_len;
          break;
        case RTA_SRC:
          NS_LOG_LOGIC(pid << "   RTA_SRC");
          break;
        case RTA_GATEWAY:
          NS_LOG_LOGIC(pid << "   RTA_GW");
          gw = BsdInAddr4ToNs3Address((struct in_addr*)RTA_DATA(cur_attr));
          break;
        case RTA_PRIORITY:
          priority = *(int*)RTA_DATA(cur_attr);
          NS_LOG_LOGIC(pid << "   RTA_PRIORITY: " << priority);
          break;
        case RTA_OIF:
          oif = *(int*)RTA_DATA(cur_attr);
          NS_LOG_LOGIC(pid << "   RTA_OIF: " << oif);
          break;
        case RTA_IIF:
          iif = *(int*)RTA_DATA(cur_attr);
          NS_LOG_LOGIC(pid << "   RTA_IIF: " << iif);
          break;
        default:
          NS_LOG_ERROR(pid << ": ERROR: unknown RTA: " << rtaname(cur_attr->rta_type));
          NS_ASSERT(false && "unknown RTA attribute");
        }
        cur_attr = RTA_NEXT(cur_attr, rbuflen);
      }
      NS_LOG_LOGIC(pid << "   ---no more attributes");
      if (gw && dst) {
        router->AddRoute(*dst,dst_len,*gw);
        struct nl_msg* reply;
        /* Allocate a default sized netlink message */
        if (!(reply = nlmsg_alloc_simple(NLMSG_ERROR, NLM_F_ACK))) {
          NS_ASSERT(false);
        }
        struct nlmsgerr ancillary_hdr;
        ancillary_hdr.error = 0;
        nlmsg_append(reply,&ancillary_hdr,sizeof(ancillary_hdr),NLMSG_ALIGNTO);
        reply_queue.push(reply);
        // NS_ASSERT(false && "NOT IMPLEMENTED");
      }
      else {
        NS_LOG_LOGIC(pid << "   -> ignoring route <-");
        assert(false);
      }
    }
    break;
  case RTM_DELROUTE:
    {
      NS_LOG_LOGIC(pid << ": [EE] [NL] " << netlinkname(hdr->nlmsg_type));

      // Message layout:
      // struct rtmsg {
      //   unsigned char rtm_family;   /* Address family of route */
      //   unsigned char rtm_dst_len;  /* Length of destination */
      //   unsigned char rtm_src_len;  /* Length of source */
      //   unsigned char rtm_tos;      /* TOS filter */
      //   unsigned char rtm_table;    /* Routing table ID */
      //   unsigned char rtm_protocol; /* Routing protocol; see below */
      //   unsigned char rtm_scope;    /* See below */
      //   unsigned char rtm_type;     /* See below */
      //   unsigned int  rtm_flags;
      // };

      NS_ASSERT(hdr->nlmsg_len > sizeof(struct nlmsghdr) && "missing netlink ancillary data");
      struct rtmsg* amsg = (rtmsg*)NLMSG_DATA(hdr);
      NS_LOG_LOGIC(pid << " route entry:");
      NS_LOG_LOGIC(pid << "   family: " << afname(amsg->rtm_family));
      NS_LOG_LOGIC(pid << "   dstlen: " << (int)amsg->rtm_dst_len);
      NS_LOG_LOGIC(pid << "   srclen: " << (int)amsg->rtm_src_len);
      NS_LOG_LOGIC(pid << "   tos   : " << (int)amsg->rtm_tos);
      NS_LOG_LOGIC(pid << "   table : " << rttablename(amsg->rtm_table));
      NS_LOG_LOGIC(pid << "   proto : " << rtprotoname(amsg->rtm_protocol));
      NS_LOG_LOGIC(pid << "   scope : " << rtscopename(amsg->rtm_scope));
      NS_LOG_LOGIC(pid << "   type  : " << rttypename(amsg->rtm_type));
      NS_LOG_LOGIC(pid << "   flags : " << (unsigned)amsg->rtm_flags);
      if(amsg->rtm_flags & RTM_F_NOTIFY) {
        NS_LOG_LOGIC(pid << "     RTM_F_NOTIFY");
        NS_ASSERT(false && "RTM_F_NOTIFY not supported");
      }
      if(amsg->rtm_flags & RTM_F_CLONED)   NS_LOG_LOGIC(pid << "     RTM_F_CLONED");
      if(amsg->rtm_flags & RTM_F_EQUALIZE) NS_LOG_LOGIC(pid << "     RTM_F_EQUALIZE");
      struct rtattr* cur_attr = (struct rtattr*)(amsg+1);
      size_t rbuflen = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(rtmsg));
      std::shared_ptr<ns3::Ipv4Address> dst, gw;
      uint8_t dst_len;
      int oif, priority;
      while(RTA_OK(cur_attr, rbuflen)) {
        NS_LOG_LOGIC(pid << "   found attribute");
        switch(cur_attr->rta_type) {
        case RTA_DST:
          NS_LOG_LOGIC(pid << "   RTA_DST");
          dst = BsdInAddr4ToNs3Address((struct in_addr*)RTA_DATA(cur_attr));
          dst_len = (int)amsg->rtm_dst_len;
          break;
        case RTA_SRC:
          NS_LOG_LOGIC(pid << "   RTA_SRC");
          break;
        case RTA_GATEWAY:
          NS_LOG_LOGIC(pid << "   RTA_GW");
          gw = BsdInAddr4ToNs3Address((struct in_addr*)RTA_DATA(cur_attr));
          break;
        case RTA_PRIORITY:
          priority = *(int*)RTA_DATA(cur_attr);
          NS_LOG_LOGIC(pid << "   RTA_PRIORITY: " << priority);
          break;
        case RTA_OIF:
          oif = *(int*)RTA_DATA(cur_attr);
          NS_LOG_LOGIC(pid << "   RTA_OIF: " << oif);
          break;
        default:
          NS_ASSERT(false && "unknown RTA attribute");
        }
        cur_attr = RTA_NEXT(cur_attr, rbuflen);
      }
      NS_LOG_LOGIC(pid << "   ---no more attributes");
      if (gw && dst) {
        router->DelRoute(*dst,dst_len,*gw);
        struct nl_msg* reply;
        /* Allocate a default sized netlink message */
        if (!(reply = nlmsg_alloc_simple(NLMSG_ERROR, NLM_F_ACK))) {
          NS_ASSERT(false);
        }
        struct nlmsgerr ancillary_hdr;
        ancillary_hdr.error = 0;
        nlmsg_append(reply,&ancillary_hdr,sizeof(ancillary_hdr),NLMSG_ALIGNTO);
        reply_queue.push(reply);
      }
      else {
        NS_ASSERT(false);
        NS_LOG_LOGIC(pid << "   -> ignoring del route <-");
      }
    }
    break;
  default:
    NS_LOG_ERROR("[EE] [NL] Netlink message type not implemented: " << netlinkname(hdr->nlmsg_type));
    exit(1);
  }
}
