/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#ifndef __NETLINK_H__
#define __NETLINK_H__

#include <linux/netlink.h>
#include <netlink/msg.h>
#include <queue>
#include <memory>

#include "ns3/application.h"
#include "ns3/ipv4.h"

#include "ptrace-utils.h"
#include "route.h"

class NetlinkSocket {
public:
  NetlinkSocket(int pid, int protocol, ns3::Ptr<ns3::Application> parent,
                ns3::Ptr<ns3::HgRoutingProtocol> routingProtocol)
    :pid(pid)
    ,protocol(protocol)
    ,has_recv_callback(false)
    ,parentApp(parent)
    ,router(routingProtocol)
  {}

  SyscallHandlerStatusCode HandleBind(int sockfd, struct sockaddr* addr, socklen_t addrlen);
  SyscallHandlerStatusCode HandleGetSockName(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
  SyscallHandlerStatusCode HandleSendTo(int sockfd, void *buf, size_t len, int flags,
                                        struct sockaddr *dest_addr, socklen_t addrlen);
  SyscallHandlerStatusCode HandleRecvMsg(int sockfd, struct msghdr *message, int flags);
  SyscallHandlerStatusCode HandleSendMsg(int sockfd, struct msghdr *message, int flags);
  
  inline bool HasData() const {return !reply_queue.empty();};

  void SetRecvCallback(std::function<void()> f) {
    recv_callback = f;
    has_recv_callback = true;
  }
  void UnsetRecvCallback() {has_recv_callback = false;}

  std::shared_ptr<ns3::Address> BsdToNs3Address(struct sockaddr* addr);
  std::shared_ptr<ns3::Ipv4Address> BsdInAddr4ToNs3Address(struct in_addr* addr);

private:
  int pid;
  int nl_pid;
  int nl_groups;
  int protocol;

  std::queue<nl_msg*> reply_queue;
  std::function<void()> recv_callback;
  bool has_recv_callback;

  void ProcessNlmsghdr(nlmsghdr* hdr);

  ns3::Ptr<ns3::Application> parentApp;
  ns3::Ptr<ns3::HgRoutingProtocol> router;
};

#define UNSUPPORTED(msg) do {                              \
    NS_LOG_ERROR(pid << ": [EE] UNSUPPORTED: " << msg);  \
    return SYSC_ERROR;                                      \
  } while(0)

#endif //__NETLINK_H__
