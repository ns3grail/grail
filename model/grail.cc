/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "grail.h"

#include "lambda-callbacks.h"
#include "lambda-events.h"
#include "ptrace-utils.h"
#include "netlink.h"
#include "syscname.h"
#include "poll-detector.h"

#include <bits/types.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/random.h>
#include <linux/netlink.h>
#include <linux/wireless.h>
#include <linux/if.h>

#include <set>
#include <regex>
#include <functional>
#include <unordered_map>
#include <memory>
#include <tuple>
#include <utility>
#include <sstream>

#include "ns3/ipv4-list-routing.h"
#include "ns3/log.h"
#include "ns3/network-module.h"
#include "ns3/ipv4.h"
#include "ns3/socket.h"
#include "ns3/tcp-socket.h"
#include "ns3/random-variable-stream.h"
#include "ns3/wifi-net-device.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/tcp-socket-base.h"

#ifndef __amd64__
#error "As of now, the gRaIL implementation only supports the amd64 platform"
#endif
#ifndef __linux__
#error "As of now, the gRaIL implementation only supports the Linux platform"
#endif

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("GrailApplication");

NS_OBJECT_ENSURE_REGISTERED (GrailApplication);

#define SHOW_DEFINE(x) printf("%s=%s\n", #x, STR(x))

TypeId
GrailApplication::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::GrailApplication")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<GrailApplication> ()
    .AddAttribute ("PrintStdout",
                   "Prints app's stdout and stderr to stdout",
                   BooleanValue (false),
                   MakeBooleanAccessor (&GrailApplication::m_printStdout),
                   MakeBooleanChecker ())
    .AddAttribute ("EnableRouting",
                   "Use routing table that the application modifies",
                   BooleanValue (true),
                   MakeBooleanAccessor (&GrailApplication::m_enableRouting),
                   MakeBooleanChecker ())
    .AddAttribute ("MayQuit",
                   "Consider it not an error if the application quits",
                   BooleanValue (false),
                   MakeBooleanAccessor (&GrailApplication::m_mayQuit),
                   MakeBooleanChecker ())
    .AddAttribute ("EnablePreloading",
                   "Use pre-loading technique to work around an enabled vDSO kernel flag.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&GrailApplication::m_enablePreloading),
                   MakeBooleanChecker ())
    .AddAttribute ("SyscallProcessingTime",
                   "The simulated time accounted for by each system call.",
                   TimeValue (NanoSeconds(0)),
                   MakeTimeAccessor (&GrailApplication::m_syscallProcessingTime),
                   MakeTimeChecker ())
    .AddAttribute ("PollLoopDetection",
                   "Use a detection heuristic and backoff strategy for poll loops.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&GrailApplication::m_pollLoopDetection),
                   MakeBooleanChecker ())
  ;
  return tid;
}

// Private struct that holds all of gRaIL's state for one application. 
struct GrailApplication::Priv
{
#define PNAME pid
  pid_t pid;
  pid_t fake_pid;
  std::vector<std::string> args;
  Ptr<GrailApplication> app;
  Ptr<HgRoutingProtocol> rt;

  // State that could as well be ns-3 attributes in the future:
  uint32_t gid;
  uint32_t egid;
  uint32_t uid;
  uint32_t euid;  

  // State to maintain for the protocol process  
  Ptr<UniformRandomVariable> rng;        // A pseudo-random number generator
  std::set<int> availableFDs;            // A set of not-yet-used, emulated file descriptors.
  std::set<int> m_random_fds;            // FD us used to access /dev/random or /dev/urandom
  std::map<int,Ptr<Socket> > m_sockets;  // A mapping of (emulated) file descriptors to ns-3 sockets
  std::set<int> m_tcpSockets;            // FD is socket and is a TCP socket
  std::set<int> m_connectedSockets;      // FD is socket and is a connected state TCP socket
  std::set<int> m_isListenTcpSocket;     // FD is socket and is a listening TCP socket
  std::set<int> m_nonblocking_sockets;   // FD is socket and was set to SO_NONBLOCKING
  std::map<int,std::shared_ptr<NetlinkSocket> > m_netlinks; // A mapping from FD to a NetlinkSocket
  // Due to ns-3 limitations, sockets must be accepted before a call to accept was issued.
  // We coin these sockets "fake accepted" and store them here.
  std::map<int,std::tuple<Ptr<Socket>,Address>> m_fakeAcceptedSockets; 

  // Returns a new, unused file descriptor.
  int GetNextFD() {
    NS_ASSERT(availableFDs.begin() != availableFDs.end() && "Out of file descriptors!");
    int fd = *availableFDs.begin();
    availableFDs.erase(fd);
    return fd;
  }

  // Used to detect poll loops with a very simple heuristric and add an exponential delay to system call processing time.
  PollLoopDetector<SimpleGettimeofdaySelectLoopDetector, ExponentialBackoffStrategy> pollLoopDetector;
  
  int DoTrace();
  
  void ProcessStatusCode(SyscallHandlerStatusCode res, int syscall) {
    if(res == SYSC_MANUAL) {
      // do nothing and do not report
      // useful when calling callback directly, see e.g. HandleRecvFrom
    } else if(res == SYSC_SUCCESS) {
      NS_LOG_LOGIC(PNAME << ": [EE] [" << Simulator::Now().GetSeconds() << "s] emulated function succeeded, rr; syscall: " << syscname(syscall));
      Simulator::Schedule(app->m_syscallProcessingTime + pollLoopDetector.GetDelay(), &Priv::HandleSyscallBefore, this);
      return;
    } else if(res == SYSC_FAILURE) {
      NS_LOG_LOGIC(PNAME << ": [EE] emulated function failed, rr; syscall: " << syscname(syscall));
      Simulator::Schedule(app->m_syscallProcessingTime + pollLoopDetector.GetDelay(), &Priv::HandleSyscallBefore, this);
      return;
    } else if(res == SYSC_ERROR) {
      NS_LOG_ERROR(PNAME << ": [EE] emulated function crashed, syscall: " << syscname(syscall));
      exit(1);
    } else if(res == SYSC_DELAYED) {
      NS_LOG_LOGIC(PNAME << ": [EE] emulated function is delayed");
      // do nothing, handler is expected to register required events
    } else if(res == SYSC_SYSTEM_EXIT) {
      if(app->m_mayQuit) {
        NS_LOG_LOGIC(PNAME << ": [EE] emulated application's execution completed");
      } else {
        NS_LOG_ERROR(PNAME << ": [EE] emulated application's execution completed");
        exit(1);
      }
    } else {
      NS_ASSERT(false);
    }
  }

  // This is the main loop entry point, which inspects each issued system call and selectively runs the call's appropriate handler.
  void HandleSyscallBefore() {
    if (WaitForSyscall(pid) != 0) {
      return;
    }
    int syscall = get_reg(pid, orig_rax);
    NS_LOG_LOGIC(pid << ": [EE] [" << Simulator::Now().GetSeconds() << "s] caught syscall: " << syscname(syscall));

    if(app->m_pollLoopDetection) {
      Time t = pollLoopDetector.HandleSystemCall(pid, syscall);
      if ( t > Seconds(0) ) {
        NS_LOG_LOGIC(pid << ": [EE] [" << Simulator::Now().GetSeconds() << "s] poll loop detected, current delay: " << t);
      }
    }

    SyscallHandlerStatusCode res;
    
    switch(syscall) {
      // Category I, i.e., no relevant IO:
    case SYS_execve:
    case SYS_brk:
    case SYS_mprotect:

      // File system IO only. Since gRaIL currently exposes the file system by design, same handling as category I.
    case SYS_fstat:
    case SYS_unlink:
    case SYS_access:
    case SYS_mmap:
    case SYS_munmap:
    case SYS_getrlimit:
    case SYS_getcwd:
    case SYS_lseek:
    case SYS_readahead:
    case SYS_umask:
    case SYS_ftruncate:
    case SYS_readlink:

      // Category I, but may need further research when multi-threading is supported:
    case SYS_prlimit64:
    case SYS_set_tid_address:
    case SYS_set_robust_list:
    case SYS_get_robust_list:
    case SYS_arch_prctl:

      // Category I for now, but definitely needs further research when multi-threading or signals are supported.
    case SYS_rt_sigaction:   // can block wait?
    case SYS_rt_sigprocmask: // can block wait?
    case SYS_futex:          // MT?
    case SYS_gettid:         // MT?
    case SYS_tgkill:         // MT?

      // Category I, but should become category II at some point:
    case SYS_uname:  // tor uses this for node name guessing, should be user specifiable as ns-3 attribute.

      // Pass through to kernel
      res = HandleSyscallAfter();
      break;

      // The following system call could be run on sockets' FDs, but are category I on normal file sytsem FDs since we currently expose the file system by design:
    case SYS_dup:
    case SYS_stat:

      if(FdIsEmulatedSocket()) {
        NS_LOG_ERROR(pid << "[EE] system call is not implemented to work on emulated file descriptors such as sockets");
        exit(1);
      } else {
        res = HandleSyscallAfter();
      }
      break;

      // The remaining system calls are partly or fully re-implemented:
    case SYS_read:
      res = HandleRead();
      break;
    case SYS_open:
      res = HandleOpen();
      break;
    case SYS_openat: // in.tftpd uses this file/directory access
      res = HandleOpenAt();
      break;
    case SYS_close:
      res = HandleClose();
      break;
    case SYS_pipe2:
      res = HandlePipe2();
      break;
    case SYS_getpid:
      res = HandleGetPid();
      break;
    case SYS_ioctl:
      res = HandleIoctl();
      break;
    case SYS_fcntl:
      res = HandleFcntl();
      break;
    case SYS_exit_group:
      res = SYSC_SYSTEM_EXIT;
      break;
    case SYS_getsockname:
      res = HandleGetSockName();
      break;
    case SYS_getpeername:
      res = HandleGetPeerName();
      break;
    case SYS_write:
      res = HandleWrite();
      break;
    case SYS_setsockopt:
      res = HandleSetSockOpt();
      break;
    case SYS_getsockopt:
      res = HandleGetSockOpt();
      break;
    case SYS_socket:
      res = HandleSocket();
      break;
    case SYS_connect:
      res = HandleConnect();
      break;
    case SYS_listen:
      res = HandleListen();
      break;
    case SYS_sendto:
      res = HandleSendTo();
      break;
    case SYS_recvfrom:
      res = HandleRecvFrom();
      break;
    case SYS_accept:
      res = HandleAccept(); 
      break;
    case SYS_recvmsg:
      res = HandleRecvMsg();
      break;
    case SYS_sendmsg:
      res = HandleSendMsg();
      break;
    case SYS_nanosleep:
      res = HandleNanoSleep();
      break;
    case SYS_time:
      res = HandleTime();
      break;
    case SYS_gettimeofday:
      res = HandleGetTimeOfDay();
      break;
    case SYS_clock_gettime:
      res = HandleClockGetTime();
      break;
    case SYS_clock_getres:
      res = HandleClockGetRes();
      break;
    case SYS_bind:
      res = HandleBind();
      break;
    case SYS_poll:
      res = HandlePoll();
      break;
    case SYS_getrandom:
      res = HandleGetRandom();
      break;
    case SYS_select:
      res = HandleSelect();
      break;
    case SYS_getrusage:
      res = HandleGetRUsage();
      break;
      // user permissions (for now fixed result (root), but could configurable via an ns-3 attribute in the future)
    case SYS_getuid:
      res = SYSC_SUCCESS;
      FAKE2(uid);
      break;
    case SYS_geteuid:
      res = SYSC_SUCCESS;
      FAKE2(euid);
      break;
    case SYS_getgid:
      res = SYSC_SUCCESS;
      FAKE2(gid);
      break;
    case SYS_getegid:
      res = SYSC_SUCCESS;
      FAKE2(egid);
      break;

    default:
      NS_LOG_ERROR(pid << ": [EE] unsupported system call: " << syscname(syscall));
      exit(1);
    }
    ProcessStatusCode(res, syscall);
  }

  // converts a BSD socket API address to an ns-3 address
  // note: reads memory from tracee
  std::shared_ptr<Address> GetNs3Address(struct sockaddr* addr, socklen_t addrlen)
  {
    struct sockaddr _addr;
    NS_ASSERT(addrlen <= sizeof(sockaddr));
    MemcpyFromTracee(pid, &_addr,addr,addrlen);

    if(_addr.sa_family != AF_INET) {
      NS_LOG_ERROR("[EE] only AF_INET is supported, requsted address family was: " << _addr.sa_family);
      return NULL;
    }
    unsigned short port = ntohs(((struct sockaddr_in*)&_addr)->sin_port);
    char addr_str[16];
    inet_ntop(AF_INET, &((struct sockaddr_in*)&_addr)->sin_addr, addr_str, 16);

    auto ns3Addr = InetSocketAddress(Ipv4Address(addr_str),port);

    NS_LOG_LOGIC(pid << ": [EE] read address " << addr_str << ":" << port);

    return std::make_shared<Address>(ns3Addr);
  }
  // converts an ns-3 address to a BSD socket API address
  // note: reads from and writes to tracee's memory 
  bool SetBsdAddress(const Address& ns3Address, struct sockaddr* addr, socklen_t* addrlen)
  {
    if(addr == NULL) {
      // sender address not requested by tracee
      return true;
    }
    if (!InetSocketAddress::IsMatchingType(ns3Address)) {
      NS_LOG_ERROR(pid << ": [EE] unsupported address type: " << ns3Address);
      return false;
    }

    auto ns3InetAddr = InetSocketAddress::ConvertFrom(ns3Address);

    // struct sockaddr_in
    // {
    //   short            sin_family;   // e.g. AF_INET, AF_INET6
    //   unsigned short   sin_port;     // e.g. htons(3490)
    //   struct in_addr   sin_addr;     // see struct in_addr, below
    //   char             sin_zero[8];  // zero this if you want to
    // };

    struct sockaddr_in cAddr;
    memset(&cAddr,0,sizeof(cAddr));
    socklen_t cAddrSize = sizeof(struct sockaddr_in);
    socklen_t _addrlen;
    MemcpyFromTracee(pid, &_addrlen, addrlen, sizeof(socklen_t));
    size_t copylen = std::min(_addrlen, cAddrSize);

    // port and family
    cAddr.sin_family = AF_INET;
    cAddr.sin_port   = htons(ns3InetAddr.GetPort());

    // ipv4 address
    {
      std::stringstream ss;
      ns3InetAddr.GetIpv4().Print(ss);
      NS_LOG_LOGIC(pid << ": [EE] parsed ip address: " << ss.str().c_str());
      inet_pton(AF_INET, ss.str().c_str(), &cAddr.sin_addr);
    }
    
    MemcpyToTracee(pid, addr, &cAddr, copylen);
    // in case you wonder: yes, copy minimum, but write struct size...
    //  - consult recvfrom(2) for the gory details.
    MemcpyToTracee(pid, addrlen, &cAddrSize, sizeof(socklen_t));
    return true;
  }
  // addr is local variable
  void MakeBsdAddress(const ns3::Ipv4Address& ns3Address, struct sockaddr_in* addr)
  {
    // struct sockaddr_in
    // {
    //   short            sin_family;   // e.g. AF_INET, AF_INET6
    //   unsigned short   sin_port;     // e.g. htons(3490)
    //   struct in_addr   sin_addr;     // see struct in_addr, below
    //   char             sin_zero[8];  // zero this if you want to
    // };

    // port and family
    addr->sin_family = AF_INET;

    // ipv4 address
    {
      std::stringstream ss;
      ns3Address.Print(ss);
      NS_LOG_LOGIC(pid << ": [EE] parsed ip address: " << ss.str().c_str());
      inet_pton(AF_INET, ss.str().c_str(), &addr->sin_addr);
    }
  }
  void MakeBsdAddress(const ns3::Ipv4Mask& ns3Mask, struct sockaddr_in* addr)
  {
    // struct sockaddr_in
    // {
    //   short            sin_family;   // e.g. AF_INET, AF_INET6
    //   unsigned short   sin_port;     // e.g. htons(3490)
    //   struct in_addr   sin_addr;     // see struct in_addr, below
    //   char             sin_zero[8];  // zero this if you want to
    // };

    // port and family
    addr->sin_family      = AF_INET;
    addr->sin_addr.s_addr = htons(ns3Mask.Get ());
  }

  SyscallHandlerStatusCode HandleSyscallAfter() {
    if (WaitForSyscall(pid) != 0) {
      return SYSC_ERROR;
    }
    int retval = get_reg(pid, rax);
    NS_LOG_LOGIC(pid << ": [EE] SYSTEM syscall returned: " << retval);

    return SYSC_SUCCESS;
  }

  bool FdIsEmulatedSocket(int fd) {

    if(m_netlinks.find(fd) != m_netlinks.end()) {
      return true;
    }
    if(m_sockets.find(fd) != m_sockets.end()) {
      return true;
    }
    if(m_random_fds.find(fd) != m_random_fds.end()) {
      return true;
    }

    return false;
  }
  /* checks whether the file descriptor is managed by syscall wrapper
     (assumed to first argument)
  */
  bool FdIsEmulatedSocket() {
    int fd;
    read_args(pid, fd);
    return FdIsEmulatedSocket(fd);
  }


  //pid_t getpid(void);
  SyscallHandlerStatusCode HandleGetPid() {
    FAKE(fake_pid);
    return SYSC_SUCCESS;
  }

  //int pipe2(int pipefd[2], int flags);
  SyscallHandlerStatusCode HandlePipe2() {
    int* pipefd;
    //    int flags;
    read_args(pid, pipefd/*, flags, cmd*/);

    int mypipefd[2];
    MemcpyFromTracee(pid, mypipefd, pipefd, 2*sizeof(int));

    if(FdIsEmulatedSocket(mypipefd[0]) || FdIsEmulatedSocket(mypipefd[1])) {
      UNSUPPORTED("pipes on emulated sockets");
      return SYSC_ERROR;
    }

    return HandleSyscallAfter();
  }

  // int getrusage(int who, struct rusage *r_usage);
  SyscallHandlerStatusCode HandleGetRUsage() {
    int who;
    struct rusage *r_usage;
    read_args(pid, who, r_usage);

    // For now, just return the empty struct as statistics they are often just printed by the program.
    // Idea for improvement: use a heuristic here that serves the purpose of causing as little confusion as possible to processes that depend on the provided information (in case the process uses it).
    struct rusage result;
    memset(&result,0,sizeof(result));

    MemcpyToTracee(pid, r_usage, &result, sizeof(result));
    FAKE(0);
    return SYSC_SUCCESS;
  }

  // ssize_t read(int fd, void *buf, size_t count);
  SyscallHandlerStatusCode HandleRead() {
    int fd;
    void *buf;
    size_t count;
    read_args(pid, fd, buf, count);

    if(!FdIsEmulatedSocket(fd)) {
      return HandleSyscallAfter();
    }
    else if (m_random_fds.find(fd) != m_random_fds.end()) {
      uint8_t _buf[count];
      for(size_t i=0; i<count; i++) {
        // future work: should use every byte of interger instead for efficient use of RNG resources
        _buf[i] = rng->GetInteger();
      }

      MemcpyToTracee(pid, buf,_buf,count);
      FAKE(count);
      return SYSC_SUCCESS;
    }
    else if (m_sockets.find(fd) != m_sockets.end() && m_tcpSockets.count(fd)) {
      Ptr<Socket> ns3socket = m_sockets.at(fd);
      std::function<void(Ptr<Socket>)> g = [=](Ptr<Socket> sock) {
        SyscallHandlerStatusCode res;
        do {
          // read packet and sender address from ns3
          uint8_t _buffer[ALIGN(count)];
          int rlen = sock->Recv(_buffer, count, 0);

          // copy message to tracee
          if(rlen > 0) {
            MemcpyToTracee(pid, buf, _buffer, std::min(count,(size_t)rlen));
          }

          FAKE2(rlen);
          res = SYSC_SUCCESS;
        
        } while(false);
      
        ProcessStatusCode(res, SYS_read);

        // reset ns3 callback (recvfrom is blocking, thus a one-shot callback)
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // !!! CAREFUL: do NOT call this earlier in the lambda expression,                            !!!
        // !!! as it causes the closure's stack to be destroyed by the C++ runtime.                   !!!
        // !!! If you call this line earlier than here, it will cause undefined behavior.             !!!
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        sock->SetRecvCallback(MakeNullCallback<void,Ptr<Socket>>());
      };

      if(ns3socket->GetRxAvailable()) {
        // return immediately
        g(ns3socket);
        return SYSC_MANUAL;
      } else if(m_nonblocking_sockets.count(fd)) {
        FAKE(-EWOULDBLOCK);
        return SYSC_FAILURE;
      } else {
        // block until data arrives
        ns3socket->SetRecvCallback(MakeFunctionCallback(g));
        return SYSC_DELAYED;
      }
    }
    else {
      NS_LOG_ERROR(pid << "[EE] system call is not implemented to work on emulated file descriptors");
      exit(1);
    }
  }

  // int close(int fd);
  SyscallHandlerStatusCode HandleClose() {
    int fd;
    read_args(pid, fd);
    if(!FdIsEmulatedSocket(fd)) {
      // pass through
      return HandleSyscallAfter();
    } else if(m_sockets.find(fd) != m_sockets.end()) {
      Ptr<Socket> sock = m_sockets.at(fd);
      sock->Close();

      // remove from all socket state sets
      m_sockets.erase(fd);
      m_tcpSockets.erase(fd);
      m_connectedSockets.erase(fd);
      m_isListenTcpSocket.erase(fd);
      m_nonblocking_sockets.erase(fd);
      
      availableFDs.insert(fd);
      
      // we must delay the deletion of the socket, since the DataSent callback may fail otherwise
      // the constant delay of one second likely includes a large safety margin
      std::function<void()> removeClosedSocket = [sock]()
                                                 {
                                                   sock->Close(); // close again to avoid compiler optimizations
                                                   return;
                                                 };
      Simulator::Schedule(Seconds(1.0), MakeFunctionalEvent(removeClosedSocket));
      FAKE(0);
      return SYSC_SUCCESS;
    } else if(m_netlinks.find(fd) != m_netlinks.end()) {
      m_netlinks.erase(fd);
      availableFDs.insert(fd);
      FAKE(0);
      return SYSC_SUCCESS;
    } else if(m_random_fds.find(fd) != m_random_fds.end()) {
      m_random_fds.erase(fd);
      availableFDs.insert(fd);
      FAKE(0);
      return SYSC_SUCCESS;
    } else {
      NS_ASSERT(false && "not implemented");
      return SYSC_ERROR;
    }
  }

  
  // int open(const char *pathname, int flags);
  // int open(const char *pathname, int flags, mode_t mode);
  SyscallHandlerStatusCode HandleOpen() {
    char *pathname;
    int flags;
    read_args(pid, pathname, flags);
    char mypathname[256];
    MemcpyFromTracee(pid, mypathname, pathname, sizeof(mypathname));

    std::regex random_regex("dev/random");
    std::regex urandom_regex("dev/urandom");
    NS_LOG_LOGIC(pid << ": (" << Simulator::Now().GetSeconds() << "s) [open] path: " << mypathname);
    if(std::regex_search(mypathname, random_regex)
       || std::regex_search(mypathname, urandom_regex)) {
      int new_socket_fd = GetNextFD();
      m_random_fds.insert(new_socket_fd);
      FAKE(new_socket_fd);
      return SYSC_SUCCESS;
    } else {
      return HandleSyscallAfter();
    }
  }


  // int openat(int dirfd, const char *pathname, int flags);
  // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
  SyscallHandlerStatusCode HandleOpenAt() {
    char *dirfd;
    char *pathname;
    int flags;
    read_args(pid, dirfd, pathname, flags);
    char mypathname[256];
    MemcpyFromTracee(pid, mypathname, pathname, sizeof(mypathname));

    std::regex random_regex("dev/random");
    std::regex urandom_regex("dev/urandom");
    NS_LOG_LOGIC(pid << ": (" << Simulator::Now().GetSeconds() << "s) [openat] path: " << mypathname);
    if(std::regex_search(mypathname, random_regex)
       || std::regex_search(mypathname, urandom_regex)) {
      int new_socket_fd = GetNextFD();
      m_random_fds.insert(new_socket_fd);
      FAKE(new_socket_fd);
      return SYSC_SUCCESS;
    } else {
      return HandleSyscallAfter();
    }
  }
  
  // int fcntl(int fd, int cmd, ... /* arg */ );
  SyscallHandlerStatusCode HandleFcntl() {
    int fd;
    int cmd;
    // ???va_arg???;
    read_args(pid, fd, cmd);

    if(!FdIsEmulatedSocket(fd)) {
      return HandleSyscallAfter();
    }
    
    NS_LOG_LOGIC(pid << ": (" << Simulator::Now().GetSeconds() << "s) [fcntl cmd]: "
                 << fcntlname(cmd) << " on fd: " << fd);
    if(cmd == F_SETFL && m_netlinks.find(fd) != m_netlinks.end()) {
      // todo: ignore for now (hoping that it works)
      FAKE(0);
      return SYSC_SUCCESS;
    }
    if(cmd == F_GETFL && m_sockets.find(fd) != m_sockets.end()) {
      FAKE(0);
      return SYSC_SUCCESS;
    }
    if(cmd == F_SETFL && m_sockets.find(fd) != m_sockets.end()) {
      int flags;
      read_args3(pid, flags);
      NS_LOG_LOGIC("fcntl/" << fcntlname(cmd) << ": " << " flags: " << flags);
      if(flags == O_NONBLOCK) {
        if(!m_nonblocking_sockets.count(fd)) m_nonblocking_sockets.insert(fd);
        FAKE(0);
        return SYSC_SUCCESS;
      }
      if(flags != O_NONBLOCK) {
        NS_LOG_LOGIC("...unsupported flags");
        FAKE(-1);
        return SYSC_FAILURE;
      }
      UNSUPPORTED("unknown fctl flag: " << flags);
    }
    return SYSC_ERROR;
  }

  // int ioctl(int fd, unsigned long request, ...);
  SyscallHandlerStatusCode HandleIoctl() {
    int fd;
    unsigned long request;
    // ???va_arg???;
    read_args(pid, fd, request);
    
    if(fd == 1 && request == TCGETS) {
      FAKE(-1);
      return SYSC_FAILURE;
    }
    
    if(!FdIsEmulatedSocket(fd)) {
      return HandleSyscallAfter();
    }
    
    if(request == SIOCGIFFLAGS) {
      struct ifreq* ifreq;
      struct ifreq myifreq;
      read_args3(pid, ifreq);
      if(!ifreq) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds() << "s) [ioctl " << ioctlname(request) << ": null ptr in arg -> failing");
        FAKE(-1);
        return SYSC_FAILURE;
      }
      MemcpyFromTracee(pid, &myifreq, ifreq, sizeof(myifreq));
      NS_LOG_LOGIC(pid << ": (" << Simulator::Now().GetSeconds() << "s) [ioctl " << ioctlname(request) << ": name]: " << 
                   myifreq.ifr_name);
      auto wifi = GetNetDeviceByName(myifreq.ifr_name)->GetObject<WifiNetDevice>();
      if(!wifi) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds() << "s) [ioctl " << ioctlname(request) << ": device not found]: " << myifreq.ifr_name);
        FAKE(-1);
        return SYSC_FAILURE;
      }
      myifreq.ifr_flags = 0;
      if(wifi->IsLinkUp()) myifreq.ifr_flags        |= IFF_UP | IFF_RUNNING;
      if(wifi->IsBroadcast()) myifreq.ifr_flags     |= IFF_BROADCAST;
      if(wifi->IsMulticast()) myifreq.ifr_flags     |= IFF_MULTICAST;
      if(wifi->IsPointToPoint()) myifreq.ifr_flags  |= IFF_POINTOPOINT;
      MemcpyToTracee(pid, ifreq, &myifreq, sizeof(myifreq));
      FAKE(0);
      return SYSC_SUCCESS;
    }
    else if(request == SIOCGIWNAME) {
      struct iwreq* iwreq;
      struct iwreq myiwreq;
      read_args3(pid, iwreq);
      if(!iwreq) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds()
                     << "s) [ioctl " << ioctlname(request) << ": null ptr in arg -> succeeding");
        FAKE(-1);
        return SYSC_FAILURE;
      }
      MemcpyFromTracee(pid, &myiwreq, iwreq, sizeof(myiwreq));
      auto wifi = GetNetDeviceByName(myiwreq.ifr_ifrn.ifrn_name)->GetObject<WifiNetDevice>();
      if(!wifi) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds() << "s) [device not found]: "
                     << myiwreq.ifr_ifrn.ifrn_name);
        return SYSC_FAILURE;
      }
      strcpy(myiwreq.u.name, "NS3-WL-Stack");
      MemcpyToTracee(pid, iwreq, &myiwreq, sizeof(myiwreq));
      FAKE(0);
      return SYSC_SUCCESS;
    }
    else if(request == SIOCGIFADDR || request == SIOCGIFBRDADDR) {
      struct ifreq* ifreq;
      struct ifreq myifreq;
      read_args3(pid, ifreq);
      if(!ifreq) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds()
                     << "s) [ioctl " << ioctlname(request) << ": null ptr in arg -> failing");
        FAKE(-1);
        return SYSC_FAILURE;
      }
      MemcpyFromTracee(pid, &myifreq, ifreq, sizeof(myifreq));
      NS_LOG_LOGIC(pid << ": (" << Simulator::Now().GetSeconds()
                   << "s) [ioctl " << ioctlname(request) << ": name]: " << 
                   myifreq.ifr_name);
      auto wifi = GetNetDeviceByName(myifreq.ifr_name)->GetObject<WifiNetDevice>();
      if(!wifi) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds()
                     << "s) [ioctl " << ioctlname(request) << ": device not found]: " << myifreq.ifr_name);
        FAKE(-1);
        return SYSC_FAILURE;
      }

      auto ipv4 = app->GetNode()->GetObject<ns3::Ipv4>();
      uint32_t if_idx = ipv4->GetInterfaceForDevice(wifi);;
      ns3::Ipv4InterfaceAddress iaddr = ipv4->GetAddress (if_idx,0);
      ns3::Ipv4Address ipAddr;
      if (request == SIOCGIFADDR) {
        ipAddr = iaddr.GetLocal ();
      } else if (request == SIOCGIFBRDADDR) {
        ipAddr = iaddr.GetBroadcast ();
      }
      
      MakeBsdAddress(ipAddr, (sockaddr_in*)&myifreq.ifr_addr);

      MemcpyToTracee(pid, ifreq, &myifreq, sizeof(myifreq));
      FAKE(0);
      return SYSC_SUCCESS;
    }
    else if(request == SIOCGIFNETMASK) {
      struct ifreq* ifreq;
      struct ifreq myifreq;
      read_args3(pid, ifreq);
      if(!ifreq) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds()
                     << "s) [ioctl " << ioctlname(request) << ": null ptr in arg -> failing");
        FAKE(-1);
        return SYSC_FAILURE;
      }
      MemcpyFromTracee(pid, &myifreq, ifreq, sizeof(myifreq));
      NS_LOG_LOGIC(pid << ": (" << Simulator::Now().GetSeconds()
                   << "s) [ioctl " << ioctlname(request) << ": name]: " << 
                   myifreq.ifr_name);
      auto wifi = GetNetDeviceByName(myifreq.ifr_name)->GetObject<WifiNetDevice>();
      if(!wifi) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds()
                     << "s) [ioctl " << ioctlname(request) << ": device not found]: " << myifreq.ifr_name);
        FAKE(-1);
        return SYSC_FAILURE;
      }

      auto ipv4 = app->GetNode()->GetObject<ns3::Ipv4>();
      uint32_t if_idx = ipv4->GetInterfaceForDevice(wifi);;
      ns3::Ipv4InterfaceAddress iaddr = ipv4->GetAddress (if_idx,0);
      ns3::Ipv4Mask ipMask = iaddr.GetMask (); 
      
      MakeBsdAddress(ipMask, (sockaddr_in*)&myifreq.ifr_addr);

      MemcpyToTracee(pid, ifreq, &myifreq, sizeof(myifreq));
      FAKE(0);
      return SYSC_SUCCESS;
    }
    else if(request == SIOCGIFMTU) {
      struct ifreq* ifreq;
      struct ifreq myifreq;
      read_args3(pid, ifreq);
      if(!ifreq) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds()
                     << "s) [ioctl " << ioctlname(request) << ": null ptr in arg -> failing");
        FAKE(-1);
        return SYSC_FAILURE;
      }
      MemcpyFromTracee(pid, &myifreq, ifreq, sizeof(myifreq));
      NS_LOG_LOGIC(pid << ": (" << Simulator::Now().GetSeconds()
                   << "s) [ioctl " << ioctlname(request) << ": name]: " << 
                   myifreq.ifr_name);
      auto wifi = GetNetDeviceByName(myifreq.ifr_name)->GetObject<WifiNetDevice>();
      if(!wifi) {
        NS_LOG_ERROR(pid << ": (" << Simulator::Now().GetSeconds()
                     << "s) [ioctl " << ioctlname(request) << ": device not found]: " << myifreq.ifr_name);
        FAKE(-1);
        return SYSC_FAILURE;
      }

      myifreq.ifr_mtu = wifi->GetMtu ();

      MemcpyToTracee(pid, ifreq, &myifreq, sizeof(myifreq));
      FAKE(0);
      return SYSC_SUCCESS;
    }
    UNSUPPORTED("unknown REQUEST: " << ioctlname(request));
  }

  // ssize_t write(int fd, const void *buf, size_t count);
  SyscallHandlerStatusCode HandleWrite() {
    int fd;
    char* str;
    size_t count;
    read_args(pid, fd, str, count);

    if(fd != 1 && fd != 2 && !FdIsEmulatedSocket(fd)) {
      return HandleSyscallAfter();
    }

    if(!FdIsEmulatedSocket(fd)) {
      NS_ASSERT(str);
      NS_ASSERT(count);
      char mystr[count+1];
      MemcpyFromTracee(pid, mystr,str,count);
      mystr[count]='\0';
      NS_LOG_INFO(pid << ": (" << Simulator::Now().GetSeconds() << "s) [stderr]: " << mystr);
      if((fd == 1 || fd == 2) && app->m_printStdout) {
        printf("%2.2f/%d: %s", Simulator::Now().GetSeconds(), pid, mystr);
      }
    
      FAKE(count);
      return SYSC_SUCCESS;
    } else {
      if(!m_connectedSockets.count(fd)) {
        UNSUPPORTED("write on emulated socket, but it is not a connected TCP socket");
      }

      uint32_t txAvailable = m_sockets.at(fd)->GetTxAvailable();
      if(txAvailable == 0) {
        // buffer space limited, block or return if no blocking is set
        if(m_nonblocking_sockets.count(fd)) {
          FAKE(-EWOULDBLOCK);
          return SYSC_FAILURE;
        }

        std::function<void(Ptr<Socket>, uint32_t)> sendCallback = [this](Ptr<Socket> sock, uint32_t n)
          {
            UNSUPPORTED("blocking wait");
          };
        
        m_sockets.at(fd)->SetSendCallback(MakeFunctionCallback(sendCallback));
        return SYSC_DELAYED; 
      }
      size_t towrite = (count < txAvailable ? count : txAvailable);
      uint8_t mystr[towrite];
      MemcpyFromTracee(pid,mystr,str,towrite);
      int ret = m_sockets.at(fd)->Send(mystr,towrite,0);
      FAKE(ret);
      if(ret > 0) {
        return SYSC_SUCCESS;
      } else {
        return SYSC_ERROR;
      }
    }
  }
  // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  SyscallHandlerStatusCode HandleGetSockName() {
    int sockfd;
    struct sockaddr *addr;
    socklen_t *addrlen;

    read_args(pid, sockfd, addr, addrlen);

    if(m_netlinks.find(sockfd) != m_netlinks.end()) {
      return m_netlinks.at(sockfd)->HandleGetSockName(sockfd, addr, addrlen);
    } else if (m_sockets.find(sockfd) != m_sockets.end()) {
      Address ns3addr;
      int ret = m_sockets.at(sockfd)->GetSockName(ns3addr);
      SetBsdAddress(ns3addr, addr, addrlen);
      FAKE(ret);
      if(ret >= 0) {
        return SYSC_SUCCESS;
      } else {
        return SYSC_FAILURE; 
      }
    }
    
    UNSUPPORTED("getsockname != netlink");
  }

  // int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  SyscallHandlerStatusCode HandleGetPeerName() {
    int sockfd;
    struct sockaddr *addr;
    socklen_t *addrlen;

    read_args(pid, sockfd, addr, addrlen);

    NS_ASSERT(m_tcpSockets.find(sockfd) != m_tcpSockets.end());

    Address ns3addr;
    int ret = m_sockets.at(sockfd)->GetPeerName(ns3addr);
    SetBsdAddress(ns3addr, addr, addrlen);
    FAKE(ret);
    if(ret >= 0) {
      return SYSC_SUCCESS;
    } else {
      return SYSC_FAILURE; 
    }
  }
  
  // int socket(int domain, int type, int protocol);
   SyscallHandlerStatusCode HandleSocket() {
    int domain;
    int type;
    int protocol;
    read_args(pid, domain, type, protocol);

    NS_LOG_LOGIC(pid << ": [EE] socket with domain: " << domain
                 << (domain==AF_NETLINK ? " [NETLINK]" : (domain==AF_INET?" [AF_INET]":"")));
    NS_LOG_LOGIC(pid << ": [EE] socket with type: " << type
                 << (type==SOCK_DGRAM ? " [DGRAM]" : (type==SOCK_RAW?" [RAW]":"")));
    NS_LOG_LOGIC(pid << ": [EE] socket with protocol: " << protocol);

    if(domain == AF_INET) {
      if(! (type == SOCK_DGRAM || type == SOCK_STREAM) ) {
        NS_LOG_WARN(pid << ": [EE] socket(2): type " << type << " not supported.");
        FAKE(-EPROTONOSUPPORT);
        return SYSC_FAILURE;
      }
      
      // Note: ignores protocol flag for now
      
      int new_socket_fd;
      if(type == SOCK_DGRAM) {
        TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
        Ptr<Socket> socket = Socket::CreateSocket (app->GetNode (), tid);
        new_socket_fd = GetNextFD();
        m_sockets[new_socket_fd] = socket;
        FAKE(new_socket_fd);
        return SYSC_SUCCESS;
      }
      if(type == SOCK_STREAM) {
        TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
        Ptr<Socket> socket = Socket::CreateSocket (app->GetNode (), tid);
        new_socket_fd = GetNextFD();
        m_sockets[new_socket_fd] = socket;
        m_tcpSockets.insert(new_socket_fd);
        FAKE(new_socket_fd);
        return SYSC_SUCCESS;
      }
      else {
        return SYSC_ERROR;
      }
    }
    else if (domain == AF_NETLINK) {
      if(type != SOCK_RAW && type != SOCK_DGRAM) {
        NS_LOG_ERROR(pid << ": [EE] unimplemented netlink protocol type: " << type);
        FAKE(-EPROTOTYPE);
        return SYSC_FAILURE;
      }
      
      if(protocol == NETLINK_ROUTE) {
        int new_socket_fd = GetNextFD();
        m_netlinks[new_socket_fd] = std::make_shared<NetlinkSocket>(pid,NETLINK_ROUTE,app,rt);
        FAKE(new_socket_fd);
        return SYSC_SUCCESS;
      }
      else {
        // TODO failure condition
        NS_LOG_ERROR("UNIMPLEMENTED NETLINK PROTOCOL");
        FAKE(-EPROTONOSUPPORT);
        return SYSC_ERROR;
      }
    }
    else {
      if(domain == AF_UNIX) 
        NS_LOG_WARN(pid << ": [EE] socket(2): domain AF_UNIX not supported.");
      else if(domain == AF_LOCAL) 
        NS_LOG_WARN(pid << ": [EE] socket(2): domain AF_LOCAL not supported.");
      else if(domain == AF_INET6) 
        NS_LOG_WARN(pid << ": [EE] socket(2): domain AF_INET6 not supported.");
      else if(domain == AF_IPX) 
        NS_LOG_WARN(pid << ": [EE] socket(2): domain AF_IPX not supported.");
      else if(domain == AF_X25) 
        NS_LOG_WARN(pid << ": [EE] socket(2): domain AF_25 not supported.");
      else if(domain == AF_PACKET) 
        NS_LOG_WARN(pid << ": [EE] socket(2): domain AF_25 not supported.");
      else
        NS_LOG_WARN(pid << ": [EE] socket(2): domain " << domain << " not supported.");
      
      FAKE(-EAFNOSUPPORT);
      return SYSC_FAILURE;
    }
    return SYSC_SUCCESS;
  }

  //int listen(int sockfd, int backlog);
  SyscallHandlerStatusCode HandleListen() {
    int sockfd;
    int backlog;
    read_args(pid, sockfd, backlog);

    if(!m_tcpSockets.count(sockfd)) {
      FAKE(-EOPNOTSUPP);
      return SYSC_FAILURE;
    }
    if(m_isListenTcpSocket.count(sockfd)) {
      FAKE(-EOPNOTSUPP);
      return SYSC_FAILURE;
    }

    int ret = m_sockets.at(sockfd)->Listen();
    m_isListenTcpSocket.insert(sockfd);
    FAKE(ret);
    if(ret != 0) {
      return SYSC_FAILURE;
    }


    NS_LOG_WARN(pid << ": [EE] listen(2): socket: " << sockfd << "");

    // register default fake accept handler
    std::function<void(Ptr<Socket>, const Address&)> fakeAccept
      = [this,sockfd](Ptr<Socket> newSock, const  Address& newAddr) {
          m_fakeAcceptedSockets[sockfd] = std::make_tuple(newSock, newAddr);
        };
    
    m_sockets.at(sockfd)->SetAcceptCallback(MakeNullCallback<bool,Ptr<Socket>,const Address&>(),
                                            MakeFunctionCallback(fakeAccept));
    
    return SYSC_SUCCESS;
  }

  //int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  SyscallHandlerStatusCode HandleConnect() {
    int sockfd;
    struct sockaddr *addr;
    socklen_t addrlen;
    read_args(pid, sockfd, addr, addrlen);
    
    if(!m_sockets.count(sockfd)) {
      FAKE(-1);
      return SYSC_FAILURE;
    }
    
    std::shared_ptr<Address> ns3addr = GetNs3Address(addr,addrlen);
    if(!ns3addr) {
      return SYSC_ERROR;
    }

    std::function<void(Ptr<Socket>)> success = [sockfd,this](Ptr<Socket> sock) {
      m_connectedSockets.insert(sockfd);
      
      SyscallHandlerStatusCode res = SYSC_SUCCESS;
      FAKE2(0);
      ProcessStatusCode(res, SYS_connect);
    };
    std::function<void(Ptr<Socket>)> failure = [this](Ptr<Socket> sock) {
      SyscallHandlerStatusCode res = SYSC_FAILURE;
      FAKE2(-1);
      ProcessStatusCode(res, SYS_connect);
    };
    
    m_sockets.at(sockfd)->SetConnectCallback(MakeFunctionCallback(success),
                                            MakeFunctionCallback(failure));
    m_sockets.at(sockfd)->Connect(*ns3addr);

    return SYSC_DELAYED;
  }

  // int getsockopt(int sockfd, int level, int optname,
  //              void *optval, socklen_t *optlen);
  SyscallHandlerStatusCode HandleGetSockOpt() {
    int sockfd;
    int level;
    int optname;
    void *optval;
    socklen_t *optlen;
    read_args(pid, sockfd, level, optname, optval, optlen);

    if(!FdIsEmulatedSocket(sockfd)) {
      return HandleSyscallAfter();
    }
    NS_ASSERT(optval);

    if(level == SOL_SOCKET) {

      NS_LOG_LOGIC(pid << ": [EE] getsockopt(2)/SOL_SOCKET: option " << sockoptname(optname));

      if (optname == SO_SNDBUF) {
        UintegerValue bufSizeValue;
        m_sockets.at(sockfd)->GetAttribute("SndBufSize", bufSizeValue);
        
        int myoptval       = bufSizeValue.Get();
        socklen_t myoptlen = sizeof(myoptlen);
        MemcpyToTracee(pid, optval, &myoptval, myoptlen);
        MemcpyToTracee(pid, optlen, &myoptlen, sizeof(myoptlen));
        NS_LOG_LOGIC(pid << ": [EE] getsockopt(2)/" << sockoptname(optname) << " -> " << myoptval);
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == SO_RCVBUF) {
        Ptr<TcpSocket> tcpSock = DynamicCast<TcpSocket>(m_sockets.at(sockfd));
        UintegerValue bufSizeValue;
        tcpSock->GetAttribute("RcvBufSize", bufSizeValue);
        
        int myoptval       = bufSizeValue.Get(); // Linux/amd64 returns 2x the user size
        socklen_t myoptlen = sizeof(myoptlen);
        MemcpyToTracee(pid, optval, &myoptval, myoptlen);
        MemcpyToTracee(pid, optlen, &myoptlen, sizeof(myoptlen));
        NS_LOG_LOGIC(pid << ": [EE] getsockopt(2)/" << sockoptname(optname) << " -> " << myoptval);
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == SO_BROADCAST) {
        int myoptval       = m_sockets.at(sockfd)->GetAllowBroadcast();
        socklen_t myoptlen = sizeof(myoptlen);
        MemcpyToTracee(pid, optval, &myoptval, myoptlen);
        MemcpyToTracee(pid, optlen, &myoptlen, sizeof(myoptlen));
        NS_LOG_LOGIC(pid << ": [EE] getsockopt(2)/" << sockoptname(optname) << " -> " << myoptval);
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == SO_REUSEADDR) {
        // no equivalent in ns-3, but there are no lingering sockets in ns-3 either
        UNSUPPORTED("not implemented");
        // FAKE(0);
        // return SYSC_SUCCESS;
      } else if (optname == SO_RCVBUF) {
        // // no equivalent in ns-3, since callbacks that process packets run immediately
        UNSUPPORTED("not implemented");
        // int myoptval = 0;
        // NS_ASSERT(sizeof(myoptval) >= optlen);
        // MemcpyFromTracee(pid, &myoptval, optval, optlen);
        // NS_LOG_LOGIC(pid << ": [EE] setsockopt(2)/" << sockoptname(optname) << " -> " << myoptval);
        // FAKE(0);
        // return SYSC_SUCCESS;
      } else if (optname == SO_BINDTODEVICE) {
        UNSUPPORTED("not implemented");
        // std::string ifname(optlen,' ');
        // MemcpyFromTracee(pid, (void*)ifname.data(), optval, optlen);
        // NS_LOG_LOGIC(pid << ": [EE] setsockopt(2)/" << sockoptname(optname) << " -> " << ifname);

        // // note: causes problems with later calls to bind, find way to handle it
        // //   -> resources https://www.nsnam.org/bugzilla/show_bug.cgi?id=51
        // // auto netDevice = GetNetDeviceByName(ifname);
        // // if(!netDevice) {
        // //   FAKE(-1);
        // //   return SYSC_FAILURE;
        // // }
        // // m_sockets.at(sockfd)->BindToNetDevice(netDevice);
        // FAKE(0);
        // return SYSC_SUCCESS;
      } else if (optname == SO_PRIORITY) {
        UNSUPPORTED("not implemented");
        // note: only sets queing priority and may be ignored on linux anyways, so possible to just ignore it
        // int priority;
        // MemcpyFromTracee(pid, &priority, optval, optlen);
        // NS_LOG_LOGIC(pid << ": [EE] setsockopt(2)/" << sockoptname(optname) << " -> " << priority);
        // FAKE(0);
        // return SYSC_SUCCESS;
      } else {
        UNSUPPORTED("socket getsockopt(2)/" << sockfd  << " option: " << sockoptname(optname));
      }
    } else if (level == IPPROTO_IP) {
      UNSUPPORTED("ip getsockopt(2)/" << sockfd  << " option: " << sockoptname(optname));
    } else if (level == IPPROTO_TCP) {
      if (optname == TCP_MAXSEG) {
        Ptr<TcpSocket> tcpSock = DynamicCast<TcpSocket>(m_sockets.at(sockfd));
        UintegerValue value;
        tcpSock->GetAttribute("SegmentSize", value);
        
        int myoptval       = value.Get();
        socklen_t myoptlen = sizeof(myoptlen);
        MemcpyToTracee(pid, optval, &myoptval, myoptlen);
        MemcpyToTracee(pid, optlen, &myoptlen, sizeof(myoptlen));
        NS_LOG_LOGIC(pid << ": [EE] tcp getsockopt(2)/" << tcpsockoptname(optname) << " -> " << myoptval);
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == TCP_CONGESTION) {
        const char* myoptval = "reno";
        socklen_t myoptlen = strlen(myoptval)+1;
        MemcpyToTracee(pid, optval, &myoptval, myoptlen);
        MemcpyToTracee(pid, optlen, &myoptlen, sizeof(myoptlen));
        NS_LOG_LOGIC(pid << ": [EE] tcp getsockopt(2)/" << tcpsockoptname(optname) << " -> " << myoptval);
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == TCP_INFO) {
        FAKE(-ENOPROTOOPT);
        return SYSC_FAILURE;
      } else {
        UNSUPPORTED("tcp getsockopt(2)/" << sockfd  << " option: " << tcpsockoptname(optname));
      }
    } else {
      FAKE(-ENOPROTOOPT);
      return SYSC_FAILURE;
    }
    
    UNSUPPORTED("not implemented");
  }

  //int setsockopt(int sockfd, int level, int optname,
  //               const void *optval, socklen_t optlen);
  SyscallHandlerStatusCode HandleSetSockOpt() {
    int sockfd;
    int level;
    int optname;
    void* optval;
    socklen_t optlen;

    read_args(pid, sockfd, level, optname, optval, optlen);

    if(!FdIsEmulatedSocket(sockfd)) {
      return HandleSyscallAfter();
    }

    if(level == SOL_SOCKET) {

      NS_LOG_LOGIC(pid << ": [EE] setsockopt(2)/SOL_SOCKET: option " << sockoptname(optname));

      if (optname == SO_BROADCAST) {
        int myoptval = 0;
        NS_ASSERT(sizeof(myoptval) >= optlen);
        MemcpyFromTracee(pid, &myoptval, optval, optlen);
        NS_LOG_LOGIC(pid << ": [EE] setsockopt(2)/" << sockoptname(optname) << " -> " << myoptval);
        m_sockets.at(sockfd)->SetAllowBroadcast(myoptval);
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == SO_REUSEADDR) {
        // no equivalent in ns-3, but there are no lingering sockets in ns-3 either
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == SO_RCVBUF) {
        int myoptval = 0;
        NS_ASSERT(sizeof(myoptval) >= optlen);
        MemcpyFromTracee(pid, &myoptval, optval, optlen);
        NS_LOG_LOGIC(pid << ": [EE] setsockopt(2)/" << sockoptname(optname) << " -> " << myoptval);
        // no equivalent in ns-3, since callbacks that process packets are run immediately
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == SO_BINDTODEVICE) {
        std::string ifname(optlen,' ');
        MemcpyFromTracee(pid, (void*)ifname.data(), optval, optlen);
        NS_LOG_LOGIC(pid << ": [EE] setsockopt(2)/" << sockoptname(optname) << " -> " << ifname);

        // todo: causes problems with later calls to bind, find way to handle it
        //   -> resources https://www.nsnam.org/bugzilla/show_bug.cgi?id=51
        // auto netDevice = GetNetDeviceByName(ifname);
        // if(!netDevice) {
        //   FAKE(-1);
        //   return SYSC_FAILURE;
        // }
        // m_sockets.at(sockfd)->BindToNetDevice(netDevice);
        FAKE(0);
        return SYSC_SUCCESS;
      } else if (optname == SO_PRIORITY) {
        int priority;
        MemcpyFromTracee(pid, &priority, optval, optlen);
        NS_LOG_LOGIC(pid << ": [EE] setsockopt(2)/" << sockoptname(optname) << " -> " << priority);

        // ignore, only sets queing priority and may be ignored on linux anyways
        FAKE(0);
        return SYSC_SUCCESS;
      } else {
        UNSUPPORTED("setsockopt(2)/" << sockfd  << " option: " << sockoptname(optname));
      }
    } else if (level == IPPROTO_IP) {
      if (optname == IP_TOS) {
        // ignore
        FAKE(0);
        return SYSC_SUCCESS;
      } else {
        UNSUPPORTED("setsockopt(2)/" << sockfd  << " option: " << sockoptname(optname));
      }
    } else if (level == IPPROTO_TCP) {
      if (optname == TCP_CONGESTION) {
        int myoptval = 0;
        NS_ASSERT(sizeof(myoptval) >= optlen);
        MemcpyFromTracee(pid, &myoptval, optval, optlen);
        UNSUPPORTED("cc algo optavl" << optval);
      } else {
        UNSUPPORTED("setsockopt(2)/" << sockfd  << " option: " << tcpsockoptname(optname));
      }
    } else {
      FAKE(-ENOPROTOOPT);
      return SYSC_FAILURE;
    }
  }
  
  //ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
  //               const struct sockaddr *dest_addr, socklen_t addrlen);
  SyscallHandlerStatusCode HandleSendTo() {
    int sockfd;
    void* buf;
    size_t len;
    int flags;
    struct sockaddr* dest_addr;
    socklen_t addrlen;

    read_args(pid,sockfd,buf,len,flags,dest_addr,addrlen);

    NS_LOG_LOGIC(pid << ": [EE] socket with sockfd: " << sockfd);
    NS_LOG_LOGIC(pid << ": [EE] socket with buf: " << buf);
    NS_LOG_LOGIC(pid << ": [EE] socket with len: " << len);
    NS_LOG_LOGIC(pid << ": [EE] socket with flags: " << flags);
    NS_LOG_LOGIC(pid << ": [EE] socket with dest_addr: " << dest_addr);
    NS_LOG_LOGIC(pid << ": [EE] socket with addrlen: " << addrlen);
    
    if(m_sockets.find(sockfd) != m_sockets.end()) {
      int flags_left = flags;
      int ns3flags = 0;

      if(flags & MSG_DONTROUTE) {
        ns3flags |= MSG_DONTROUTE;
        flags_left -= MSG_DONTROUTE;
      }
      
      if(flags_left) {
        NS_LOG_ERROR("unknown socket flags: " << flags);
        return SYSC_ERROR;
      }

      void* _buf = malloc(ALIGN(len));
      MemcpyFromTracee(pid, _buf,buf,len);

      std::shared_ptr<Address> ns3addr;
      if(dest_addr) {
        ns3addr = GetNs3Address(dest_addr,addrlen);
      } else {
        ns3addr = std::make_shared<Address>();
      }
    
      Ptr<Socket> socket = m_sockets.at(sockfd);
      int ret = socket->SendTo((uint8_t*)_buf, len, ns3flags, *ns3addr);
      free(_buf);
      
      FAKE(ret);
      return SYSC_SUCCESS;
    }
    else if(m_netlinks.find(sockfd) != m_netlinks.end()) {
      return m_netlinks.at(sockfd)->HandleSendTo(sockfd,buf,len,flags,dest_addr,addrlen);
    }
    else {
      // Note, SYSC_FAILURE may be 
      NS_LOG_ERROR("could not find ns-3 socket or NETLINK socket for file descriptor " << sockfd);
      return SYSC_ERROR;
    }
  }

  // int select(int nfds, fd_set *readfds, fd_set *writefds,
  //            fd_set *exceptfds, struct timeval *timeout);
  SyscallHandlerStatusCode HandleSelect()
  {
    // Select is one of the most complex calls to implement, as it has
    // several different outcomes depending on the polled sockets'
    // state, the sockets' options, and and the select options
    // supplied. The complexity of this implementation is quite high
    // and it is thus desireable to refactor/split the different
    // outcomes into separate functions at some point.
    //
    // The most important distinction in the current implementation is
    // whether the call *may* block (eg., due to select options) and
    // whether it *does* block. We do a preliminary run over all
    // sockets to determine whether the select call can return
    // immediately, in which case it may not block but shall return
    // the result immediately. A second run registers necessary
    // handlers in case the call may block, or returns a result
    // immediatelly if data is available. Finally, the implementation
    // registers a timeout event if a timeout was supplied and the
    // call does indeed block.
    
    int nfds;
    fd_set *readfds;
    fd_set *writefds;
    fd_set *exceptfds;
    struct timeval *timeout;
    struct timeval mytimeout = {0,0};
    read_args(pid, nfds, readfds, writefds, exceptfds, timeout);
    
    if(timeout) {
      LoadFromTracee(pid, &mytimeout, timeout);
      NS_LOG_LOGIC(pid << ": [EE] select/" << nfds << " timeout: " << mytimeout.tv_sec << "s"
                   << " " << mytimeout.tv_usec << "us");
    } else {
      NS_LOG_LOGIC(pid << ": [EE] select/" << nfds << " timeout: infinite");
    }
    bool may_block = !timeout || (mytimeout.tv_sec || mytimeout.tv_usec);
    bool does_block = false;
    
    fd_set myreadfds;
    fd_set mywritefds;
    fd_set myexceptfds;

    LoadFromTracee(pid, &myreadfds,   readfds);
    LoadFromTracee(pid, &mywritefds,  writefds);
    LoadFromTracee(pid, &myexceptfds, exceptfds);

    fd_set newreadfds;
    fd_set newwritefds;
    fd_set newexceptfds;
    
    FD_ZERO(&newreadfds);
    FD_ZERO(&newwritefds);
    FD_ZERO(&newexceptfds);

    std::shared_ptr<bool> already_handled = std::make_shared<bool>(false);
    std::shared_ptr<EventId> timeout_event = std::make_shared<EventId>();
    size_t ctx = 0;

    if(may_block) {
      bool has_data = false;
      // pass 1, figure out if we are blocking
      for(auto& kv : m_sockets) {
        if(writefds && FD_ISSET(kv.first,&mywritefds) && kv.second->GetTxAvailable()) {
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "pre-analysis found data in: " << kv.first);
          has_data = true;
          goto has_data;
        }
        if(readfds && FD_ISSET(kv.first,&myreadfds) && kv.second->GetRxAvailable()) {
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "pre-analysis found data in: " << kv.first);
          has_data = true;
          goto has_data;
        }
        if(readfds && FD_ISSET(kv.first,&myreadfds) && m_fakeAcceptedSockets.count(kv.first)) {
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "pre-analysis found fake accepted connection in: " << kv.first);
          has_data = true;
          goto has_data;
        }
        if(exceptfds && FD_ISSET(kv.first,&myexceptfds)) {
          UNSUPPORTED("exceptfds");
        }
      }
      for(auto& kv : m_netlinks) {
        if(readfds && FD_ISSET(kv.first,&myreadfds) && kv.second->HasData()) {
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "pre-analysis found data in: " << kv.first);
          has_data = true;
          goto has_data;
        }
        if(exceptfds && FD_ISSET(kv.first,&myexceptfds)) {
          UNSUPPORTED("exceptfds");
        }
      }
    has_data:
      may_block = may_block && !has_data;
      NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "pre-analysis says has-data: " << has_data);
    }
    
    for(auto& kv : m_sockets) {
      NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "processing socket: " << kv.first);
      // WRITE-FDS
      if(writefds && FD_ISSET(kv.first,&mywritefds)) {
        NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "write fds set!");
        if(kv.second->GetTxAvailable()) {
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "...setting!");
          FD_SET(kv.first, &newwritefds);
          may_block = false;
          ++ctx;
        } else if (may_block) {
          int fdnr = kv.first;
          std::function<void(Ptr<Socket>, uint32_t)> g = [this,readfds,writefds,exceptfds,fdnr,already_handled,timeout_event] \
            (Ptr<Socket> sock, uint32_t size) {
            // a needed precaution if multiple sockets receive at same time (possible with ns3)
            if(*already_handled) return;
            *already_handled = true;
            timeout_event->Cancel();
            NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "write fd ready");
            SyscallHandlerStatusCode res = SYSC_SUCCESS;
            do {
              fd_set newreadfds;
              fd_set newwritefds;
              fd_set newexceptfds;
              FD_ZERO(&newreadfds);
              FD_ZERO(&newwritefds);
              FD_ZERO(&newexceptfds);

              FD_SET(fdnr, &newwritefds);

              StoreToTracee(pid, &newreadfds,   readfds);
              StoreToTracee(pid, &newwritefds,  writefds);
              StoreToTracee(pid, &newexceptfds, exceptfds);
              FAKE2(1);
            } while(false);
            ProcessStatusCode(res, SYS_select);
            sock->SetSendCallback(MakeNullCallback<void,Ptr<Socket>,uint32_t>());
          };
            
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "setting new send callback");
          kv.second->SetSendCallback(MakeFunctionCallback(g));
          does_block = true;
        } else {
          // non blocking and no data available: do nothing
        }
      }
      // EXCEPT-FDS
      if(exceptfds && FD_ISSET(kv.first,&myexceptfds)) {
        UNSUPPORTED("exceptfds");
      }
      // READ-FDS
      if(readfds && FD_ISSET(kv.first,&myreadfds)) {
        NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "read fds set!");
        if(kv.second->GetRxAvailable()) {
          // data to read available:
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "...setting!");
          FD_SET(kv.first, &newreadfds);
          may_block = false;
          ++ctx;
        } else if(m_fakeAcceptedSockets.count(kv.first)) {
          // already accepted connection:
            NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "...setting due to fake accept!");
            FD_SET(kv.first, &newreadfds);
            may_block = false;
            ++ctx;
        } else if(may_block && m_isListenTcpSocket.count(kv.first)) {
          // listen state which may receive a connection
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "...setting due to listen state!");
          int fdnr = kv.first;
          // default fake accept handler
          std::function<void(Ptr<Socket>, const Address&)> defaultFakeAccept
            = [this,fdnr](Ptr<Socket> newSock, const  Address& newAddr) {
                m_fakeAcceptedSockets[fdnr] = std::make_tuple(newSock, newAddr);
              };
          
          // select fake accept handler
          std::function<void(Ptr<Socket>, const Address&)> fakeAccept = \
            [this,readfds,writefds,exceptfds,fdnr,already_handled,timeout_event,defaultFakeAccept] \
            (Ptr<Socket> newSock, const  Address& newAddr)
            {
              // needed precaution if multiple sockets receive at same time (possible with ns3)
              if(*already_handled) return;
              *already_handled = true;
              timeout_event->Cancel();
              NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "read(listening) fd ready");
              
              
              
              m_fakeAcceptedSockets[fdnr] = std::make_tuple(newSock,newAddr);
              // restore default callback handling
              m_sockets.at(fdnr)->SetAcceptCallback(
                                                    MakeNullCallback<bool,Ptr<Socket>,const Address&>(),
                                                    MakeFunctionCallback(defaultFakeAccept));
              
              m_sockets.at(fdnr)->SetAcceptCallback(
                                                    MakeNullCallback<bool,Ptr<Socket>,const Address&>(),
                                                    MakeNullCallback<void,Ptr<Socket>,const Address&>());
              
              SyscallHandlerStatusCode res = SYSC_SUCCESS;
              do {
                fd_set newreadfds;
                fd_set newwritefds;
                fd_set newexceptfds;
                FD_ZERO(&newreadfds);
                FD_ZERO(&newwritefds);
                FD_ZERO(&newexceptfds);

                FD_SET(fdnr, &newreadfds);

                StoreToTracee(pid, &newreadfds,   readfds);
                StoreToTracee(pid, &newwritefds,  writefds);
                StoreToTracee(pid, &newexceptfds, exceptfds);
                FAKE2(1);
              } while(false);
              ProcessStatusCode(res, SYS_select);
            };
          
            NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "setting new accept callback");
            kv.second->SetAcceptCallback(MakeNullCallback<bool,Ptr<Socket>,const Address&>(),
                                         MakeFunctionCallback(fakeAccept));
            does_block = true;
        } else if(may_block) {
          int fdnr = kv.first;
          std::function<void(Ptr<Socket>)> g = [this,readfds,writefds,exceptfds,fdnr,already_handled,timeout_event] \
            (Ptr<Socket> sock) {
                                                 // needed precaution if multiple sockets receive at same time (possible with ns3)
                                                 if(*already_handled) return;
                                                 *already_handled = true;
                                                 timeout_event->Cancel();
                                                 NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "read fd ready");

                                                 SyscallHandlerStatusCode res = SYSC_SUCCESS;
                                                 do {
                                                   fd_set newreadfds;
                                                   fd_set newwritefds;
                                                   fd_set newexceptfds;
                                                   FD_ZERO(&newreadfds);
                                                   FD_ZERO(&newwritefds);
                                                   FD_ZERO(&newexceptfds);

                                                   FD_SET(fdnr, &newreadfds);

                                                   StoreToTracee(pid, &newreadfds,   readfds);
                                                   StoreToTracee(pid, &newwritefds,  writefds);
                                                   StoreToTracee(pid, &newexceptfds, exceptfds);
                                                   FAKE2(1);
                                                 } while(false);
                                                 ProcessStatusCode(res, SYS_select);
                                                 sock->SetRecvCallback(MakeNullCallback<void,Ptr<Socket>>());
                                               };
            
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "setting new recv callback");
          kv.second->SetRecvCallback(MakeFunctionCallback(g));
          does_block = true;
        } else {
          // non blocking and no data available: do nothing
        }
      }
    }
    for(auto& kv : m_netlinks) {
      NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "processing netlink socket: " << kv.first);
      if(readfds && FD_ISSET(kv.first,&myreadfds)) {
        if(kv.second->HasData()) {
          FD_SET(kv.first, &newreadfds);
          may_block = false;
          ++ctx;
        } else if (may_block) {
          //UNSUPPORTED("select: blocking netlink socket");
          int fdnr = kv.first;
          std::shared_ptr<NetlinkSocket> nl_sock = kv.second;
          std::function<void()> g = [this,readfds,writefds,exceptfds,fdnr,already_handled,nl_sock,timeout_event]() {
            // needed precaution if multiple sockets receive at same time (possible with ns3)
            if(*already_handled) return;
            *already_handled = true;
            timeout_event->Cancel();
            NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "read(netlink) fd ready");
            SyscallHandlerStatusCode res = SYSC_SUCCESS;
            do {
              fd_set newreadfds;
              fd_set newwritefds;
              fd_set newexceptfds;
              FD_ZERO(&newreadfds);
              FD_ZERO(&newwritefds);
              FD_ZERO(&newexceptfds);

              FD_SET(fdnr, &newreadfds);

              StoreToTracee(pid, &newreadfds,   readfds);
              StoreToTracee(pid, &newwritefds,  writefds);
              StoreToTracee(pid, &newexceptfds, exceptfds);
              FAKE2(1);
            } while(false);
            ProcessStatusCode(res, SYS_select);
            nl_sock->UnsetRecvCallback();
          };
            
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "setting new recv(netlink) callback");
          nl_sock->SetRecvCallback(g);
          does_block = true;
        } else {
          // non blocking and no data available: do nothing
        }
      }
    }

    if(may_block && does_block) {
      if(timeout) {
        std::function<void()> to_cb = [this,already_handled]() {
          NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "select timeout");
          if(*already_handled) return;
          *already_handled = true;
          SyscallHandlerStatusCode res = SYSC_SUCCESS;
          do {
            // if(timeout) {
            //   struct timeval mytimeoutl = mytimeout;
            //   mytimeoutl.tv_sec = mytimeoutl.tv_usec = 0;
            //   StoreToTracee(pid, &mytimeoutl, timeout);
            // }
            FAKE2(0);
          } while(0);
          ProcessStatusCode(res, SYS_select);
        };
        NS_LOG_LOGIC(pid << " [" << Simulator::Now().GetSeconds() << "s] " << "setting new timeout");
        *timeout_event = Simulator::Schedule(Seconds(mytimeout.tv_sec)+MicroSeconds(mytimeout.tv_usec),
                            MakeFunctionalEvent(to_cb));
      }
      return SYSC_DELAYED;
    }
    if(!may_block && does_block) {
      *already_handled = true;
    }
    
    StoreToTracee(pid, &newreadfds,   readfds);
    StoreToTracee(pid, &newwritefds,  writefds);
    StoreToTracee(pid, &newexceptfds, exceptfds);
    if(timeout) {
      mytimeout.tv_sec = mytimeout.tv_usec = 0;
      StoreToTracee(pid, &mytimeout, timeout);
    }
    
    FAKE(ctx);
    return SYSC_SUCCESS;
  }
  
  // ssize_t recvmsg(int socket, struct msghdr *message, int flags);
  SyscallHandlerStatusCode HandleRecvMsg()
  {
    int socket;
    struct msghdr *message; // OUT
    int flags;
    
    read_args(pid, socket, message, flags);

    // The low-level call RecvMsg is only implemented for netlink sockets as of now.
    if(m_netlinks.find(socket) != m_netlinks.end()) {
      return m_netlinks.at(socket)->HandleRecvMsg(socket, message, flags);
    } else {
      NS_ASSERT(false && "UNIMPLEMENTED");
    }
  }

  //ssize_t sendmsg(int socket, const struct msghdr *message, int flags);
  SyscallHandlerStatusCode HandleSendMsg()
  {
    int socket;
    struct msghdr *message;
    int flags;
    
    read_args(pid, socket, message, flags);
    
    if(m_netlinks.find(socket) == m_netlinks.end()) {
      NS_ASSERT(false && "UNIMPLEMENTED");
    }
    
    return m_netlinks.at(socket)->HandleSendMsg(socket, message, flags);
  }
  
  // int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  SyscallHandlerStatusCode HandleAccept()
  {
    int sockfd;
    struct sockaddr *addr;
    socklen_t *addrlen;
    read_args(pid, sockfd, addr, addrlen);
    
    NS_ASSERT(FdIsEmulatedSocket(sockfd) && m_isListenTcpSocket.count(sockfd));
    
    // todo: handle blocking question
    bool dont_block = m_nonblocking_sockets.count(sockfd);
    bool already_fake_accepted = m_fakeAcceptedSockets.count(sockfd);
    
    if(already_fake_accepted) {
      auto ns3Sock = std::get<0>(m_fakeAcceptedSockets.at(sockfd));
      auto ns3Addr = std::get<1>(m_fakeAcceptedSockets.at(sockfd));
      m_fakeAcceptedSockets.erase(sockfd);
      SetBsdAddress(ns3Addr, addr, addrlen);

      int new_socket_fd = GetNextFD();
      m_sockets[new_socket_fd] = ns3Sock;
      m_tcpSockets.insert(new_socket_fd);
      m_connectedSockets.insert(new_socket_fd);
      FAKE(new_socket_fd);
      
      return SYSC_SUCCESS;
    } else {
      if(dont_block) {
        FAKE(-EWOULDBLOCK);
        return SYSC_FAILURE;
      }
      
      // register accept handler
      std::function<void(Ptr<Socket>, const Address&)> acceptCallback
        = [this,sockfd,addr,addrlen](Ptr<Socket> ns3Sock, const  Address& ns3Addr) {
            
            SetBsdAddress(ns3Addr, addr, addrlen);
            
            int new_socket_fd = GetNextFD();
            m_sockets[new_socket_fd] = ns3Sock;
            m_tcpSockets.insert(new_socket_fd);
            m_connectedSockets.insert(new_socket_fd);

            SyscallHandlerStatusCode res = SYSC_SUCCESS;
            FAKE2(new_socket_fd);
            ProcessStatusCode(res, SYS_accept);
          };
      m_sockets.at(sockfd)->SetAcceptCallback(MakeNullCallback<bool,Ptr<Socket>,const Address&>(),
                                              MakeFunctionCallback(acceptCallback));
      return SYSC_DELAYED;
    }
  }
  
  // ssize_t recvfrom(int socket, void *restrict buffer, size_t length,
  //                  int flags, struct sockaddr *restrict address,
  //                  socklen_t *restrict address_len);
  SyscallHandlerStatusCode HandleRecvFrom()
  {
    int socket;
    void* buffer;             // OUT
    size_t length;
    int flags;
    struct sockaddr* address; // OUT
    socklen_t* address_len;   // OUT

    read_args(pid, socket, buffer, length, flags, address, address_len);

    NS_LOG_LOGIC(pid << ": [EE] socket with socket: " << socket);
    NS_LOG_LOGIC(pid << ": [EE] socket with buffer: " << buffer);
    NS_LOG_LOGIC(pid << ": [EE] socket with length: " << length);
    NS_LOG_LOGIC(pid << ": [EE] socket with flags: " << flags);
    NS_LOG_LOGIC(pid << ": [EE] socket with address: " << address);
    NS_LOG_LOGIC(pid << ": [EE] socket with address_len: " << address_len);
          
 
    if(m_sockets.find(socket) == m_sockets.end()) {
      NS_LOG_ERROR("could not find ns-3 socket for file descriptor " << socket);
      return SYSC_ERROR;
    }
    Ptr<Socket> ns3socket = m_sockets.at(socket);

    if(flags != 0 && ns3socket->GetObject<TcpSocketBase>()) {
      NS_LOG_WARN("socket flags are not supported by ns-3's TCP implementation");
      flags = 0;
    }

    std::function<void(Ptr<Socket>)> g = [=](Ptr<Socket> sock) {
      SyscallHandlerStatusCode res;
      do {
        // read packet and sender address from ns3
        uint8_t _buffer[ALIGN(length)];
        Address ns3Address;

        // WARNING: Don't use RecvFrom like this from ns-3, unlike Unix, it wont kill packet from the queue sometimes
        // (!!!dontuse!!!) int rlen = sock->RecvFrom(_buffer, length, flags, ns3Address);
        // Instead, use the API like this:
        int rlen = 0;
        {
          Ptr<Packet> p = sock->RecvFrom (std::numeric_limits<uint32_t>::max(), flags, ns3Address);
          if (p != 0) {
            p->CopyData (_buffer, std::min((uint32_t)length, p->GetSize ()));
            rlen = p->GetSize ();
          }
        }

        // copy from address to tracee
        if(!SetBsdAddress(ns3Address, address, address_len)) {
          res = SYSC_ERROR;
          break;
        }

        // copy message to tracee
        if(rlen > 0) {
          MemcpyToTracee(pid, buffer, _buffer, std::min(length,(size_t)rlen));
        }

        FAKE2(rlen);
        res = SYSC_SUCCESS;
        
      } while(false);
      
      ProcessStatusCode(res, SYS_recvfrom);

      // reset ns3 callback (recvfrom is blocking, thus a one-shot callback)
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      // !!! CAREFUL: do NOT call this earlier in the lambda expression,                            !!!
      // !!! as it causes the closure's stack to be destroyed by the C++ runtime.                   !!!
      // !!! If you call this line earlier than here, it will cause undefined behavior.             !!!
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      sock->SetRecvCallback(MakeNullCallback<void,Ptr<Socket>>());
    };

    if(ns3socket->GetRxAvailable()) {
      // return immediately
      g(ns3socket);
      return SYSC_MANUAL;
    } else if(m_nonblocking_sockets.count(socket)) {
      FAKE(-EWOULDBLOCK);
      return SYSC_SUCCESS;
    } else {
      // block until data arrives
      ns3socket->SetRecvCallback(MakeFunctionCallback(g));
      return SYSC_DELAYED;
    }
  }

  // int nanosleep(const struct timespec *req, struct timespec *rem);
  SyscallHandlerStatusCode HandleNanoSleep() {
    struct timespec* req;
    // //struct timespec* rem;

    read_args(pid, req/*, rem*/);

    struct timespec* _req = (timespec*)malloc(ALIGN(sizeof(struct timespec)));
    MemcpyFromTracee(pid, _req,req,sizeof(struct timespec));

    std::function<void()> cb = [this](){
      SyscallHandlerStatusCode res = SYSC_SUCCESS;
      do {
        FAKE2(0);
      } while(0);
      ProcessStatusCode(res, SYS_nanosleep);
    };
    
    Simulator::Schedule(Seconds(_req->tv_sec)+NanoSeconds(_req->tv_nsec), MakeFunctionalEvent(cb));

    free(_req);
    return SYSC_DELAYED;
  }
  
  // time_t time(time_t *tloc);
  SyscallHandlerStatusCode HandleTime() {
    time_t *tloc;
    read_args(pid, tloc);
    time_t mytloc;

    LoadFromTracee(pid, &mytloc, tloc);
    mytloc = Simulator::Now().ToInteger(Time::S);
    StoreToTracee(pid, &mytloc, tloc);
    FAKE(mytloc);
    
    return SYSC_SUCCESS;
  }

  // int gettimeofday(struct timeval *tv, struct timezone *tz);
  SyscallHandlerStatusCode HandleGetTimeOfDay() {
    struct timeval *tv;
    struct timezone *tz;
    read_args(pid, tv, tz);
    struct timeval mytv;
    //struct timezone mytz;

    NS_ASSERT(!tz);
    
    LoadFromTracee(pid, &mytv, tv);

    mytv.tv_sec  = Simulator::Now().ToInteger(Time::S);
    mytv.tv_usec = Simulator::Now().ToInteger(Time::US) - mytv.tv_sec * 1000000;
    
    StoreToTracee(pid, &mytv, tv);

    FAKE(0);
    return SYSC_SUCCESS;
  }

  // int clock_gettime(clockid_t clk_id, struct timespec *tp);
  SyscallHandlerStatusCode HandleClockGetTime() {
    clockid_t clk_id;
    struct timespec *tp;
    read_args(pid, clk_id, tp);
    struct timespec mytp;
    LoadFromTracee(pid, &mytp, tp);

    // check for unspported clocks
    if(clk_id == CLOCK_PROCESS_CPUTIME_ID || clk_id == CLOCK_THREAD_CPUTIME_ID) {
      FAKE(-1);
      return SYSC_FAILURE;
    }
    
    mytp.tv_sec  = Simulator::Now().ToInteger(Time::S);
    mytp.tv_nsec = Simulator::Now().ToInteger(Time::NS) - (long)(mytp.tv_sec) * 1000000000;
    
    StoreToTracee(pid, &mytp, tp);
    return SYSC_SUCCESS;
  }

  // int clock_getres(clockid_t clk_id, struct timespec *res);
  SyscallHandlerStatusCode HandleClockGetRes() {
    clockid_t clk_id;
    struct timespec *res;
    read_args(pid, clk_id, res);
    struct timespec myres;
    // LoadFromTracee(pid, &myres, res);

    // report FAILURE for unsupported clock types
    if(clk_id == CLOCK_PROCESS_CPUTIME_ID || clk_id == CLOCK_THREAD_CPUTIME_ID) {
      FAKE(-1);
      return SYSC_FAILURE;
    }

    myres.tv_sec  =  0;
    myres.tv_nsec = 10; // a reported resolution of 10ns seems reasonable, since ns-3 has 1ns internal resolution.
    
    StoreToTracee(pid, &myres, res);
    return SYSC_SUCCESS;
  }

  // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  SyscallHandlerStatusCode HandleBind() {
    int sockfd;
    struct sockaddr* addr;
    socklen_t addrlen;

    read_args(pid, sockfd, addr, addrlen);

    if(m_sockets.find(sockfd) != m_sockets.end()) {
      std::shared_ptr<Address> ns3addr = GetNs3Address(addr,addrlen);
      if(!ns3addr) {
        return SYSC_ERROR;
      }
    
      int ret = m_sockets.at(sockfd)->Bind(*ns3addr);

      FAKE(ret);
      return SYSC_SUCCESS;
    }
    else if(m_netlinks.find(sockfd) != m_netlinks.end()) {
      return m_netlinks.at(sockfd)->HandleBind(sockfd, addr, addrlen);
    }
    else {
      NS_LOG_ERROR("could not find ns-3 socket or NETLINK socket for file descriptor " << sockfd);
      return SYSC_ERROR;
    }
  }

  //int poll(struct pollfd *fds, nfds_t nfds, int timeout);
  SyscallHandlerStatusCode HandlePoll() {
    struct pollfd* fds;
    nfds_t nfds;
    int timeout;
    read_args(pid, fds, nfds, timeout);

    struct pollfd _fds[nfds];
    MemcpyFromTracee(pid, _fds,fds,nfds*sizeof(struct pollfd));
    
    NS_LOG_LOGIC("poll, descriptors: ");
    for(nfds_t i = 0; i < nfds; i++) {
      NS_LOG_LOGIC("pollfd: " << i);
      NS_LOG_LOGIC(" fd: " << _fds[i].fd);
      NS_LOG_LOGIC(" events: " << _fds[i].events);
      NS_LOG_LOGIC(" revents: " << _fds[i].revents);

      if(m_sockets.find(_fds[i].fd) != m_sockets.end()) {
        // UNIMPLEMENTED 
        return SYSC_ERROR;
      }
    }
    NS_LOG_LOGIC("timeout: " << timeout);
    return HandleSyscallAfter();
  }

  // int getrandom(void *buf, size_t buflen, unsigned int flags);
  SyscallHandlerStatusCode HandleGetRandom() {
    void* buf;
    size_t buflen;
    unsigned int flags;

    read_args(pid, buf, buflen, flags);
    
    NS_LOG_LOGIC("buf: " << buf);
    NS_LOG_LOGIC("buflen: " << buflen);
    NS_LOG_LOGIC("flags: " << flags);
    
    if(flags & ~(GRND_RANDOM | GRND_NONBLOCK)) {
      NS_LOG_ERROR(pid << ": [EE] SYS_getrandom: unsupported flags specified");
      return SYSC_ERROR;
    }

    uint8_t _buf[buflen];
    for(size_t i=0; i<buflen; i++) {
      // future work: should use every byte of interger instead for efficient use of RNG resources
      _buf[i] = rng->GetInteger();
    }

    MemcpyToTracee(pid, buf,_buf,buflen);
    
    FAKE(buflen);
    return SYSC_SUCCESS;
  }

  Ptr<NetDevice> GetNetDeviceByName(const std::string& ifname) {
    std::regex wlan_regex("^wlan");
    std::regex p2p_regex("^eth");
    if(std::regex_search(ifname, wlan_regex)) {
      // use first wifi device of node for now
      Ptr<ns3::WifiNetDevice> wifi;
      uint32_t nDevices = app->GetNode()->GetNDevices();
      for(uint32_t i=0; i<nDevices; i++) {
        wifi = app->GetNode()->GetDevice(i)->GetObject<ns3::WifiNetDevice>();
        if(wifi) break;
      }
      return wifi;
    } else if(std::regex_search(ifname, p2p_regex)) {
      // use first p2p device of node for now
      Ptr<ns3::PointToPointNetDevice> p2p;
      uint32_t nDevices = app->GetNode()->GetNDevices();
      for(uint32_t i=0; i<nDevices; i++) {
        p2p = app->GetNode()->GetDevice(i)->GetObject<ns3::PointToPointNetDevice>();
        if(p2p) break;
      }
      return p2p;
    } else {
      NS_ASSERT(false && "only wifi and p2p interfaces supported for now");
    }
  }
};

GrailApplication::GrailApplication ()
  :p(new Priv)
{
  p->app = this;
  p->rt  = CreateObject<HgRoutingProtocol> ();
  p->rng = CreateObject<UniformRandomVariable> ();
  p->rng->SetAttribute("Min", DoubleValue(0.0));
  p->rng->SetAttribute("Max", DoubleValue(255.0));
  p->egid = p->gid = p->euid = p->uid = 0; // root

#define MAX_NUM_FDS 100
  for (int i=100; i<100+MAX_NUM_FDS; i++) {
    p->availableFDs.insert(i);
  }

  // set fake pid, which is simply a global counter variable.
  static int global_process_pids = 0;
  p->fake_pid = ++global_process_pids;

}

GrailApplication::~GrailApplication ()
{}

void GrailApplication::StartApplication (void)
{
  if(m_enableRouting) {
    Ptr<Ipv4> ipv4 = GetNode ()->GetObject<Ipv4> ();
    auto oldRt = ipv4->GetRoutingProtocol ();
    auto oldLrt = DynamicCast<Ipv4ListRouting>(oldRt);
    if(oldLrt) {
      oldLrt->AddRoutingProtocol(p->rt,100);
    }
    else {
      Ptr<Ipv4ListRouting> lRt = CreateObject<Ipv4ListRouting>();
      ipv4->SetRoutingProtocol (lRt);
      lRt->AddRoutingProtocol(oldRt,1);
      lRt->AddRoutingProtocol(p->rt,2);
    }
  }
  
  pid_t child = fork();
  if (child == 0) {
    int argc = p->args.size();
    char *argv [argc+1];
    argv[argc] = NULL;
    for(int i=0; i<argc; i++) {
      argv[i] = const_cast<char*>(p->args.at(i).c_str());
    }

    ptrace(PTRACE_TRACEME);
    // kill(getpid(), SIGSTOP); // WARNING: interferes with valgrind usage, but enables "execve" tracing
    int ret;
    if(!m_enablePreloading) {
      ret = execvp(argv[0], argv);
    } else {
      char * const newenviron[] = { (char*const) "LD_PRELOAD=./build/src/grail/libnovdso.so", NULL };
      ret = execvpe(argv[0], argv, newenviron);
    }
    if(ret < 0) {
      exit(1);
    }
  } else {
    p->pid = child;
    p->DoTrace();
  }
}

void GrailApplication::StopApplication (void)
{}


int GrailApplication::Priv::DoTrace() {
  int status, c;
  waitpid(pid, &status, 0);
  c = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
  NS_ASSERT(c == 0);
  
  HandleSyscallBefore();
  
  return 0;
}

bool fileExists(const std::string &file){
  struct stat buf;
  return (stat(file.c_str(), &buf)==0);
}

void GrailApplication::Setup(const std::vector<std::string>& args)
{
  std::string filePath {args[0]};
  std::string notFoundErrMsg {"Application " + filePath + " not found!"};

  if (!fileExists(filePath)){
    NS_LOG_ERROR (notFoundErrMsg);
    exit (EXIT_FAILURE);
  }
  p->args = args;
}

}
