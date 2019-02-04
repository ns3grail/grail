/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef GRAIL_H
#define GRAIL_H


#include <vector>
#include <string>
#include <memory>
#include <sstream>

#include "ns3/applications-module.h"
#include "ns3/application.h"
#include "ns3/socket.h"

namespace ns3 {

  class GrailApplication : public ns3::Application
  {
  public:
    GrailApplication ();
    virtual ~GrailApplication ();
    static TypeId GetTypeId ();

    void Setup(const std::vector<std::string>& argv);
  private:
    virtual void StartApplication (void);
    virtual void StopApplication (void);

    // attributes:
    int  m_printStdout; 
    bool m_enableRouting; 
    bool m_mayQuit; 
    bool m_enablePreloading; 
    Time m_syscallProcessingTime;
    bool m_pollLoopDetection;

    // Most of the internal state is hidden with a private struct pattern.
    // This helps to keep this header concise and without all the ugly Linux headers.
    struct Priv;
    std::shared_ptr<Priv> p;
  };
  
  static inline std::string ns3AddressToString(const InetSocketAddress& addr) {
    std::stringstream ss;
    addr.GetIpv4().Print(ss);
    return ss.str();
  }


}

#endif /* GRAIL_H */

