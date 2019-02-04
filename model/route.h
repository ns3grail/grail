/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

/*
 * A separate routing protocol for gRaIL. Will be registered with the
 * gRaIL-running node. Whenever the gRaIL-emulated protocol changes
 * routing tables, it will modify this routing protocol's state.
 */

#ifndef __ROUTE_H__
#define __ROUTE_H__

#include <vector>

#include "ns3/nstime.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-static-routing.h"

namespace ns3 {
  struct RtEntry {
    Ipv4Address dst;
    uint8_t len;
    Ipv4Address gw;

    RtEntry(){}
    RtEntry(const Ipv4Address& dst, uint8_t len, const Ipv4Address& gw)
      :dst(dst),
      len(len),
      gw(gw)
    {};
    
    bool operator==(const RtEntry& rhs) const {
      return this->dst == rhs.dst && this->len == rhs.len;
    }
  };

  class HgRoutingProtocol : public ns3::Ipv4RoutingProtocol {
  public:
    static TypeId GetTypeId (void);

    HgRoutingProtocol () {};
    virtual ~HgRoutingProtocol () {};


    // route entry management:
    void AddRoute(Ipv4Address dst, uint8_t len, Ipv4Address gw);
    void DelRoute(Ipv4Address dst, uint8_t len, Ipv4Address gw);
    
    // inherited:
    virtual void NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address) {};
    virtual void NotifyInterfaceDown (uint32_t interface) {};
    virtual void NotifyInterfaceUp (uint32_t interface) {};
    virtual void NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address) {};
    virtual void PrintRoutingTable (Ptr< OutputStreamWrapper > stream, Time::Unit unit=Time::S) const {};
    virtual void PrintRoutingTable (Ptr< OutputStreamWrapper > stream) const;
    
    virtual bool 	RouteInput (Ptr< const Packet > p, const Ipv4Header &header,
                              Ptr< const NetDevice > idev, UnicastForwardCallback ucb,
                              MulticastForwardCallback mcb, LocalDeliverCallback lcb,
                              ErrorCallback ecb);

    virtual Ptr< Ipv4Route > 	RouteOutput (Ptr< Packet > p,
                                           const Ipv4Header &header,
                                           Ptr< NetDevice > oif,
                                           Socket::SocketErrno &sockerr);    
 
    virtual void 	SetIpv4 (Ptr< Ipv4 > ipv4);
  
  private:
    std::vector<RtEntry> m_entries;
    ns3::Ptr<ns3::Ipv4> m_ipv4;
  };
};

#endif //__ROUTE_H__
