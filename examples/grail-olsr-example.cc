/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "ns3/core-module.h"
#include "ns3/grail-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/point-to-point-star.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-module.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/traffic-control-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-flow-classifier.h"

#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>

#include "ns3/int64x64-128.h"

#include <iostream>
#include <functional>
#include <cmath>

using namespace ns3;

int64x64_t g_tx;
int64x64_t g_rx;

void TxTrace(Ptr<const Packet> packet) {
  g_tx += 1;
}
void RxTrace(Ptr<const Packet> packet, const Address&) {
  g_rx += 1;
}

void PrintPositions(NodeContainer*);
void PrintSmem();

int
main (int argc, char *argv[])
{
  Time::SetResolution (Time::NS);
  // LogComponentEnable("PacketSink", LOG_LEVEL_INFO);
  // LogComponentEnable("OnOffApplication", LOG_LEVEL_INFO);
  LogComponentEnable("GrailApplication", LOG_LEVEL_ERROR);
  LogComponentEnable("GrailNetlink", LOG_LEVEL_ERROR);

  uint32_t rngRun = 0;

#define OLSR_NS3 0
#define OLSR_HG  1
  uint32_t olsrVariant = OLSR_HG;
  bool olsrLq = false;
  Time transientPhase = Minutes(2.5);
  Time measurePhase = Minutes(2.0);
  Time cooldownPhase = Seconds(10.0);
  int n = 12;
  int distance = 25;
  bool pcap = false;
  DataRate rate = DataRate("1Mbps");
  bool disc = false;
  double radiusPerNode = 15.0; // reserve ~350 square meters area per node
  double discRadius;
  bool disableUserTraffic = false;
  bool printPositions = false;
  bool printPathLength = false;
  bool printSmem = false;
  bool enablePreloading = true;
  
  CommandLine cmd;
  cmd.AddValue("rngRun", "run-# of the PRNG", rngRun);
  cmd.AddValue("olsrVariant", "OLSR implementation: 0=NS3, 1=gRaIL", olsrVariant);
  cmd.AddValue("olsrLq", "Enable OLSR LinkQuality extensions", olsrLq);
  cmd.AddValue("n", "number of grid nodes", n);
  cmd.AddValue("distance", "horizontal/vertical distance between grid nodes", distance);
  cmd.AddValue("rate", "off-grid sender node constant data rate", rate);
  cmd.AddValue("transientPhase", "duration of transient phase", transientPhase);
  cmd.AddValue("measurePhase", "duration of measurement phase", measurePhase);
  cmd.AddValue("cooldownPhase", "duration of cooldown phase", cooldownPhase);
  cmd.AddValue("pcap", "enable pcap", pcap);
  cmd.AddValue("disc", "use disc instead of grid", disc);
  cmd.AddValue("disableUserTraffic", "no user traffic", disableUserTraffic);
  cmd.AddValue("printPositions", "print node positions, then quit", printPositions);
  cmd.AddValue("radiusPerNode", "used to calculate total disc area for nodes", radiusPerNode);
  cmd.AddValue("printPathLength", "print path length in addition to pdr", printPathLength);
  cmd.AddValue("enablePreloading", "enable LD-Preloading feature", enablePreloading);
  cmd.AddValue("printSmem", "print memory usage, then quit", printSmem);
  cmd.Parse (argc, argv);
  
  if(!disc && int(sqrt(n))*int(sqrt(n)) != n) {
    fprintf(stderr,"error: n should be a square number");
    return 1;
  }
  
  discRadius = std::sqrt (radiusPerNode * radiusPerNode * n);
  
  RngSeedManager::SetRun(rngRun);
  
  /// WIFI SETUP
  std::string phyMode ("ErpOfdmRate54Mbps");
  // disable fragmentation
  Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("2200"));
  // Fix non-unicast data rate to be the same as that of unicast
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
    StringValue (phyMode));
  
  
  WifiHelper wifi = WifiHelper();
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel;
  WifiMacHelper wifiMac;
  
  wifi.SetStandard (WIFI_PHY_STANDARD_80211g);
  
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
                                  "Exponent", DoubleValue (3.0),
                                  "ReferenceLoss", DoubleValue(40.1),
                                  "ReferenceDistance", DoubleValue(1));
  wifiChannel.AddPropagationLoss ("ns3::NakagamiPropagationLossModel",
                                  "m0", DoubleValue (1.0),
                                  "m1", DoubleValue (1.0),
                                  "m2", DoubleValue (1.0));
  wifiPhy.SetChannel (wifiChannel.Create ());
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
  
  // Add a non-QoS upper mac, and disable rate control
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue (phyMode),
                                "ControlMode",StringValue (phyMode));
  
  Ssid ssid = Ssid ("preview");
  wifiMac.SetType ("ns3::AdhocWifiMac",
                   "Ssid", SsidValue (ssid));
  /// END WIFI SETUP
  
  NodeContainer nodes;
  nodes.Create(n /* num nodes */);
  NodeContainer hnaNodes;
  hnaNodes.Create(2);
  
  NodeContainer allNodes;
  allNodes.Add(nodes);
  allNodes.Add(hnaNodes);
  
  MobilityHelper mobility;
  if (disc) {
    mobility.SetPositionAllocator(
                                  "ns3::UniformDiscPositionAllocator",
                                  "rho", DoubleValue (discRadius)
                                  );
  } else {
    mobility.SetPositionAllocator(
                                  "ns3::GridPositionAllocator",
                                  "GridWidth", UintegerValue (sqrt(n)),
                                  "DeltaX", DoubleValue (distance),
                                  "DeltaY", DoubleValue (distance)
                                  );
  }
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install(allNodes);
  
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);
  
  CsmaHelper pointToPoint;
  pointToPoint.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));
  auto hnaDevsS = pointToPoint.Install(NodeContainer(hnaNodes.Get(0), nodes.Get(0)));
  auto hnaDevsC = pointToPoint.Install(NodeContainer(hnaNodes.Get(1), nodes.Get(nodes.GetN()-1)));
  
  InternetStackHelper stack;
  stack.Install (allNodes);
  Ipv4AddressHelper address;
  address.SetBase ("10.0.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign(devices);
 
  address.SetBase ("10.0.2.0", "255.255.255.0");
  Ipv4InterfaceContainer hnaInterfacesS = address.Assign(hnaDevsS);
  address.SetBase ("10.0.4.0", "255.255.255.0");
  Ipv4InterfaceContainer hnaInterfacesC = address.Assign(hnaDevsC);
  
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  
  if(pcap) {
    wifiPhy.EnablePcap ("grail-olsr-example-wlan", devices, true);
    pointToPoint.EnablePcapAll ("grail-olsr-example-p2p", true);
  }
  
  OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(Ipv4Address ("10.0.2.1"), 9999)));
  onoff.SetConstantRate (rate);
  ApplicationContainer clientApps = onoff.Install( hnaNodes.Get (1) );
  if(!disableUserTraffic) {
    clientApps.Start(transientPhase);
    clientApps.Stop (transientPhase+measurePhase);
  }
  
  PacketSinkHelper sink ("ns3::UdpSocketFactory", Address (InetSocketAddress (Ipv4Address::GetAny (),
                                                                              9999)));
  ApplicationContainer serverApps = sink.Install( hnaNodes.Get (0) );
  serverApps.Start (transientPhase);
  serverApps.Stop (transientPhase+measurePhase);
  
  if(olsrVariant == OLSR_HG) {
    auto rng = CreateObject<UniformRandomVariable> ();
    rng->SetAttribute ("Min", DoubleValue ( 1.0));
    rng->SetAttribute ("Max", DoubleValue (10.0));
    for(size_t i=0; i<nodes.GetN(); ++i) {
      // create OLSRd configuration file
      std::string olsrd_config_name = "/tmp/olsrd_"+std::to_string(i+1)+".conf";
      FILE* cfg = fopen(olsrd_config_name.c_str(), "w");
      NS_ASSERT(cfg);
      fprintf(cfg,
              "DebugLevel   0\n"
              "Pollrate     0.5\n"
              "Interface    \"wlan0\" {}\n"
              "LockFile     \"/tmp/olsr%lu.lock\"\n"
              "%s",
              i,
              ( olsrLq ? "" : "LinkQualityLevel        0\n"));
      if(i==0) {
        fprintf(cfg, "Hna4{10.0.2.0 255.255.255.0}");
      } else if((int)i==(int)n-1) {
        fprintf(cfg, "Hna4{10.0.3.0 255.255.255.0}");
      }
      fclose(cfg);

      // create gRaIL object:
      Ptr<GrailApplication> app = CreateObject<GrailApplication>();
      app->Setup({"/usr/sbin/olsrd","-f", // default path on Debian/Ubuntu for package "olsrd"
            olsrd_config_name,
            "-nofork"});
      app->SetAttribute("EnablePreloading", BooleanValue(enablePreloading));
      app->SetAttribute("PrintStdout", BooleanValue(false));
      Time startTime = Seconds (rng->GetValue ());
      app->SetStartTime(startTime);
      nodes.Get (i)->AddApplication(app);
    }
  }
  else if(olsrVariant == OLSR_NS3) {
    OlsrHelper olsr;
    // exclude HNA interfaces
    olsr.ExcludeInterface (nodes.Get (1-1), 2);
    olsr.ExcludeInterface (nodes.Get (n-1), 2);
    // not supported by stock olsr model, requires homebrew extensions
    //    olsr.Set ("TcRedundancy", UintegerValue (2));
    for(size_t i=0; i<nodes.GetN(); ++i) {
      Ptr<Ipv4RoutingProtocol> rt = olsr.Create(nodes.Get(i));
      Ptr<Ipv4> ipv4 = nodes.Get (i)->GetObject<Ipv4> ();
      auto oldRt = ipv4->GetRoutingProtocol ();
      auto oldLrt = DynamicCast<Ipv4ListRouting>(oldRt);
      if(!oldLrt) {
        NS_ASSERT(false && "cannot find list routing protocol in nodes");
      }
      if(olsrLq)  {
        NS_ASSERT(false && "cannot use link quality with ns-3 model");
        rt->SetAttribute("UseLinkQuality", BooleanValue(olsrLq));
      }

      oldLrt->AddRoutingProtocol(rt,100);

      // add HNA entries
      auto rto = DynamicCast<olsr::RoutingProtocol>(rt);
      if(i==1-1) {
        rto->AddHostNetworkAssociation (Ipv4Address ("10.0.2.0"), Ipv4Mask ("255.255.255.0"));
      }
      if(i==(size_t)n-1) {
        rto->AddHostNetworkAssociation (Ipv4Address ("10.0.4.0"), Ipv4Mask ("255.255.255.0"));
      }
    }
  } else {
    NS_ASSERT(false && "unknown olsr variant");
  }

  g_tx = g_rx = 0;
  // add traces
  Config::ConnectWithoutContext ("/NodeList/*/ApplicationList/*/$ns3::OnOffApplication/Tx",
                                 MakeCallback (&TxTrace));
  Config::ConnectWithoutContext ("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx",
                                 MakeCallback (&RxTrace));

  if(printPositions) {
    Simulator::Schedule(Seconds(5.0), &PrintPositions, &nodes);
  }
  if(printSmem) {
    Simulator::Schedule(transientPhase + measurePhase/10*9, &PrintSmem);
  }

  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowHelper;
  flowMonitor = flowHelper.InstallAll();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
  
  Simulator::Stop(transientPhase+measurePhase+cooldownPhase);
  Simulator::Run ();

  double avg_times_forwarded = 0.0;
  uint32_t num_flows = 0;
  for (auto kv : flowMonitor->GetFlowStats ()) {
    auto flowId    = kv.first;
    auto flowStats = kv.second;
    auto fiveTuple = classifier->FindFlow(flowId);
    if(fiveTuple.destinationPort!=9999) {
      // it is not our data flow, continue
      continue;
    }
    ++num_flows;
    avg_times_forwarded += (double)flowStats.timesForwarded / (double)flowStats.rxPackets;
  }
  avg_times_forwarded /= (double)num_flows;

  if(g_tx>0) {
    printf("%2.2f", (g_rx/g_tx).GetDouble());
  } else {
    printf("%2.2f", 0.0);
  }

  if(!printPathLength) {
    printf("\n");
  }
  else {
    printf(", %2.2f\n", avg_times_forwarded);
  }
  
  Simulator::Destroy ();

  return 0;
}

void PrintPositions(NodeContainer* nodes)
{
  uint32_t nodeNum = 0;
  std::cerr << "Positions at time t=" << Simulator::Now().GetMilliSeconds()/1000 << "s:\n";
  for(NodeContainer::Iterator it = nodes->Begin();
      it != nodes->End();
      it++) {
    Vector pos = (*it)->GetObject<MobilityModel>()->GetPosition();
    std::cerr << "    Node #" << (++nodeNum) << " has pos " << pos << std::endl;
  }
  exit(1);
}

void PrintSmem()
{
  system("smem");
  exit(0);
}
