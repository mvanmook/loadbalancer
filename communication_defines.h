#pragma once

#include <ctime>
#include <mist/shared_memory.h>
#include <mist/tinythread.h>
#include <mist/util.h>
#include <set>
#include <string>

namespace Loadbalancer{

  extern IPC::sharedPage promethStreams;
  extern std::map<std::string, uint64_t> promethStreamRecords;
  extern IPC::sharedPage promethServers;
  extern std::map<std::string, uint64_t> promethServersRecords;
  extern IPC::sharedPage promethLoadbalancers;
  extern std::map<std::string, uint64_t> promethLoadbalancersRecords;
  extern IPC::sharedPage promethGeoIP;
  extern std::map<std::string, uint64_t> promethGeoIPRecords;

// prometheus
#define NRECONNSERV "numReconnectServer"
#define NSUCCCONNSERV "numSuccessConnectServer"
#define NFAILCONNSERV "numFailedConnectServer"
#define NRECONNLB "numReconnectLB"
#define NSUCCCONNLB "numSuccessConnectLB"
#define NFAILCONNLB "numFailedConnectLB"
#define NVIEWERS "numViewers" // for streams and geo ip
#define TOTDIST "totalDistance"

// transmision json names
#define CONFSTREAMKEY "conf_streams"
#define TAGKEY "tags"
#define STREAMKEY "streams"
#define OUTPUTSKEY "outputs"
#define CPUKEY "cpu"
#define BALANCEKEY "balance"

// balancing transmision json names
#define MINSBYKEY "minstandby"
#define MAXSBYKEY "maxstandby"
#define CAPTRIGCPUDECKEY "triggerdecrementcpu"      // percentage om cpu te verminderen
#define CAPTRIGBWDECKEY "triggerdecrementbandwidth" // percentage om bandwidth te verminderen
#define CAPTRIGRAMDECKEY "triggerdecrementram"      // percentage om ram te verminderen
#define CAPTRIGCPUKEY "triggercpu"                  // max capacity trigger for balancing cpu
#define CAPTRIGBWKEY "triggerbandwidth"             // max capacity trigger for balancing bandwidth
#define CAPTRIGRAMKEY "triggerram"                  // max capacity trigger for balancing ram
#define HCAPTRIGCPUKEY                                                                             \
  "balancingtriggercpu" // capacity at which considerd almost full. should be less than cappacityTriggerCPU
#define HCAPTRIGBWKEY                                                                              \
  "balancingtriggerbandwidth" // capacity at which considerd almost full. should be less than cappacityTriggerBW
#define HCAPTRIGRAMKEY                                                                             \
  "balancingtriggerram" // capacity at which considerd almost full. should be less than cappacityTriggerRAM
#define LCAPTRIGCPUKEY                                                                             \
  "balancingminimumtriggercpu" // capacity at which considerd almost full. should be less than cappacityTriggerCPU
#define LCAPTRIGBWKEY                                                                              \
  "balancingminimumtriggerbandwidth" // capacity at which considerd almost full. should be less than cappacityTriggerBW
#define LCAPTRIGRAMKEY                                                                             \
  "balancingminimumtriggerram" // capacity at which considerd almost full. should be less than cappacityTriggerRAM
#define BALINTKEY "balancingInterval"
#define SERVMONLIMKEY "servermonitorlimit"

// const websocket api names
#define SCONFKEY "configExchange"

// config file names allemaal
#define CONFFB "fallback"
#define CONFCPU "weight_cpu"
#define CONFRAM "weight_ram"
#define CONFBW "weight_bw"
#define CONFWG "weight_geo"
#define CONFWB "weight_bonus"
#define CONFPASS "passHash"
#define CONFSPASS "passphrase"
#define CONFPORT "port"
#define CONFINT "interface"
#define CONFWL "whitelist"
#define CONFBEAR "bearer_tokens"
#define CONFUSER "user_auth"
#define CONFSERV "server_list"
#define CONFLB "loadbalancers"

// balancing config file names
#define CONMINSBY "minstandby"
#define CONFMAXSBY "maxstandby"
#define CONFCAPTRIGCPUDEC "cappacitytriggerdecrementcpu" // percentage om cpu te verminderen
#define CONFCAPTRIGBWDEC                                                                           \
  "cappacitytriggerdecrementbandwidth"                   // percentage om bandwidth te verminderen
#define CONFCAPTRIGRAMDEC "cappacitytriggerdecrementram" // percentage om ram te verminderen
#define CONFCAPTRIGCPU "cappacitytriggercpu"             // max capacity trigger for balancing cpu
#define CONFCAPTRIGBW "cappacitytriggerbandwidth" // max capacity trigger for balancing bandwidth
#define CONFCAPTRIGRAM "cappacitytriggerram"      // max capacity trigger for balancing ram
#define CONFHCAPTRIGCPU                                                                            \
  "balancingtriggercpu" // capacity at which considerd almost full. should be less than cappacityTriggerCPU
#define CONFHCAPTRIGBW                                                                             \
  "balancingtriggerbandwidth" // capacity at which considerd almost full. should be less than cappacityTriggerBW
#define CONFHCAPTRIGRAM                                                                            \
  "balancingtriggerram" // capacity at which considerd almost full. should be less than cappacityTriggerRAM
#define CONFLCAPTRIGCPU                                                                            \
  "balancingminimumtriggercpu" // capacity at which considerd almost empty. should be less than cappacityTriggerCPU
#define CONFLCAPTRIGBW                                                                             \
  "balancingminimumtriggerbandwidth" // capacity at which considerd almost empty. should be less than cappacityTriggerBW
#define CONFLCAPTRIGRAM                                                                            \
  "balancingminimumtriggerram" // capacity at which considerd almost empty. should be less than cappacityTriggerRAM
#define CONFBI "balancingInterval"

}// namespace Loadbalancer