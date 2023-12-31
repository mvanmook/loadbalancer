#ifndef util_load
#define util_load

#include "communication_defines.h"
#include "server.h"

namespace Loadbalancer{
  // rebalancing
  extern int minstandby;
  extern int maxstandby;
  extern double cappacityTriggerCPUDec; // percentage om cpu te verminderen
  extern double cappacitytriggerBWDec;  // percentage om bandwidth te verminderen
  extern double cappacityTriggerRAMDec; // percentage om ram te verminderen
  extern double cappacityTriggerCPU;    // max capacity trigger for balancing cpu
  extern double cappacityTriggerBW;     // max capacity trigger for balancing bandwidth
  extern double cappacityTriggerRAM;    // max capacity trigger for balancing ram
  extern double highCappacityTriggerCPU; // capacity at which considerd almost full. should be less than cappacityTriggerCPU
  extern double highCappacityTriggerBW; // capacity at which considerd almost full. should be less than cappacityTriggerBW
  extern double highCappacityTriggerRAM; // capacity at which considerd almost full. should be less than cappacityTriggerRAM
  extern double lowCappacityTriggerCPU; // capacity at which considerd almost empty. should be less than cappacityTriggerCPU
  extern double lowCappacityTriggerBW; // capacity at which considerd almost empty. should be less than cappacityTriggerBW
  extern double lowCappacityTriggerRAM; // capacity at which considerd almost empty. should be less than cappacityTriggerRAM
  extern int balancingInterval;
  extern int serverMonitorLimit;

#define SALTSIZE 10

  // timer vars
  extern int prometheusMaxTimeDiff;  // time prometheusnodes stay in system
  extern int prometheusTimeInterval; // time prometheusnodes receive data
  extern std::time_t now;

  // authentication storage
  extern std::map<std::string, std::pair<std::string, std::string> > userAuth; // username: (passhash, salt)
  extern std::set<std::string> bearerTokens;
  extern std::string passHash;
  extern std::set<std::string> whitelist;
  extern std::map<std::string, std::time_t> activeSalts;

  extern std::string passphrase;
  extern std::string fallback;
  extern std::string myName;
  extern tthread::mutex fileMutex;

  /**
   * prometheus data sorted in PROMETHEUSTIMEINTERVA minute intervals
   * each node is stored for PROMETHEUSMAXTIMEDIFF minutes
   */
  struct prometheusDataNode{
    int numSuccessViewer; // new viewer redirects preformed without problem
    int numIllegalViewer; // new viewer redirect requests for stream that doesn't exist
    int numFailedViewer;  // new viewer redirect requests the load balancer can't forfill

    int numSuccessSource; // request best source for stream that occured without problem
    int numFailedSource;  // request best source for stream that can't be forfilled or doesn't exist

    int numSuccessIngest; // request best ingest for stream that occured without problem
    int numFailedIngest;  // request best ingest for stream that can't be forfilled or doesn't exist

    int numSuccessRequests; // http api requests that occured without problem
    int numIllegalRequests; // http api requests that don't exist
    int numFailedRequests;  // http api requests the load balancer can't forfill

    int numLBSuccessRequests; // websocket requests that occured without problem
    int numLBIllegalRequests; // webSocket requests that don't exist
    int numLBFailedRequests;  // webSocket requests the load balancer can't forfill

    int badAuth;  // number of failed logins
    int goodAuth; // number of successfull logins
  }typedef prometheusDataNode;

  extern prometheusDataNode promethNode;
  extern bool prometheusIsJSON;

  /**
   * increment map in relAccX
   */
  void incrementAccX(const std::string name, const std::string field, IPC::sharedPage &page,
                     std::map<std::string, uint64_t> &records, const int value = 1);

  /**
   * creates new prometheus data node every PROMETHEUSTIMEINTERVAL
   */
  void prometheusTimer(void *);

  /**
   * return JSON with all prometheus data nodes
   */
  std::string handlePrometheus(bool prometheusIsJSON);

  /**
   * timer to send the add viewer data
   */
  void timerAddViewer(void *);

  /**
   * redirects traffic away
   */
  bool redirectServer(struct hostEntry *H);
  /**
   * grabs server from standby and if minstandby reached calls trigger LOAD_OVER
   */
  void extraServer(double longi = 181, double lati = 181);
  /**
   * puts server in standby mode and if max standby is reached calss trigger LOAD_UNDER
   */
  void reduceServer(struct hostEntry *H);
  /**
   * checks if redirect needs to happen
   * prevents servers from going online when still balancing the servers
   */
  void checkNeedRedirect(void *);

  /**
   * monitor server
   * \param hostEntryPointer a hostEntry with hostDetailsCalc on details field
   */
  void handleServer(void *hostEntryPointer);

  /**
   * create new server without starting it
   */
  void initNewHost(hostEntry &H, const std::string &N);
  /**
   * setup new server for monitoring (with hostDetailsCalc class)
   * \param N gives server name
   * \param H is the host entry being setup
   */
  void initHost(hostEntry &H, const std::string &N, bool standbyLock);
  /**
   * Setup foreign host (with hostDetails class)
   * \param N gives server name
   */
  void initForeignHost(const std::string &N, bool standbyLock);
  /**
   * remove monitored server or foreign server at \param H
   */
  void cleanupHost(hostEntry &H);

  /// Fills the given map with the given JSON string of tag adjustments
  void fillTagAdjust(std::map<std::string, int32_t> &tags, const std::string &adjust);

  /**
   * generate random string using time and process id
   */
  std::string generateSalt();

  /**
   * \returns the identifiers of the load balancers that need to monitor the server in \param H
   */
  std::set<std::string> hostNeedsMonitoring(hostEntry H);
  /**
   * changes host to correct monitor state
   */
  void checkServerMonitors();
}// namespace Loadbalancer
#endif // util_load
