#include "util_load.h"
#include <mist/downloader.h>
#include <mist/encryption.h>
#include <mist/triggers.h>

namespace Loadbalancer {
  // rebalancing
  int minstandby = 1;
  int maxstandby = 1;
  double cappacityTriggerCPUDec = 0.01; // percentage om cpu te verminderen
  double cappacitytriggerBWDec = 0.01;  // percentage om bandwidth te verminderen
  double cappacityTriggerRAMDec = 0.01; // percentage om ram te verminderen
  double cappacityTriggerCPU = 0.9;     // max capacity trigger for balancing cpu
  double cappacityTriggerBW = 0.9;      // max capacity trigger for balancing bandwidth
  double cappacityTriggerRAM = 0.9;     // max capacity trigger for balancing ram
  double highCappacityTriggerCPU =
      0.8; // capacity at which considerd almost full. should be less than cappacityTriggerCPU
  double highCappacityTriggerBW =
      0.8; // capacity at which considerd almost full. should be less than cappacityTriggerBW
  double highCappacityTriggerRAM =
      0.8; // capacity at which considerd almost full. should be less than cappacityTriggerRAM
  double lowCappacityTriggerCPU =
      0.3; // capacity at which considerd almost empty. should be less than cappacityTriggerCPU
  double lowCappacityTriggerBW =
      0.3; // capacity at which considerd almost empty. should be less than cappacityTriggerBW
  double lowCappacityTriggerRAM =
      0.3; // capacity at which considerd almost empty. should be less than cappacityTriggerRAM
  int balancingInterval = 5000;
  int serverMonitorLimit;

  // timer vars
  int prometheusMaxTimeDiff = 180; // time prometheusnodes stay in system
  int prometheusTimeInterval = 10; // time prometheusnodes receive data

  std::time_t now;

  // authentication storage
  std::map<std::string, std::pair<std::string, std::string> > userAuth; // username: (passhash, salt)
  std::set<std::string> bearerTokens;
  std::string passHash;
  std::set<std::string> whitelist;
  std::map<std::string, std::time_t> activeSalts;

  std::string passphrase;
  std::string fallback;
  std::string myName;
  tthread::mutex fileMutex;

  prometheusDataNode promethNode;

  tthread::mutex mutexPrometh;

  void incrementAccX(const std::string name, const std::string field, IPC::sharedPage &page,
                     std::map<std::string, uint64_t> &records, const int value) {
    if (page.mapped) {
      std::map<std::string, uint64_t>::iterator it = records.find(name);
      uint64_t loc = records.size();
      if (it != records.end()) {
        loc = it->second;
      } else {
        tthread::lock_guard<tthread::mutex> guard(mutexPrometh);
        records[name] = loc;
      }
      Util::RelAccX accX(page.mapped);
      if (accX.isReady() && accX.getFieldAccX(field)) {
        uint32_t val = accX.getInt(field);
        accX.setInt(field, val + value, loc);
      }
    }
  }

  IPC::sharedPage promethServers;
  std::map<std::string, uint64_t> promethServersRecords;
  IPC::sharedPage promethLoadbalancers;
  std::map<std::string, uint64_t> promethLoadbalancersRecords;
  IPC::sharedPage promethStreams;
  std::map<std::string, uint64_t> promethStreamRecords;
  IPC::sharedPage promethGeoIP;
  std::map<std::string, uint64_t> promethGeoIPRecords;

  /**
   * return JSON with all prometheus data nodes
   */
  std::string handlePrometheus(bool prometheusIsJSON) {
    JSON::Value j;
    std::stringstream output;

    output << "# HELP server_" << NFAILCONNSERV << " number of failed connects to the server." << std::endl;
    output << "# TYPE server_" << NFAILCONNSERV << " counter" << std::endl;
    output << "# HELP server_" << NSUCCCONNSERV << " number of successful connects to the server." << std::endl;
    output << "# TYPE server_" << NSUCCCONNSERV << " counter" << std::endl;
    output << "# HELP server_" << NRECONNSERV << " number of reconnects to the server." << std::endl;
    output << "# TYPE server_" << NRECONNSERV << " counter" << std::endl;

    // update prometheus vars for servers
    promethServers.init("promethserver", 4096, false, false);
    if (!promethServers.mapped) { promethServers.init("promethserver", 4096, true, false); }
    if (promethServers.mapped) {
      Util::RelAccX promethServersAccX(promethServers.mapped, false);

      // if fields missing, recreate the page
      if (promethServersAccX.isReady()) {
        for (std::map<std::string, uint64_t>::iterator i = promethServersRecords.begin();
             i != promethServersRecords.end(); i++) {
          if (promethServersAccX.getFieldAccX(NRECONNSERV) && promethServersAccX.getFieldAccX(NSUCCCONNSERV) &&
              promethServersAccX.getFieldAccX(NFAILCONNSERV)) {
            if (prometheusIsJSON) {
              j["servers"][(*i).first][NRECONNSERV] = promethServersAccX.getInt(NRECONNSERV, (*i).second);
              j["servers"][(*i).first][NSUCCCONNSERV] = promethServersAccX.getInt(NSUCCCONNSERV, (*i).second);
              j["servers"][(*i).first][NFAILCONNSERV] = promethServersAccX.getInt(NFAILCONNSERV, (*i).second);
            } else {
              output << "server_" << NRECONNSERV << "{server=\"" << (*i).first << "\"} "
                     << promethServersAccX.getInt(NRECONNSERV, (*i).second) << std::endl;
              output << "server_" << NSUCCCONNSERV << "{server=\"" << (*i).first << "\"} "
                     << promethServersAccX.getInt(NSUCCCONNSERV, (*i).second) << std::endl;
              output << "server_" << NFAILCONNSERV << "{server=\"" << (*i).first << "\"} "
                     << promethServersAccX.getInt(NFAILCONNSERV, (*i).second) << std::endl;
            }
          }
        }
        if (promethServersAccX.getFieldAccX(NRECONNSERV) && promethServersAccX.getFieldAccX(NSUCCCONNSERV) &&
            promethServersAccX.getFieldAccX(NFAILCONNSERV)) {
          promethServersAccX.setReload();
          promethServers.master = true;
          promethServers.close();
          promethServers.init("promethserver", 4096, true, false);
          promethServersAccX = Util::RelAccX(promethServers.mapped, false);
        }
      }
      if (!promethServersAccX.getFieldAccX(NRECONNSERV) && !promethServersAccX.getFieldAccX(NSUCCCONNSERV) &&
          !promethServersAccX.getFieldAccX(NFAILCONNSERV)) {
        promethServersAccX.addField(NRECONNSERV, RAX_32UINT);
        promethServersAccX.addField(NSUCCCONNSERV, RAX_32UINT);
        promethServersAccX.addField(NFAILCONNSERV, RAX_32UINT);
        promethServersAccX.setRCount(1);
        promethServersAccX.setEndPos(1);
        promethServersAccX.setReady();
      }
      promethServers.master = false; // leave the page after closing
    }

    output << "# HELP loadbalancer_" << NFAILCONNLB
           << " number of failed connects to the loadbalancer." << std::endl;
    output << "# TYPE loadbalancer_" << NFAILCONNLB << " counter" << std::endl;
    output << "# HELP loadbalancer_" << NSUCCCONNLB
           << " number of successful connects to the loadbalancer." << std::endl;
    output << "# TYPE loadbalancer_" << NSUCCCONNLB << " counter" << std::endl;
    output << "# HELP loadbalancer_" << NRECONNLB << " number of reconnects to the loadbalancer." << std::endl;
    output << "# TYPE loadbalancer_" << NRECONNLB << " counter" << std::endl;

    // update prometheus vars for loadbalancers
    promethLoadbalancers.init("promethlb", 4096, false, false);
    if (!promethLoadbalancers.mapped) { promethLoadbalancers.init("promethlb", 4096, true, false); }
    if (promethLoadbalancers.mapped) {
      Util::RelAccX promethLoadbalancersAccX(promethLoadbalancers.mapped, false);

      // if fields missing, recreate the page
      if (promethLoadbalancersAccX.isReady()) {
        for (std::map<std::string, uint64_t>::iterator i = promethLoadbalancersRecords.begin();
             i != promethLoadbalancersRecords.end(); i++) {
          if (promethLoadbalancersAccX.getFieldAccX(NRECONNLB) && promethLoadbalancersAccX.getInt(NRECONNLB) &&
              promethLoadbalancersAccX.getFieldAccX(NSUCCCONNLB) &&
              promethLoadbalancersAccX.getInt(NSUCCCONNLB) && promethLoadbalancersAccX.getFieldAccX(NFAILCONNLB) &&
              promethLoadbalancersAccX.getInt(NFAILCONNLB)) {
            if (prometheusIsJSON) {
              j["loadbalancers"][(*i).first][NRECONNLB] =
                  promethLoadbalancersAccX.getInt(NRECONNLB, (*i).second);
              j["loadbalancers"][(*i).first][NSUCCCONNLB] =
                  promethLoadbalancersAccX.getInt(NSUCCCONNLB, (*i).second);
              j["loadbalancers"][(*i).first][NFAILCONNLB] =
                  promethLoadbalancersAccX.getInt(NFAILCONNLB, (*i).second);
            } else {
              output << "loadbalancer_" << NRECONNLB << "{loadbalancer=\"" << (*i).first << "\"} "
                     << promethLoadbalancersAccX.getInt(NRECONNLB, (*i).second) << std::endl;
              output << "loadbalancer_" << NSUCCCONNLB << "{loadbalancer=\"" << (*i).first << "\"} "
                     << promethLoadbalancersAccX.getInt(NSUCCCONNLB, (*i).second) << std::endl;
              output << "loadbalancer_" << NFAILCONNLB << "{loadbalancer=\"" << (*i).first << "\"} "
                     << promethLoadbalancersAccX.getInt(NFAILCONNLB, (*i).second) << std::endl;
            }
          }
        }
        if (promethLoadbalancersAccX.getFieldAccX(NRECONNLB) &&
            promethLoadbalancersAccX.getFieldAccX(NSUCCCONNLB) &&
            promethLoadbalancersAccX.getFieldAccX(NFAILCONNLB)) {
          promethLoadbalancersAccX.setReload();
          promethLoadbalancers.master = true;
          promethLoadbalancers.close();
          promethLoadbalancers.init("promethlb", 4096, true, false);
          promethLoadbalancersAccX = Util::RelAccX(promethLoadbalancers.mapped, false);
        }
      }
      if (!promethLoadbalancersAccX.getFieldAccX(NRECONNLB) &&
          !promethLoadbalancersAccX.getFieldAccX(NSUCCCONNLB) &&
          !promethLoadbalancersAccX.getFieldAccX(NFAILCONNLB)) {
        promethLoadbalancersAccX.addField(NRECONNLB, RAX_32UINT);
        promethLoadbalancersAccX.addField(NSUCCCONNLB, RAX_32UINT);
        promethLoadbalancersAccX.addField(NFAILCONNLB, RAX_32UINT);
        promethLoadbalancersAccX.setRCount(1);
        promethLoadbalancersAccX.setEndPos(1);
        promethLoadbalancersAccX.setReady();
      }
      promethLoadbalancers.master = false; // leave the page after closing
    }

    output << "# HELP stream_" << NVIEWERS << " number of viewers to the stream." << std::endl;
    output << "# TYPE stream_" << NVIEWERS << " counter" << std::endl;
    // update prometheus vars for streams
    promethStreams.init("promethstream", 4096, false, false);
    if (!promethStreams.mapped) { promethStreams.init("promethstream", 4096, true, false); }
    if (promethStreams.mapped) {
      Util::RelAccX promethStreamsAccX(promethStreams.mapped, false);

      // if fields missing, recreate the page
      if (promethStreamsAccX.isReady()) {
        for (std::map<std::string, uint64_t>::iterator i = promethStreamRecords.begin();
             i != promethStreamRecords.end(); i++) {
          if (promethStreamsAccX.getFieldAccX(NVIEWERS) && promethStreamsAccX.getInt(NVIEWERS)) {
            if (prometheusIsJSON) {
              j["streams"][(*i).first][NVIEWERS] = promethStreamsAccX.getInt(NVIEWERS, (*i).second);
            } else {
              output << "stream_" << NVIEWERS << "{stream=\"" << (*i).first << "\"} "
                     << promethStreamsAccX.getInt(NVIEWERS, (*i).second) << std::endl;
            }
          }
        }
        if (promethStreamsAccX.getFieldAccX(NVIEWERS)) {
          promethStreamsAccX.setReload();
          promethStreams.master = true;
          promethStreams.close();
          promethStreams.init("promethstream", 4096, true, false);
          promethStreamsAccX = Util::RelAccX(promethStreams.mapped, false);
        }
      }
      if (!promethStreamsAccX.getFieldAccX(NVIEWERS)) {
        promethStreamsAccX.addField(NVIEWERS, RAX_32UINT);
        promethStreamsAccX.setRCount(1);
        promethStreamsAccX.setEndPos(1);
        promethStreamsAccX.setReady();
      }
      promethStreams.master = false; // leave the page after closing
    }

    output << "# HELP geoip_" << NVIEWERS << " number of viewers from the location." << std::endl;
    output << "# TYPE geoip_" << NVIEWERS << " counter" << std::endl;
    output << "# HELP geoip_" << TOTDIST
           << " distance viewers are from a the server they are connecting to." << std::endl;
    output << "# TYPE geoip_" << TOTDIST << " counter" << std::endl;

    // update prometheus vars for geoip
    promethGeoIP.init("promethgeoip", 4096, false, false);
    if (!promethGeoIP.mapped) { promethGeoIP.init("promethgeoip", 4096, true, false); }
    if (promethGeoIP.mapped) {
      Util::RelAccX promethGeoIPAccX(promethGeoIP.mapped, false);

      // if fields missing, recreate the page
      if (promethGeoIPAccX.isReady()) {
        for (std::map<std::string, uint64_t>::iterator i = promethGeoIPRecords.begin();
             i != promethGeoIPRecords.end(); i++) {
          if (promethGeoIPAccX.getFieldAccX(NVIEWERS) && promethGeoIPAccX.getInt(NVIEWERS) &&
              promethGeoIPAccX.getFieldAccX(TOTDIST) && promethGeoIPAccX.getInt(TOTDIST)) {
            if (prometheusIsJSON) {
              j["geoip"][(*i).first][NVIEWERS] = promethGeoIPAccX.getInt(NVIEWERS, (*i).second);
              j["geoip"][(*i).first][TOTDIST] = promethGeoIPAccX.getInt(TOTDIST, (*i).second);
            } else {
              output << "geoip_" << NVIEWERS << "{location=\"" << (*i).first << "\"} "
                     << promethGeoIPAccX.getInt(NVIEWERS, (*i).second) << std::endl;
              output << "geoip_" << TOTDIST << "{location=\"" << (*i).first << "\"} "
                     << promethGeoIPAccX.getInt(TOTDIST, (*i).second) << std::endl;
            }
          }
        }
        if (promethGeoIPAccX.getFieldAccX(NVIEWERS) && promethGeoIPAccX.getFieldAccX(TOTDIST)) {
          promethGeoIPAccX.setReload();
          promethGeoIP.master = true;
          promethGeoIP.close();
          promethGeoIP.init("promethgeoip", 4096, true, false);
          promethGeoIPAccX = Util::RelAccX(promethStreams.mapped, false);
        }
      }
      if (!promethGeoIPAccX.getFieldAccX(NVIEWERS) && !promethGeoIPAccX.getFieldAccX(TOTDIST)) {
        promethGeoIPAccX.addField(NVIEWERS, RAX_32UINT);
        promethGeoIPAccX.addField(TOTDIST, RAX_32UINT);
        promethGeoIPAccX.setRCount(1);
        promethGeoIPAccX.setEndPos(1);
        promethGeoIPAccX.setReady();
      }
      promethGeoIP.master = false; // leave the page after closing
    }

    if (prometheusIsJSON) {
      j["successful_viewers_assignments"] = promethNode.numSuccessViewer;
      j["failed_viewers_assignments"] = promethNode.numFailedViewer;
      j["Illegal_viewers_assignments"] = promethNode.numIllegalViewer;

      j["successful_source_requests"] = promethNode.numSuccessSource;
      j["failed_source_requests"] = promethNode.numFailedSource;

      j["successful_ingest_requests"] = promethNode.numSuccessIngest;
      j["failed_ingest_requests"] = promethNode.numFailedIngest;

      j["successful_api_requests"] = promethNode.numSuccessRequests;
      j["failed_api_requests"] = promethNode.numFailedRequests;
      j["illegal_api_requests"] = promethNode.numIllegalRequests;

      j["successful_loadbalancer_requests"] = promethNode.numLBSuccessRequests;
      j["failed_loadbalancer_requests"] = promethNode.numLBFailedRequests;
      j["illegal_loadbalancer_requests"] = promethNode.numLBIllegalRequests;

      j["successful_login_attempts"] = promethNode.goodAuth;
      j["failed_login_attempts"] = promethNode.badAuth;

      return j.asString();
    } else {
      output << "# HELP successful_viewers_assignments number of times the loadbalancer "
                "successfully connects a user to their stream."
             << std::endl;
      output << "# TYPE successful_viewers_assignments counter" << std::endl;
      output << "successful_viewers_assignments " << promethNode.numSuccessViewer << "\n\n";

      output << "# HELP failed_viewers_assignments number of times the loadbalancer failed connect "
                "user to their stream."
             << std::endl;
      output << "# TYPE failed_viewers_assignments counter" << std::endl;
      output << "failed_viewers_assignments " << promethNode.numFailedViewer << "\n\n";

      output << "# HELP Illegal_viewers_assignments number of times users try to connect user to "
                "an nonexisting stream."
             << std::endl;
      output << "# TYPE Illegal_viewers_assignments counter" << std::endl;
      output << "Illegal_viewers_assignments " << promethNode.numIllegalViewer << "\n\n";

      output << "# HELP successful_source_requests number of times the loadbalancer can get a "
                "sutable source for a stream."
             << std::endl;
      output << "# TYPE successful_source_requests counter" << std::endl;
      output << "successful_source_requests " << promethNode.numSuccessSource << "\n\n";

      output << "# HELP failed_source_requests number of times the loadbalancer can't get a "
                "sutable source for a stream."
             << std::endl;
      output << "# TYPE failed_source_requests counter" << std::endl;
      output << "failed_source_requests " << promethNode.numFailedSource << "\n\n";

      output << "# HELP successful_ingest_requests number of times the loadbalancer can't get a "
                "sutable ingest point for a stream."
             << std::endl;
      output << "# TYPE successful_ingest_requests counter" << std::endl;
      output << "successful_ingest_requests " << promethNode.numSuccessIngest << "\n\n";

      output << "# HELP failed_ingest_requests number of times the loadbalancer can't get a "
                "sutable ingest point for a stream."
             << std::endl;
      output << "# TYPE failed_ingest_requests counter" << std::endl;
      output << "failed_ingest_requests " << promethNode.numFailedIngest << "\n\n";

      output << "# HELP successful_api_requests number of times the loadbalancer can execute api "
                "requests."
             << std::endl;
      output << "# TYPE successful_api_requests counter" << std::endl;
      output << "successful_api_requests " << promethNode.numSuccessRequests << "\n\n";

      output << "# HELP failed_api_requests number of times the loadbalancer can't execute api "
                "requests."
             << std::endl;
      output << "# TYPE failed_api_requests counter" << std::endl;
      output << "failed_api_requests " << promethNode.numFailedRequests << "\n\n";

      output << "# HELP illegal_api_requests number of times the loadbalancer receives invalid api "
                "requests."
             << std::endl;
      output << "# TYPE illegal_api_requests counter" << std::endl;
      output << "illegal_api_requests " << promethNode.numIllegalRequests << "\n\n";

      output << "# HELP successful_loadbalancer_requests number of times the loadbalancer can "
                "execute loadbalancer requests."
             << std::endl;
      output << "# TYPE successful_loadbalancer_requests counter" << std::endl;
      output << "successful_loadbalancer_requests " << promethNode.numLBSuccessRequests << "\n\n";

      output << "# HELP failed_loadbalancer_requests number of times the loadbalancer can't "
                "execute loadbalancer requests."
             << std::endl;
      output << "# TYPE failed_loadbalancer_requests counter" << std::endl;
      output << "failed_loadbalancer_requests " << promethNode.numLBFailedRequests << "\n\n";

      output << "# HELP illegal_loadbalancer_requests number of times the loadbalancer receives "
                "invalid loadbalancer requests."
             << std::endl;
      output << "# TYPE illegal_loadbalancer_requests counter" << std::endl;
      output << "illegal_loadbalancer_requests " << promethNode.numLBIllegalRequests << "\n\n";

      output << "# HELP successful_login_attempts number of times a login successfully occured." << std::endl;
      output << "# TYPE successful_login_attempts counter" << std::endl;
      output << "successful_login_attempts " << promethNode.goodAuth << "\n\n";

      output << "# HELP failed_login_attempts number of times a login failed." << std::endl;
      output << "# TYPE failed_login_attempts counter" << std::endl;
      output << "failed_login_attempts " << promethNode.badAuth << "\n\n";
      return output.str();
    }
  }

  /**
   * timer to send the add viewer data
   */
  void timerAddViewer(void *) {
    while (cfg->is_active) {
      JSON::Value j;
      for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++) {
        if ((*it)->state != STATE_ACTIVE) continue;
        std::string name = (*it)->name;
        j["addviewer"][name] = (*it)->details->getAddBandwidth();
      }
      for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); it++) {
        (*it)->send(j.asString());
      }
      Util::sleep(100);
    }
  }

  /**
   * redirects traffic away
   */
  bool redirectServer(hostEntry *H) {
    if (H->details->balanceBlock > 0) return true;
    std::map<int, hostEntry *> lbw;
    // find host with lowest bw usage
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++) {
      if ((*it)->state != STATE_ACTIVE) continue;
      if (highCappacityTriggerBW * (*it)->details->getAvailBandwidth() > ((*it)->details->getCurrBandwidth())) {
        lbw.insert(std::pair<uint64_t, hostEntry *>((*it)->details->getCurrBandwidth(), *it));
      }
    }
    if (!lbw.size()) return false;

    std::map<int, hostEntry *>::iterator bestServ;
    double bestScore = 0;
    for (std::map<int, hostEntry *>::iterator i = lbw.begin(); i != lbw.end(); i++) {
      if ((*i).second->details->balanceBlock <= 0) {
        double score = geoDist((*i).second->details->servLati, (*i).second->details->servLongi,
                               H->details->servLati, H->details->servLongi);
        if (score > bestScore) {
          bestServ = i;
          bestScore = score;
        }
      }
    }
    if (bestScore == 0) return false;
    JSON::Value oViewstat;
    (*bestServ).second->details->fillState(oViewstat);
    JSON::Value hViewstat;
    H->details->fillState(hViewstat);
    int cpupvo = 1000 / oViewstat["viewers"].asInt();
    int cpupvh = 1000 / hViewstat["viewers"].asInt();
    int cpuP = (highCappacityTriggerCPU * 1000 - (*bestServ).second->details->getCpu()) / cpupvo * cpupvh;
    int ramP = (highCappacityTriggerRAM * (*bestServ).second->details->getRamMax() -
                (*bestServ).second->details->getRamCurr()) *
               1000 / H->details->getRamMax();
    int bwP = (highCappacityTriggerBW * (*bestServ).second->details->availBandwidth -
               (*bestServ).second->details->getCurrBandwidth()) *
              1000 / H->details->getAvailBandwidth();
    if (cappacityTriggerCPUDec < cpuP) cpuP = cappacityTriggerCPUDec;
    if (cappacitytriggerBWDec < bwP) bwP = cappacitytriggerBWDec;
    if (cappacityTriggerRAMDec < ramP) ramP = cappacityTriggerRAMDec;

    if (cpuP > bwP && cpuP > ramP) {
      H->details->balanceP = cpuP;
    } else if (bwP > ramP) {
      H->details->balanceP = bwP;
    } else {
      H->details->balanceP = ramP;
    }
    H->details->balanceRedirect = (*bestServ).second->name;
    H->details->balanceBlock = 10;
    (*bestServ).second->details->balanceBlock = 10;

    return true;
  }
  /**
   * grabs server from standby and if minstandby reached calls trigger LOAD_OVER
   * default value of params are illegal values
   */
  void extraServer(double longi, double lati) {
    bool found = false;
    std::set<hostEntry *> availServ;
    std::set<hostEntry *>::iterator it;
    for (it = hosts.begin(); it != hosts.end(); it++) {
      if ((*it)->state == STATE_ONLINE && !(*it)->standByLock) {
        availServ.insert(*it);
        found = true;
      }
    }
    if (found) {
      if (longi <= 180 && longi >= -180 && lati <= 90 && lati >= -90) {
        // turn on closest server
        hostEntry *bestServ;
        for (std::set<hostEntry *>::iterator it = availServ.begin(); it != availServ.end(); it++) {
          if (!bestServ || geoDist(lati, longi, bestServ->details->servLati, bestServ->details->servLongi) >
                               geoDist(lati, longi, (*it)->details->servLati, (*it)->details->servLongi)) {
            bestServ = *it;
          }
        }
        removeStandBy(bestServ);
      } else {
        removeStandBy(*it);
      }
    }

    if (availServ.size() < minstandby) {
      JSON::Value serverData;
      if (longi <= 180 && longi >= -180 && lati <= 90 && lati >= -90) {
        serverData["longi"] = longi;
        serverData["lati"] = lati;
      }
      for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++) {
        if ((*it)->details) {
          serverData[(const char *)((*it)->name)] = (*it)->details->getServerData();
        }
      }
      if (Triggers::shouldTrigger("LOAD_OVER")) {
        Triggers::doTrigger("LOAD_OVER", serverData.asString());
      }
      WARN_MSG("Server capacity running low!");
    }
  }
  /**
   * puts server in standby mode and if max standby is reached calss trigger LOAD_UNDER
   */
  void reduceServer(hostEntry *H) {
    setStandBy(H, false);
    int counter = 0;
    redirectServer(H);
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++) {
      if ((*it)->state == STATE_ONLINE && !(*it)->standByLock) counter++;
    }
    if (counter > maxstandby) {
      JSON::Value serverData;
      for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++) {
        serverData[(const char *)((*it)->name)] = (*it)->details->getServerData();
      }
      if (Triggers::shouldTrigger("LOAD_UNDER")) {
        Triggers::doTrigger("LOAD_UNDER", serverData.asString());
      }
      WARN_MSG("A lot of free server ! %d free servers", counter);
    }
  }
  /**
   * checks if redirect needs to happen
   * prevents servers from going online when still balancing the servers
   */
  void checkNeedRedirect(void *) {
    while (cfg->is_active) {
      // check if redirect is needed
      bool balancing = false;
      for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++) {
        if ((*it)->state != STATE_ACTIVE) continue;
        if ((*it)->details->getRamMax() * cappacityTriggerRAM > (*it)->details->getRamCurr() ||
            cappacityTriggerCPU * 1000 < (*it)->details->getCpu() ||
            cappacityTriggerBW * (*it)->details->getAvailBandwidth() < (*it)->details->getCurrBandwidth()) {
          balancing = redirectServer(*it);
        }
      }

      if (!balancing) { // dont trigger when still balancing
        // check if reaching capacity
        std::set<hostEntry *> highCapacity;
        std::set<hostEntry *> lowCapacity;
        int counter = 0;
        for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++) {
          if ((*it)->state != STATE_ACTIVE) continue;
          counter++;
          if (highCappacityTriggerCPU * 1000 < (*it)->details->getCpu()) {
            highCapacity.insert(*it);
          }
          if (highCappacityTriggerRAM * (*it)->details->getRamMax() < (*it)->details->getRamCurr()) {
            highCapacity.insert(*it);
          }
          if (highCappacityTriggerBW * (*it)->details->getAvailBandwidth() < (*it)->details->getCurrBandwidth()) {
            highCapacity.insert(*it);
          }
          if (lowCappacityTriggerCPU * 1000 > (*it)->details->getCpu()) { lowCapacity.insert(*it); }
          if (lowCappacityTriggerRAM * (*it)->details->getRamMax() > (*it)->details->getRamCurr()) {
            lowCapacity.insert(*it);
          }
          if (lowCappacityTriggerBW * (*it)->details->getAvailBandwidth() > (*it)->details->getCurrBandwidth()) {
            lowCapacity.insert(*it);
          }
        }
        // check if too much capacity
        if (lowCapacity.size() > 1) { reduceServer(*lowCapacity.begin()); }
        // check if too little capacity
        if (lowCapacity.size() == 0 && highCapacity.size() == counter) { extraServer(); }
      }

      Util::wait(balancingInterval);
    }
  }

  /**
   * monitor server
   * \param hostEntryPointer a hostEntry with hostDetailsCalc on details field
   */
  void handleServer(void *hostEntryPointer) {
    hostEntry *entry = (hostEntry *)hostEntryPointer;
    JSON::Value bandwidth = 128 * 1024 * 1024u; // assume 1G connection
    HTTP::URL url(entry->name);
    if (!url.protocol.size()) { url.protocol = "http"; }
    if (!url.port.size()) { url.port = "4242"; }
    if (url.path.size()) {
      bandwidth = url.path;
      bandwidth = bandwidth.asInt() * 1024 * 1024;
      url.path.clear();
    }
    url.path = passphrase + ".json";

    INFO_MSG("Monitoring %s", url.getUrl().c_str());
    entry->details->availBandwidth = bandwidth.asInt();
    ((hostDetailsCalc *)(entry->details))->host = url.host;
    entry->state = STATE_BOOT;
    bool down = true;

    HTTP::Downloader DL;

    while (cfg->is_active && (entry->state != STATE_GODOWN)) {
      JSON::Value j;
      j["balancingpercentage"] = entry->details->balanceP;
      j["redirect"] = entry->details->balanceRedirect;
      DL.setHeader("Balancing", j.asString().c_str());
      if (DL.get(url) && DL.isOk()) {
        JSON::Value servData = JSON::fromString(DL.data());
        if (!servData) {
          incrementAccX(entry->name, NFAILCONNSERV, promethServers, promethServersRecords);
          FAIL_MSG("Can't decode server %s load information", url.host.c_str());
          ((hostDetailsCalc *)(entry->details))->badNess();
          DL.getSocket().close();
          down = true;
          entry->state = STATE_ERROR;
        } else {
          if (down) {
            std::string ipStr;
            Socket::hostBytesToStr(DL.getSocket().getBinHost().data(), 16, ipStr);
            WARN_MSG("Connection established with %s (%s)", url.host.c_str(), ipStr.c_str());
            memcpy(((hostDetailsCalc *)(entry->details))->binHost, DL.getSocket().getBinHost().data(), 16);
            entry->state = STATE_ONLINE;
            down = false;
            incrementAccX(entry->name, NRECONNSERV, promethServers, promethServersRecords);
          }
          ((hostDetailsCalc *)(entry->details))->update(servData);
          incrementAccX(entry->name, NSUCCCONNSERV, promethServers, promethServersRecords);
        }
      } else {
        incrementAccX(entry->name, NFAILCONNSERV, promethServers, promethServersRecords);
        FAIL_MSG("Can't retrieve server %s load information", url.host.c_str());
        ((hostDetailsCalc *)(entry->details))->badNess();
        DL.getSocket().close();
        down = true;
        entry->state = STATE_ERROR;
      }
      Util::wait(5000);
    }
    WARN_MSG("Monitoring thread for %s stopping", url.host.c_str());
    DL.getSocket().close();
    entry->state = STATE_REQCLEAN;
  }

  /**
   * create new server without starting it
   */
  void initNewHost(hostEntry &H, const std::string &N) {
    // Cancel if this host has no name set
    if (!N.size()) { return; }
    H.state = STATE_OFF;
    memset(H.name, 0, HOSTNAMELEN);
    memcpy(H.name, N.data(), N.size());
    H.thread = 0;
    H.details = 0;
    H.standByLock = 1;
  }
  /**
   * setup new server for monitoring (with hostDetailsCalc class)
   * \param N gives server name
   * \param H is the host entry being setup
   */
  void initHost(hostEntry &H, const std::string &N, bool standbyLock) {
    // Cancel if this host has no name set
    if (!N.size()) { return; }
    H.state = STATE_BOOT;
    H.details = (hostDetails *)new hostDetailsCalc(H.name);
    memset(H.name, 0, HOSTNAMELEN);
    memcpy(H.name, N.data(), N.size());
    H.thread = new tthread::thread(handleServer, (void *)&H);
    H.standByLock = standbyLock;
    INFO_MSG("Starting monitoring %s", H.name);
  }
  /**
   * Setup foreign host (with hostDetails class)
   * \param LB identifies the load balancer creating this foreign host
   * \param N gives server name
   */
  void initForeignHost(const std::string &N, bool standbyLock) {
    // Cancel if this host has no name or load balancer set
    if (!N.size()) { return; }

    hostEntry *H = new hostEntry();
    H->state = STATE_ONLINE;
    H->details = new hostDetails(H->name);
    memset(H->name, 0, HOSTNAMELEN);
    memcpy(H->name, N.data(), N.size());
    H->thread = 0;
    hosts.insert(H);
    H->standByLock = standbyLock;
    INFO_MSG("Created foreign server %s", H->name);
  }
  /**
   * remove monitored server or foreign server at \param H
   */
  void cleanupHost(hostEntry &H) {
    // Cancel if this host has no name set
    if (!H.name[0]) { return; }
    if (H.state == STATE_BOOT) {
      while (H.state != STATE_ONLINE) {}
    }
    H.state = STATE_GODOWN;
    if (H.thread) {
      // Clean up thread
      H.thread->join();
      delete H.thread;
      H.thread = 0;
    }
    // Clean up details
    delete H.details;
    H.details = 0;
    memset(H.name, 0, HOSTNAMELEN);
    H.state = STATE_OFF;
    hosts.erase(&H);
    delete &H;
  }

  /// Fills the given map with the given JSON string of tag adjustments
  void fillTagAdjust(std::map<std::string, int32_t> &tags, const std::string &adjust) {
    JSON::Value adj = JSON::fromString(adjust);
    jsonForEach(adj, t) {
      tags[t.key()] = t->asInt();
    }
  }

  /**
   * generate random string using time and process id
   */
  std::string generateSalt() {
    std::string alphbet("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    std::string out;
    out.reserve(SALTSIZE);
    for (int i = 0; i < SALTSIZE; i++) { out += alphbet[rand() % alphbet.size()]; }
    std::time_t t;
    time(&t);
    activeSalts.insert(std::pair<std::string, std::time_t>(out, t));
    return out;
  }

  /**
   * \returns the identifiers of the load balancers that need to monitor the server in \param H
   */
  std::set<std::string> hostNeedsMonitoring(hostEntry H) {
    int num = 0; // find start position
    std::set<std::string> hostnames;
    for (std::set<hostEntry *>::iterator i = hosts.begin(); i != hosts.end(); i++) {
      hostnames.insert((*i)->name);
    }
    // get offset
    for (std::set<std::string>::iterator i = hostnames.begin(); i != hostnames.end(); i++) {
      if (H.name == (*i)) break;
      num++;
    }
    // find indexes
    int trigger = hostnames.size() / identifiers.size();
    if (trigger < 1) { trigger = 1; }
    std::set<int> indexs;
    for (int j = 0; j < serverMonitorLimit; j++) {
      indexs.insert((num / trigger + j) % identifiers.size());
    }
    // find identifiers
    std::set<std::string> ret;
    std::set<int>::iterator i = indexs.begin();
    for (int x = 0; x < serverMonitorLimit && i != indexs.end(); x++) {
      std::set<std::string>::iterator it = identifiers.begin();
      std::advance(it, (*i));
      ret.insert(*it);
      i++;
    }
    return ret;
  }
  /**
   * changes host to correct monitor state
   */
  void checkServerMonitors() {
    INFO_MSG("recalibrating server monitoring")
    // check for monitoring changes
    std::set<hostEntry *>::iterator it = hosts.begin();
    while (it != hosts.end()) {
      std::set<std::string> idents = hostNeedsMonitoring(*(*it));
      std::set<std::string>::iterator i = idents.find(identifier);
      if (i != idents.end()) {
        if ((*it)->thread == 0) { // check monitored
          std::string name = ((*it)->name);
          bool standbyLock = (*it)->standByLock;

          // delete old host
          cleanupHost(**it);

          // create new host
          hostEntry *e = new hostEntry();
          initHost(*e, name, standbyLock);
          hosts.insert(e);

          // reset itterator
          it = hosts.begin();
        } else
          it++;
      } else if ((*it)->thread != 0 || (*it)->details == 0) { // check not monitored
        // delete old host
        std::string name((*it)->name);
        bool standbyLock = (*it)->standByLock;

        cleanupHost(**it);

        // create new host
        initForeignHost(name, standbyLock);

        // reset iterator
        it = hosts.begin();
      } else {
        it++;
      }
    }
  }
} // namespace Loadbalancer