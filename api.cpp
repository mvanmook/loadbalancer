#include "api.h"
#include "util_load.h"
#include <fstream>
#include <mist/auth.h>
#include <mist/encode.h>
#include <mist/encryption.h>
#include <mist/websocket.h>
namespace Loadbalancer{

  // file save and loading vars
  tthread::thread *saveTimer;
  std::time_t prevconfigChange; // time of last config change
  std::time_t prevSaveTime;     // time of last save
  std::string fileLoc = "lbconfig.json";

  /**
   * allow connection threads to be made to call handleRequests
   */
  int handleRequest(Socket::Connection &conn){
    return handleRequests(conn, 0, 0);
  }
  /**
   * function to select the api function wanted
   */
  int handleRequests(Socket::Connection &conn, HTTP::Websocket *webSock = 0, LoadBalancer *LB = 0){
    HTTP::Parser H;
    while (conn){
      // Handle websockets
      if (webSock){
        if (webSock->readFrame()){
          LB = onWebsocketFrame(webSock, conn.getHost(), LB);
          continue;
        }else{
          Util::sleep(100);
          continue;
        }
      }else if ((conn.spool() || conn.Received().size()) && H.Read(conn)){
        // Handle upgrade to websocket if the output supports it
        std::string upgradeHeader = H.GetHeader("Upgrade");
        Util::stringToLower(upgradeHeader);
        if (upgradeHeader == "websocket"){
          INFO_MSG("Switching to Websocket mode");
          conn.setBlocking(false);
          HTTP::Parser req;
          webSock = new HTTP::Websocket(conn, req, H);
          if (!(*webSock)){
            delete webSock;
            webSock = 0;
            continue;
          }
          H.Clean();
          continue;
        }

        // handle non-websocket connections
        std::string pathvar = H.url;
        Util::StringParser path(pathvar, pathdelimiter);
        path.next();
        std::string api = path.next();

        if (H.method == "PUT" && api == "stream"){
          stream(conn, H, path.next(), path.next(), true);
          promethNode.numSuccessRequests++;
          continue;
        }
        if (H.method == "GET" && api == "salt"){// request your salt
          H.Clean();
          H.SetHeader("Content-Type", "text/plain");
          H.SetBody(userAuth.at(path.next()).second);
          H.setCORSHeaders();
          H.SendResponse("200", "OK", conn);
          H.Clean();
          promethNode.numSuccessRequests++;
          continue;
        }

        if (H.url.substr(0, passphrase.size() + 6) == "/" + passphrase){
          H.SetHeader("Content-Type", "text/json");
          H.setCORSHeaders();
          H.StartResponse("200", "OK", H, conn);
          H.Chunkify(handlePrometheus(false), conn);
          H.Chunkify(0,0,conn);
          H.Clean();
          continue;
        }

        if (H.url.substr(0, passphrase.size() + 6) == "/" + passphrase + ".json"){
          H.SetHeader("Content-Type", "text/json");
          H.setCORSHeaders();
          H.StartResponse("200", "OK", H, conn);
          H.Chunkify(handlePrometheus(true), conn);
          H.Chunkify(0,0,conn);
          H.Clean();
          continue;
        }

        // Authentication
        std::string creds = H.GetHeader("Authorization");

        // auth with username and password
        if (creds.substr(0, 5) == "Basic"){
          std::string auth = Encodings::Base64::decode(creds.substr(6, creds.size()));
          Util::StringParser cred(auth, authDelimiter);
          // check if user exists
          std::map<std::string, std::pair<std::string, std::string> >::iterator user =
              userAuth.find(cred.next());
          // check password
          if (user == userAuth.end() ||
              (*user).second.first == Secure::sha256(cred.next() + (*user).second.second)){
            H.SetBody("invalid credentials");
            H.setCORSHeaders();
            H.SendResponse("403", "Forbidden", conn);
            H.Clean();
            conn.close();
            promethNode.badAuth++;
            continue;
          }
          promethNode.goodAuth++;
        }
        // auth with bearer token
        else if (creds.substr(0, 7) == "Bearer "){
          if (!bearerTokens.count(creds.substr(7, creds.size()))){
            H.SetBody("invalid token");
            H.setCORSHeaders();
            H.SendResponse("403", "Forbidden", conn);
            H.Clean();
            conn.close();
            promethNode.badAuth++;
            continue;
          }
          promethNode.goodAuth++;
        }
        // whitelist ipv6 & ipv4
        else if (conn.getHost().size()){
          bool found = false;
          std::set<std::string>::iterator it = whitelist.begin();
          while (it != whitelist.end()){
            if (Socket::isBinAddress(conn.getBinHost(), *it)){
              found = true;
              break;
            }
            it++;
          }
          if (!found){
            H.SetBody("not in whitelist");
            H.setCORSHeaders();
            H.SendResponse("403", "Forbidden", conn);
            H.Clean();
            conn.close();
            promethNode.badAuth++;
            continue;
          }
          promethNode.goodAuth++;
        }
        // block other auth forms including none
        else{
          H.SetBody("no credentials given");
          H.setCORSHeaders();
          H.SendResponse("403", "Forbidden", conn);
          H.Clean();
          conn.close();
          promethNode.badAuth++;
          continue;
        }
        


        // API METHODS
        if (H.method == "PUT"){
          // save config
          if (api == "save"){
            api = path.next();
            if (api == "savetimeinterval"){
              int newVal = path.nextInt();
              if (newVal > 0){saveTimeInterval = newVal;}
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("saveTimeInterval: " + saveTimeInterval);
              H.setCORSHeaders();
              H.SendResponse("204", "OK", conn);
              H.Clean();
              // start save timer
              time(&prevconfigChange);
              if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
              promethNode.numSuccessRequests++;
            }else if (api == "saveloc"){
              fileLoc = H.body;
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("saveLoc: " + fileLoc);
              H.setCORSHeaders();
              H.SendResponse("204", "OK", conn);
              H.Clean();
              // start save timer
              time(&prevconfigChange);
              if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
              promethNode.numSuccessRequests++;
            }else{
              saveFile(true);
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("OK");
              H.setCORSHeaders();
              H.SendResponse("204", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
            }
          }
          // load config
          else if (api == "load"){
            loadFile();
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody("OK");
            H.setCORSHeaders();
            H.SendResponse("204", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }else if(api == "fallback"){
            fallback == path.next();
          }else if (api == "prometheus"){
            api = path.next();
            bool changed = false;
            while (api == "maxtimediff" || api == "timeinterval"){
              if (api == "maxtimediff"){
                int newVal = path.nextInt();
                if (newVal > 1 && prometheusTimeInterval < newVal){
                  prometheusMaxTimeDiff = newVal;
                  changed = true;
                }
              }else if (api == "timeinterval"){
                int newVal = path.nextInt();
                if (newVal > 1 && prometheusMaxTimeDiff > newVal){
                  prometheusTimeInterval = newVal;
                  changed = true;
                }
              }
              api = path.next();
            }
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            std::string body = "prometheusMaxTimeDiff: " + prometheusMaxTimeDiff;
            body += ", prometheusTimeInterval: " + prometheusTimeInterval;
            H.SetBody(body);
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            if (!changed){
              promethNode.numLBFailedRequests++;
            }else{
              promethNode.numSuccessRequests++;
            }

          }
          // add load balancer to mesh
          else if (api == "loadbalancers"){
            std::string loadbalancer = H.body;
            new tthread::thread(addLB, (void *)&loadbalancer);
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody("OK");
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // Get/set weights
          else if (api == "weights"){
            JSON::Value ret = setWeights(path, true);
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(ret.toString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // Add server to list
          else if (api == "servers"){
            std::string ret;
            addServer(ret, H.body, true);
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(ret.c_str());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }else if (api == "balancing"){
            balance(path);
            promethNode.numSuccessRequests++;
          }else if (api == "standby"){
            std::string name = path.next();
            std::set<hostEntry *>::iterator it = hosts.begin();
            while (name == (*it)->name && it != hosts.end()) it++;
            if (it != hosts.end()){
              setStandBy(*it, path.nextInt());
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
            }else{
              promethNode.numFailedRequests++;
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("invalid server name");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
            }
          }
          // auth
          else if (api == "auth"){
            api = path.next();
            // add bearer token
            if (api == "bearer"){
              std::string bearer = path.next();
              if (bearer.size()){
                bearerTokens.insert(bearer);
                H.Clean();
                H.SetHeader("Content-Type", "text/plain");
                H.SetBody("OK");
                H.setCORSHeaders();
                H.SendResponse("200", "OK", conn);
                H.Clean();
                promethNode.numSuccessRequests++;
                // start save timer
                time(&prevconfigChange);
                if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
              }else{
                H.Clean();
                H.SetHeader("Content-Type", "text/plain");
                H.SetBody("OK");
                H.setCORSHeaders();
                H.SendResponse("200", "OK", conn);
                H.Clean();
                promethNode.numFailedRequests++;
              }
            }
            // add user acount
            else if (api == "user"){
              std::string userName = path.next();
              std::string pass = path.next();
              if (!userName.size() || !pass.size()){
                H.Clean();
                H.SetHeader("Content-Type", "text/plain");
                H.SetBody("invalid");
                H.setCORSHeaders();
                H.SendResponse("200", "OK", conn);
                H.Clean();
                promethNode.numFailedRequests++;
              }
              std::string salt = generateSalt();
              std::string password = Secure::sha256(pass + salt);
              userAuth[userName] = std::pair<std::string, std::string>(password, salt);
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("OK");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              JSON::Value j;
              j["auser"] = userName;
              j["apass"] = password;
              j["asalt"] = salt;
              for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin();
                   it != loadBalancers.end(); it++){
                (*it)->send(j.asString());
              }
              promethNode.numSuccessRequests++;
              // start save timer
              time(&prevconfigChange);
              if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
            }
            // add whitelist policy
            else if (api == "whitelist"){
              if (!H.body.size()){
                H.Clean();
                H.SetHeader("Content-Type", "text/plain");
                H.SetBody("invalid");
                H.setCORSHeaders();
                H.SendResponse("200", "OK", conn);
                H.Clean();
                promethNode.numFailedRequests++;
              }
              whitelist.insert(H.body);
              JSON::Value j;
              j["awhitelist"] = H.body;
              for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin();
                   it != loadBalancers.end(); it++){
                (*it)->send(j.asString());
              }
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("OK");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
              // start save timer
              time(&prevconfigChange);
              if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
            }
            // handle none api
            else{
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("invalid");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numIllegalRequests++;
            }
          }
          // handle none api
          else{
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody("invalid");
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numIllegalRequests++;
          }
        }else if (H.method == "GET"){
          if (api == "save"){
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            std::string res("savetimeinterval: " + saveTimeInterval);
            res.append(", fileloc: " + fileLoc);
            H.SetBody(res);
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }else if (api == "loadbalancers"){
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(getLoadBalancerList().toPrettyString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // Get server list
          else if (api == "servers"){
            JSON::Value ret = serverList();
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(ret.toPrettyString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // Request viewer count
          else if (api == "viewers"){
            JSON::Value ret = getViewers();
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(ret.toPrettyString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // Request full stream statistics
          else if (api == "streamstats"){
            JSON::Value ret = getStreamStats(path.next());
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(ret.toPrettyString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // get stream viewer count
          else if (api == "stream"){
            uint64_t count = getStream(path.next());
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(JSON::Value(count).asString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // Find source for given stream
          else if (api == "source"){
            std::string source = path.next();
            getSource(conn, H, source, path.next(), true);
          }
          // Find optimal ingest point
          else if (api == "ingest"){
            std::string ingest = path.next();
            getIngest(conn, H, ingest, path.next(), true);
          }
          // Find host(s) status
          else if (api == "host"){
            std::string host = path.next();
            if (!host.size()){
              JSON::Value ret = getAllHostStates();
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody(ret.toPrettyString());
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
            }else{
              JSON::Value ret = getHostState(host);
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody(ret.toPrettyString());
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
            }
            // Get weights
          }else if (api == "weights"){
            JSON::Value ret = setWeights(Util::StringParser(empty, empty), false);
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(ret.toString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }else if (api == "balancing"){
            JSON::Value ret;
            ret["balancing interval"] = balancingInterval;
            ret["minstandby"] = minstandby;
            ret["maxstandby"] = maxstandby;
            ret["highcappacitytriggerbw"] = highCappacityTriggerBW;
            ret["highcappacitytriggercpu"] = highCappacityTriggerCPU;
            ret["highcappacitytriggerram"] = highCappacityTriggerRAM;
            ret["lowcappacitytriggerbw"] = lowCappacityTriggerBW;
            ret["lowcappacitytriggercpu"] = lowCappacityTriggerCPU;
            ret["lowcappacitytriggerram"] = lowCappacityTriggerRAM;
            ret["cappacitytriggerbw"] = cappacityTriggerBW;
            ret["cappacitytriggercpu"] = cappacityTriggerCPU;
            ret["cappacitytriggerram"] = cappacityTriggerRAM;
            ret["cappacitytriggercpudec"] = cappacityTriggerCPUDec;
            ret["cappacitytriggerbwdec"] = cappacitytriggerBWDec;
            ret["cappacitytriggerramdec"] = cappacityTriggerRAMDec;
            ret["servermonitorlimit"] = serverMonitorLimit;
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(ret.toString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }else if (api == "prometheus"){
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            std::string body = "prometheusMaxTimeDiff: " + prometheusMaxTimeDiff;
            body += ", prometheusTimeInterval: " + prometheusTimeInterval;
            H.SetBody(body);
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }else if (api == "auth"){
            api = path.next();
            // add bearer token
            if (api == "bearer"){
              JSON::Value j;
              j = bearerTokens;
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody(j.asString());
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
            }
            // add user acount
            else if (api == "user"){
              JSON::Value j;
              j = userAuth;
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody(j.asString());
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
            }
            // add whitelist policy
            else if (api == "whitelist"){
              JSON::Value j;
              j = whitelist;
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody(j.asString());
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
            }
            // handle none api
            else{
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("invalid");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              conn.close();
              promethNode.numIllegalRequests++;
            }
          }
          // handle none api
          else{
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody("invalid");
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            conn.close();
            promethNode.numIllegalRequests++;
          }
        }else if (H.method == "DELETE"){
          // remove load balancer from mesh
          if (api == "loadbalancers"){
            std::string loadbalancer = H.body;
            removeLB(loadbalancer, true);
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody("OK");
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // Remove server from list
          else if (api == "servers"){
            std::string s = H.body;
            JSON::Value ret = delServer(s, true);
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody(ret.toPrettyString());
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numSuccessRequests++;
          }
          // auth
          else if (api == "auth"){
            api = path.next();
            // del bearer token
            if (api == "bearer"){
              bearerTokens.erase(path.next());
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("OK");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
              // start save timer
              time(&prevconfigChange);
              if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
            }
            // del user acount
            else if (api == "user"){
              std::string userName = path.next();
              userAuth.erase(userName);
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("OK");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              JSON::Value j;
              j["ruser"] = userName;
              for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin();
                   it != loadBalancers.end(); it++){
                (*it)->send(j.asString());
              }
              promethNode.numSuccessRequests++;
              // start save timer
              time(&prevconfigChange);
              if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
            }
            // del whitelist policy
            else if (api == "whitelist"){
              std::set<std::string>::iterator it = whitelist.begin();
              while (it != whitelist.end()){
                if ((*it) == H.body){
                  whitelist.erase(it);
                  it = whitelist.begin();
                }else
                  it++;
              }

              JSON::Value j;
              j["rwhitelist"] = H.body;
              for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin();
                   it != loadBalancers.end(); it++){
                (*it)->send(j.asString());
              }
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("OK");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numSuccessRequests++;
              // start save timer
              time(&prevconfigChange);
              if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
            }
            // handle none api
            else{
              H.Clean();
              H.SetHeader("Content-Type", "text/plain");
              H.SetBody("invalid");
              H.setCORSHeaders();
              H.SendResponse("200", "OK", conn);
              H.Clean();
              promethNode.numIllegalRequests++;
            }
          }
          // handle none api
          else{
            H.Clean();
            H.SetHeader("Content-Type", "text/plain");
            H.SetBody("invalid");
            H.setCORSHeaders();
            H.SendResponse("200", "OK", conn);
            H.Clean();
            promethNode.numIllegalRequests++;
          }
        }
        // handle none api
        else{
          H.Clean();
          H.SetHeader("Content-Type", "text/plain");
          H.SetBody("invalid");
          H.setCORSHeaders();
          H.SendResponse("200", "OK", conn);
          H.Clean();
          promethNode.numIllegalRequests++;
        }
      }
    }
    // check if this is a load balancer connection
    if (LB){
      if (!LB->Go_Down){// check if load balancer crashed
        LB->state = false;
        WARN_MSG("restarting connection of load balancer: %s", LB->getName().c_str());
        incrementAccX(LB->getName(), NRECONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        new tthread::thread(reconnectLB, (void *)LB);
      }else{// shutdown load balancer
        LB->Go_Down = true;
        loadBalancers.erase(LB);
        delete LB;
        INFO_MSG("shuting Down connection");
      }
    }
    conn.close();
    return 0;
  }
  /**
   * handle websockets only used for other load balancers
   * \return loadbalancer corisponding to this socket
   */
  LoadBalancer *onWebsocketFrame(HTTP::Websocket *webSock, std::string name, LoadBalancer *LB){
    std::string frame(webSock->data, webSock->data.size());
    if (frame.substr(0, frame.size()) == "ident"){
      webSock->sendFrame(identifier);
      promethNode.numLBSuccessRequests++;
    }else if (frame.substr(0, frame.find(":")) == "auth"){
      // send response to challenge
      std::string auth = frame.substr(frame.find(":") + 1);
      std::string pass = Secure::sha256(passHash + auth);
      webSock->sendFrame(pass);

      // send own challenge
      std::string salt = generateSalt();
      webSock->sendFrame(salt);
      promethNode.numLBSuccessRequests++;
    }else if (frame.substr(0, frame.find(":")) == "salt"){
      // check responce
      std::string salt = frame.substr(frame.find(":") + 1, frame.find(";") - frame.find(":") - 1);
      std::map<std::string, time_t>::iterator saltIndex = activeSalts.find(salt);

      if (saltIndex == activeSalts.end()){
        webSock->sendFrame("noAuth");
        webSock->getSocket().close();
        WARN_MSG("no salt")
        promethNode.numLBFailedRequests++;
        return LB;
      }

      if (Secure::sha256(passHash + salt) ==
          frame.substr(frame.find(";") + 1, frame.find(" ") - frame.find(";") - 1)){
        // auth successful
        webSock->sendFrame("OK");
        // remove monitored servers to receive new data
        for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
          delServer((*it)->name, false);
        }
        // remove load balancers to receive new data
        std::set<LoadBalancer *>::iterator it = loadBalancers.begin();
        while (loadBalancers.size()){
          (*it)->send("close");
          (*it)->Go_Down = true;
          loadBalancers.erase(it);
          it = loadBalancers.begin();
        }

        LB = new LoadBalancer(webSock, frame.substr(frame.find(" ") + 1, frame.size()),
                              frame.substr(frame.find(" "), frame.size()));
        loadBalancers.insert(LB);
        INFO_MSG("Load balancer added");
        checkServerMonitors();
        promethNode.numLBSuccessRequests++;
      }else{
        webSock->sendFrame("noAuth");
        INFO_MSG("unautherized load balancer");
        LB = 0;
        promethNode.numLBFailedRequests++;
      }

    }
    // close bad auth
    else if (frame.substr(0, frame.find(":")) == "noAuth"){
      webSock->getSocket().close();
      promethNode.numLBSuccessRequests++;
    }
    // close authenticated load balancer
    else if (frame == "close"){
      LB->Go_Down = true;
      loadBalancers.erase(LB);
      webSock->getSocket().close();
      promethNode.numLBSuccessRequests++;
    }else if (LB && frame.substr(0, 1) == "{"){
      JSON::Value newVals = JSON::fromString(frame);
      if (newVals.isMember("addloadbalancer")){
        new tthread::thread(addLB, (void *)&(newVals["addloadbalancer"].asStringRef()));
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("removeloadbalancer")){
        removeLB(newVals["removeloadbalancer"], false);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("updatehost")){
        updateHost(newVals["updatehost"]);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("weights")){
        setWeights(newVals["weights"]);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("addserver")){
        std::string ret;
        addServer(ret, newVals["addserver"], false);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("removeServer")){
        delServer(newVals["removeServer"].asString(), false);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember(SCONFKEY)){
        configFromString(newVals[SCONFKEY]);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("addviewer")){
        // find host
        for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
          if (newVals["host"].asString() == (*it)->details->host){
            // call add viewer function
            jsonForEach(newVals["addviewer"], i){
              for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
                if (i.key() == (*it)->name){
                  (*it)->details->prevAddBandwidth += i.num();
                  continue;
                }
              }
            }
          }
        }
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("save")){
        saveFile();
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("load")){
        loadFile();
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember(BALANCEKEY)){
        balance(newVals[BALANCEKEY]);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("standby") && newVals.isMember("lock")){
        std::set<hostEntry *>::iterator it = hosts.begin();
        while (newVals["standby"].asString() == (*it)->name && it != hosts.end()) it++;
        if (it != hosts.end()) setStandBy(*it, newVals["lock"]);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("removestandby")){
        std::set<hostEntry *>::iterator it = hosts.begin();
        while (newVals["removestandby"].asString() == (*it)->name && it != hosts.end()) it++;
        if (it != hosts.end()) removeStandBy(*it);
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("awhitelist")){
        whitelist.insert(newVals["awhitelist"].asString());
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("apass") && newVals.isMember("auser") && newVals.isMember("asalt")){
        userAuth[newVals["auser"].asString()] =
            std::pair<std::string, std::string>(newVals["apass"].asString(), newVals["asalt"].asString());
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("rwhitelist")){
        std::set<std::string>::iterator it = whitelist.begin();
        while (it != whitelist.end()){
          if ((*it) == newVals["rwhitelist"].asString()){
            whitelist.erase(it);
            it = whitelist.begin();
          }else
            it++;
        }
        promethNode.numLBSuccessRequests++;
      }else if (newVals.isMember("ruser")){
        userAuth.erase(newVals["ruser"].asString());
        promethNode.numLBSuccessRequests++;
      }else{
        promethNode.numLBIllegalRequests++;
      }
    }else{
      promethNode.numLBIllegalRequests++;
    }
    return LB;
  }

  /**
   * set balancing settings received through API
   */
  void balance(Util::StringParser path){
    JSON::Value j;
    std::string api = path.next();
    while (api == MINSBYKEY || api == MAXSBYKEY || api == CAPTRIGCPUDECKEY || api == CAPTRIGRAMDECKEY ||
           api == CAPTRIGBWDECKEY || api == CAPTRIGCPUKEY || api == CAPTRIGRAMKEY || api == CAPTRIGBWKEY ||
           api == HCAPTRIGCPUKEY || api == HCAPTRIGRAMKEY || api == HCAPTRIGBWKEY || api == LCAPTRIGCPUKEY ||
           api == LCAPTRIGRAMKEY || api == LCAPTRIGBWKEY || api == BALINTKEY || api == SERVMONLIMKEY){
      if (api == MINSBYKEY){
        int newVal = path.nextInt();
        if (newVal > maxstandby){
          minstandby = newVal;
          j[BALANCEKEY][MINSBYKEY] = minstandby;
        }
      }else if (api == MAXSBYKEY){
        int newVal = path.nextInt();
        if (newVal < minstandby){
          maxstandby = newVal;
          j[BALANCEKEY][MAXSBYKEY] = maxstandby;
        }
      }
      if (api == CAPTRIGCPUDECKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= 1){
          cappacityTriggerCPUDec = newVal;
          j[BALANCEKEY][CAPTRIGCPUDECKEY] = cappacityTriggerCPUDec;
        }
      }else if (api == CAPTRIGRAMDECKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= 1){
          cappacityTriggerRAMDec = newVal;
          j[BALANCEKEY][CAPTRIGRAMDECKEY] = cappacityTriggerRAMDec;
        }
      }else if (api == CAPTRIGBWDECKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= 1){
          cappacitytriggerBWDec = newVal;
          j[BALANCEKEY][CAPTRIGBWDECKEY] = cappacitytriggerBWDec;
        }
      }else if (api == CAPTRIGCPUKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= 1){
          cappacityTriggerCPU = newVal;
          j[BALANCEKEY][CAPTRIGCPUKEY] = cappacityTriggerCPU;
        }
      }else if (api == CAPTRIGRAMKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= 1){
          cappacityTriggerRAM = newVal;
          j[BALANCEKEY][CAPTRIGRAMKEY] = cappacityTriggerRAM;
        }
      }else if (api == CAPTRIGBWKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= 1){
          cappacityTriggerBW = newVal;
          j[BALANCEKEY][CAPTRIGBWKEY] = cappacityTriggerBW;
        }
      }else if (api == HCAPTRIGCPUKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= cappacityTriggerCPU){
          highCappacityTriggerCPU = newVal;
          j[BALANCEKEY][HCAPTRIGCPUKEY] = highCappacityTriggerCPU;
        }
      }else if (api == HCAPTRIGRAMKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= cappacityTriggerRAM){
          highCappacityTriggerRAM = newVal;
          j[BALANCEKEY][HCAPTRIGRAMKEY] = highCappacityTriggerRAM;
        }
      }else if (api == HCAPTRIGBWKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= cappacityTriggerBW){
          highCappacityTriggerBW = newVal;
          j[BALANCEKEY][HCAPTRIGBWKEY] = highCappacityTriggerBW;
        }
      }
      if (api == LCAPTRIGCPUKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= highCappacityTriggerCPU){
          lowCappacityTriggerCPU = newVal;
          j[BALANCEKEY][LCAPTRIGCPUKEY] = lowCappacityTriggerCPU;
        }
      }else if (api == LCAPTRIGRAMKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= highCappacityTriggerRAM){
          lowCappacityTriggerRAM = newVal;
          j[BALANCEKEY][LCAPTRIGRAMKEY] = lowCappacityTriggerRAM;
        }
      }else if (api == LCAPTRIGBWKEY){
        double newVal = path.nextDouble();
        if (newVal >= 0 && newVal <= highCappacityTriggerBW){
          lowCappacityTriggerBW = newVal;
          j[BALANCEKEY][LCAPTRIGBWKEY] = lowCappacityTriggerBW;
        }
      }else if (api == BALINTKEY){
        int newVal = path.nextInt();
        if (newVal >= 0){
          balancingInterval = newVal;
          j[BALANCEKEY][BALINTKEY] = balancingInterval;
        }
      }else if (api == SERVMONLIMKEY){
        int newVal = path.nextInt();
        if (newVal >= 0){
          serverMonitorLimit = newVal;
          j[BALANCEKEY][SERVMONLIMKEY] = serverMonitorLimit;
        }
      }else{
        path.next();
      }
      api = path.next();
    }
    for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); it++){
      (*it)->send(j.asString());
    }
    // start save timer
    time(&prevconfigChange);
    if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
  }
  /**
   * set balancing settings receiverd from load balancers
   */
  void balance(JSON::Value newVals){
    if (newVals.isMember(MINSBYKEY)){
      int newVal = newVals[MINSBYKEY].asInt();
      if (newVal > maxstandby){minstandby = newVal;}
    }
    if (newVals.isMember(MAXSBYKEY)){
      int newVal = newVals[MAXSBYKEY].asInt();
      if (newVal < minstandby){maxstandby = newVal;}
    }
    if (newVals.isMember(CAPTRIGCPUDECKEY)){
      double newVal = newVals[CAPTRIGCPUDECKEY].asDouble();
      if (newVal >= 0 && newVal <= 1){cappacityTriggerCPUDec = newVal;}
    }
    if (newVals.isMember(CAPTRIGRAMDECKEY)){
      double newVal = newVals[CAPTRIGRAMDECKEY].asDouble();
      if (newVal >= 0 && newVal <= 1){cappacityTriggerRAMDec = newVal;}
    }
    if (newVals.isMember(CAPTRIGBWDECKEY)){
      double newVal = newVals[CAPTRIGBWDECKEY].asDouble();
      if (newVal >= 0 && newVal <= 1){cappacitytriggerBWDec = newVal;}
    }
    if (newVals.isMember(CAPTRIGCPUKEY)){
      double newVal = newVals[CAPTRIGCPUKEY].asDouble();
      if (newVal >= 0 && newVal <= 1){cappacityTriggerCPU = newVal;}
    }
    if (newVals.isMember(CAPTRIGRAMKEY)){
      double newVal = newVals[CAPTRIGRAMKEY].asDouble();
      if (newVal >= 0 && newVal <= 1){cappacityTriggerRAM = newVal;}
    }else if (newVals.isMember(CAPTRIGBWKEY)){
      double newVal = newVals[CAPTRIGBWKEY].asDouble();
      if (newVal >= 0 && newVal <= 1){cappacityTriggerBW = newVal;}
    }
    if (newVals[HCAPTRIGCPUKEY]){
      double newVal = newVals[HCAPTRIGCPUKEY].asDouble();
      if (newVal >= 0 && newVal <= cappacityTriggerCPU){highCappacityTriggerCPU = newVal;}
    }
    if (newVals.isMember(HCAPTRIGRAMKEY)){
      double newVal = newVals[HCAPTRIGRAMKEY].asDouble();
      if (newVal >= 0 && newVal <= cappacityTriggerRAM){highCappacityTriggerRAM = newVal;}
    }
    if (newVals.isMember(HCAPTRIGBWKEY)){
      double newVal = newVals[HCAPTRIGBWKEY].asDouble();
      if (newVal >= 0 && newVal <= cappacityTriggerBW){highCappacityTriggerBW = newVal;}
    }
    if (newVals.isMember(LCAPTRIGCPUKEY)){
      double newVal = newVals[LCAPTRIGCPUKEY].asDouble();
      if (newVal >= 0 && newVal <= highCappacityTriggerCPU){lowCappacityTriggerCPU = newVal;}
    }
    if (newVals.isMember(LCAPTRIGRAMKEY)){
      double newVal = newVals[LCAPTRIGRAMKEY].asDouble();
      if (newVal >= 0 && newVal <= highCappacityTriggerRAM){lowCappacityTriggerRAM = newVal;}
    }
    if (newVals.isMember(LCAPTRIGBWKEY)){
      double newVal = newVals[LCAPTRIGBWKEY].asDouble();
      if (newVal >= 0 && newVal <= highCappacityTriggerBW){lowCappacityTriggerBW = newVal;}
    }
    if (newVals.isMember(BALINTKEY)){
      int newVal = newVals[BALINTKEY].asInt();
      if (newVal >= 0){balancingInterval = newVal;}
    }
    if (newVals.isMember(SERVMONLIMKEY)){
      int newVal = newVals[SERVMONLIMKEY].asInt();
      if (newVal >= 0){serverMonitorLimit = newVal;}
    }
    // start save timer
    time(&prevconfigChange);
    if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
  }

  /**
   * set and get weights
   */
  JSON::Value setWeights(Util::StringParser path, bool resend){
    std::string newVals = path.next();
    while (newVals == "cpu" || newVals == "ram" || newVals == "bw" || newVals == "geo" || newVals == "bonus"){
      int num = path.nextInt();
      if (newVals == "cpu"){
        weight_cpu = num;
      }else if (newVals == "ram"){
        weight_ram = num;
      }else if (newVals == "bw"){
        weight_bw = num;
      }else if (newVals == "geo"){
        weight_geo = num;
      }else if (newVals == "bonus"){
        weight_bonus = num;
      }
      newVals = path.next();
    }

    // create json for sending
    JSON::Value ret;
    ret[CPUKEY] = weight_cpu;
    ret["ram"] = weight_ram;
    ret["bw"] = weight_bw;
    ret["geo"] = weight_geo;
    ret["bonus"] = weight_bonus;

    if (resend){
      JSON::Value j;
      j["weights"] = ret;
      for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); ++it){
        (*it)->send(j.asString());
      }
    }

    // start save timer
    time(&prevconfigChange);
    if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);

    return ret;
  }
  /**
   * set weights for websockets
   */
  void setWeights(const JSON::Value newVals){
    WARN_MSG("%s", newVals.asString().c_str())
    if (!newVals.isMember(CPUKEY)){weight_cpu = newVals[CPUKEY].asInt();}
    if (!newVals.isMember("ram")){weight_ram = newVals["ram"].asInt();}
    if (!newVals.isMember("bw")){weight_bw = newVals["bw"].asInt();}
    if (!newVals.isMember("geo")){weight_geo = newVals["geo"].asInt();}
    if (!newVals.isMember("bonus")){weight_bonus = newVals["bonus"].asInt();}
    // start save timer
    time(&prevconfigChange);
    if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
  }

  /**
   * remove server from the mesh
   */
  JSON::Value delServer(const std::string delserver, bool resend){
    JSON::Value ret;
    if (resend){
      JSON::Value j;
      j["removeServer"] = delserver;
      for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); ++it){
        (*it)->send(j.asString());
      }
    }
    {
      tthread::lock_guard<tthread::mutex> globGuard(globalMutex);

      ret = "Server not monitored - could not delete from monitored server list!";
      std::string name = "";
      std::set<hostEntry *>::iterator it = hosts.begin();
      while (it != hosts.end() && delserver != (*it)->name){it++;}
      if (it != hosts.end()){
        name = (*it)->name;
        cleanupHost(**it);
        ret[name] = stateLookup[STATE_OFF];
      }
    }

    checkServerMonitors();
    // start save timer
    time(&prevconfigChange);
    if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
    return ret;
  }
  /**
   * add server to be monitored
   */
  void addServer(std::string &ret, const std::string addserver, bool resend){
    tthread::lock_guard<tthread::mutex> globGuard(globalMutex);
    if (!addserver.size() || addserver.size() >= HOSTNAMELEN){return;}
    if (resend){
      JSON::Value j;
      j["addserver"] = addserver;
      for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); ++it){
        (*it)->send(j.asString());
      }
    }
    bool stop = false;
    hostEntry *newEntry = 0;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((std::string)(*it)->name == addserver){
        stop = true;
        break;
      }
    }
    if (stop){
      ret = "Server already monitored - add request ignored";
    }else{
      newEntry = new hostEntry();
      initNewHost(*newEntry, addserver);
      hosts.insert(newEntry);
      checkServerMonitors();

      ret = "server starting";
    }
    // start save timer
    time(&prevconfigChange);
    if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
    return;
  }
  /**
   * return server list
   */
  JSON::Value serverList(){
    JSON::Value ret;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      ret[(std::string)(*it)->name] = stateLookup[(*it)->state];
    }
    return ret;
  }

  /**
   * receive server updates and adds new foreign hosts if needed
   */
  void updateHost(JSON::Value newVals){
    std::string hostName = newVals["hostName"].asString();
    std::set<hostEntry *>::iterator i = hosts.begin();
    while (i != hosts.end()){
      if (hostName == (*i)->name) break;
      i++;
    }
    if (i == hosts.end()){
      INFO_MSG("unknown host update failed")
    }else{
      (*i)->details->update(
          newVals["fillStateOut"], newVals["fillStreamsOut"], newVals["scoreSource"].asInt(),
          newVals["scoreRate"].asInt(), newVals[OUTPUTSKEY], newVals[CONFSTREAMKEY],
          newVals[STREAMKEY], newVals[TAGKEY], newVals[CPUKEY].asInt(), newVals["servLati"].asDouble(),
          newVals["servLongi"].asDouble(), newVals["binhost"].asString().c_str(),
          newVals["host"].asString(), newVals["toadd"].asInt(), newVals["currBandwidth"].asInt(),
          newVals["availBandwidth"].asInt(), newVals["currram"].asInt(), newVals["ramMax"].asInt());
    }
  }

  /**
   * remove load balancer from mesh
   */
  void removeLB(std::string removeLoadBalancer, bool resend){
    JSON::Value j;
    j["removeloadbalancer"] = removeLoadBalancer;

    // remove load balancer
    std::set<LoadBalancer *>::iterator it = loadBalancers.begin();
    while (it != loadBalancers.end()){
      if ((*it)->getName() == removeLoadBalancer){
        INFO_MSG("removeing load balancer: %s", removeLoadBalancer.c_str());
        identifiers.erase((*it)->getIdent());
        (*it)->send("close");
        (*it)->Go_Down = true;
        loadBalancers.erase(it);
        it = loadBalancers.end();
      }else{
        it++;
      }
    }
    // notify the last load balancers
    if (resend){
      for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); it++){
        (*it)->send(j.asString());
      }
    }
    checkServerMonitors();
    // start save timer
    time(&prevconfigChange);
    if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);
  }
  /**
   * add load balancer to mesh
   */
  void addLB(void *p){
    std::string *addLoadBalancer = (std::string *)p;
    if (addLoadBalancer->find(":") == -1){addLoadBalancer->append(":8042");}

    Socket::Connection conn(addLoadBalancer->substr(0, addLoadBalancer->find(":")),
                            atoi(addLoadBalancer->substr(addLoadBalancer->find(":") + 1).c_str()),
                            false, false);

    HTTP::URL url("ws://" + (*addLoadBalancer));
    HTTP::Websocket *ws = new HTTP::Websocket(conn, url);

    ws->sendFrame("ident");

    // check responce
    int reset = 0;
    while (!ws->readFrame()){
      reset++;
      if (reset >= 20){
        WARN_MSG("auth failed: connection timeout");
        incrementAccX(*addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        return;
      }
      Util::sleep(1);
    }

    std::string ident(ws->data, ws->data.size());

    for (std::set<std::string>::iterator i = identifiers.begin(); i != identifiers.end(); i++){
      if ((*i) == ident){
        ws->sendFrame("noAuth");
        conn.close();
        WARN_MSG("load balancer already connected");
        incrementAccX(*addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        return;
      }
    }

    // send challenge
    std::string salt = generateSalt();
    ws->sendFrame("auth:" + salt);

    // check responce
    reset = 0;
    while (!ws->readFrame()){
      reset++;
      if (reset >= 20){
        WARN_MSG("auth failed: connection timeout");
        incrementAccX(*addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        return;
      }
      Util::sleep(1);
    }
    std::string result(ws->data, ws->data.size());

    if (Secure::sha256(passHash + salt) != result){
      // unautherized
      WARN_MSG("unautherised");
      incrementAccX(*addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
      ws->sendFrame("noAuth");
      return;
    }
    // send response to challenge
    reset = 0;
    while (!ws->readFrame()){
      reset++;
      if (reset >= 20){
        WARN_MSG("auth failed: connection timeout");
        incrementAccX(*addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        return;
      }
      Util::sleep(1);
    }
    std::string auth(ws->data, ws->data.size());
    std::string pass = Secure::sha256(passHash + auth);

    ws->sendFrame("salt:" + auth + ";" + pass + " " + myName);

    reset = 0;
    while (!ws->readFrame()){
      reset++;
      if (reset >= 20){
        WARN_MSG("auth failed: connection timeout");
        incrementAccX(*addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        return;
      }
      Util::sleep(1);
    }
    std::string check(ws->data, ws->data.size());
    if (check == "OK"){
      INFO_MSG("Successful authentication of load balancer %s", addLoadBalancer->c_str());
      LoadBalancer *LB = new LoadBalancer(ws, *addLoadBalancer, ident);
      loadBalancers.insert(LB);
      identifiers.insert(ident);

      JSON::Value z;
      z[SCONFKEY] = configToString();
      LB->send(z.asString());

      // start save timer
      time(&prevconfigChange);
      if (saveTimer == 0) saveTimer = new tthread::thread(saveTimeCheck, NULL);

      incrementAccX(*addLoadBalancer, NSUCCCONNLB, promethLoadbalancers, promethLoadbalancersRecords);

      // start monitoring
      handleRequests(conn, ws, LB);
    }else if (check == "noAuth"){
      addLB(addLoadBalancer);
    }
    return;
  }
  /**
   * reconnect to load balancer
   */
  void reconnectLB(void *p){
    LoadBalancer *LB = (LoadBalancer *)p;
    identifiers.erase(LB->getIdent());
    std::string addLoadBalancer = LB->getName();

    Socket::Connection conn(addLoadBalancer.substr(0, addLoadBalancer.find(":")),
                            atoi(addLoadBalancer.substr(addLoadBalancer.find(":") + 1).c_str()), false, false);

    HTTP::URL url("ws://" + (addLoadBalancer));
    HTTP::Websocket *ws = new HTTP::Websocket(conn, url);

    ws->sendFrame("ident");

    // check responce
    int reset = 0;
    while (!ws->readFrame()){
      reset++;
      if (reset >= 20){
        WARN_MSG("auth failed: connection timeout");
        incrementAccX(addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        reconnectLB(p);
        return;
      }
      Util::sleep(1);
    }

    std::string ident(ws->data, ws->data.size());

    for (std::set<std::string>::iterator i = identifiers.begin(); i != identifiers.end(); i++){
      if ((*i) == ident){
        ws->sendFrame("noAuth");
        conn.close();
        WARN_MSG("load balancer already connected");
        incrementAccX(addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        return;
      }
    }

    // send challenge
    std::string salt = generateSalt();
    ws->sendFrame("auth:" + salt);

    // check responce
    reset = 0;
    while (!ws->readFrame()){
      reset++;
      if (reset >= 20){
        WARN_MSG("auth failed: connection timeout");
        incrementAccX(addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        reconnectLB(p);
        return;
      }
      Util::sleep(1);
    }
    std::string result(ws->data, ws->data.size());

    if (Secure::sha256(passHash + salt) != result){
      // unautherized
      WARN_MSG("unautherised");
      incrementAccX(addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
      ws->sendFrame("noAuth");
      return;
    }
    // send response to challenge
    reset = 0;
    while (!ws->readFrame()){
      reset++;
      if (reset >= 20){
        WARN_MSG("auth failed: connection timeout");
        incrementAccX(addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        reconnectLB(p);
        return;
      }
      Util::sleep(1);
    }
    std::string auth(ws->data, ws->data.size());
    std::string pass = Secure::sha256(passHash + auth);

    ws->sendFrame("salt:" + auth + ";" + pass + " " + myName);

    reset = 0;
    while (!ws->readFrame()){
      reset++;
      if (reset >= 20){
        WARN_MSG("auth failed: connection timeout");
        incrementAccX(addLoadBalancer, NFAILCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
        reconnectLB(p);
        return;
      }
      Util::sleep(1);
    }
    std::string check(ws->data, ws->data.size());
    if (check == "OK"){
      INFO_MSG("Successful authentication of load balancer %s", addLoadBalancer.c_str());
      LoadBalancer *LB = new LoadBalancer(ws, addLoadBalancer, ident);
      loadBalancers.insert(LB);
      identifiers.insert(ident);
      LB->state = true;

      JSON::Value z;
      z[SCONFKEY] = configToString();
      LB->send(z.asString());

      incrementAccX(addLoadBalancer, NSUCCCONNLB, promethLoadbalancers, promethLoadbalancersRecords);
      // start monitoring
      handleRequests(conn, ws, LB);
    }else{
      reconnectLB(p);
    }
    return;
  }
  /**
   * returns load balancer list
   */
  JSON::Value getLoadBalancerList(){
    JSON::Value out;
    for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); ++it){
      out["loadbalancers"].append((*it)->getName());
    }
    return out;
  }

  /**
   * return server data of a server
   */
  JSON::Value getHostState(const std::string host){
    JSON::Value ret;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->state == STATE_OFF){continue;}
      if ((*it)->details->host == host){
        ret = stateLookup[(*it)->state];
        if ((*it)->state != STATE_ACTIVE){continue;}
        (*it)->details->fillState(ret);
        break;
      }
    }
    return ret;
  }
  /**
   * return all server data
   */
  JSON::Value getAllHostStates(){
    JSON::Value ret;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->state == STATE_OFF){continue;}
      ret[(*it)->details->host] = stateLookup[(*it)->state];
      if ((*it)->state != STATE_ACTIVE){continue;}
      (*it)->details->fillState(ret[(*it)->details->host]);
    }
    return ret;
  }

  /**
   * return viewer counts of streams
   */
  JSON::Value getViewers(){
    JSON::Value ret;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->state == STATE_OFF){continue;}
      (*it)->details->fillStreams(ret);
    }
    return ret;
  }
  /**
   * get view count of a stream
   */
  uint64_t getStream(const std::string stream){
    uint64_t count = 0;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->state == STATE_OFF){continue;}
      count += (*it)->details->getViewers(stream);
    }
    return count;
  }
  /**
   * return stream stats
   */
  JSON::Value getStreamStats(const std::string streamStats){
    JSON::Value ret;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->state == STATE_OFF){continue;}
      (*it)->details->fillStreamStats(streamStats, ret);
    }
    return ret;
  }

  /**
   * return the best source of a stream for inter server replication
   */
  void getSource(Socket::Connection conn, HTTP::Parser H, const std::string source,
                 const std::string fback, bool repeat = true){
    H.Clean();
    H.SetHeader("Content-Type", "text/plain");
    INFO_MSG("Finding source for stream %s", source.c_str());
    std::string bestHost = "";
    std::map<std::string, int32_t> tagAdjust;
    if (H.GetVar("tag_adjust") != ""){fillTagAdjust(tagAdjust, H.GetVar("tag_adjust"));}
    if (H.hasHeader("X-Tag-Adjust")){fillTagAdjust(tagAdjust, H.GetHeader("X-Tag-Adjust"));}
    double lat = 0;
    double lon = 0;
    if (H.GetVar("lat") != ""){
      lat = atof(H.GetVar("lat").c_str());
      H.SetVar("lat", "");
    }
    if (H.GetVar("lon") != ""){
      lon = atof(H.GetVar("lon").c_str());
      H.SetVar("lon", "");
    }
    if (H.hasHeader("X-Latitude")){lat = atof(H.GetHeader("X-Latitude").c_str());}
    if (H.hasHeader("X-Longitude")){lon = atof(H.GetHeader("X-Longitude").c_str());}
    uint64_t bestScore = 0;

    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->state != STATE_ACTIVE){continue;}
      if (Socket::matchIPv6Addr(std::string((*it)->details->binHost, 16), conn.getBinHost(), 0)){
        INFO_MSG("Ignoring same-host entry %s", (*it)->details->host.data());
        continue;
      }
      uint64_t score = (*it)->details->source(source, tagAdjust, 0, lat, lon);
      if (score > bestScore){
        bestHost = "dtsc://" + (*it)->details->host;
        bestScore = score;
      }
    }
    if (bestScore == 0){
      if (repeat){
        if (lon == 0 && lat == 0){
          extraServer();
        }else{
          extraServer(lon, lat);
        }
        getSource(conn, H, source, fback, false);
      }
      if (fback.size()){
        bestHost = fback;
      }else{
        bestHost = fallback;
      }
      promethNode.numFailedSource++;
      FAIL_MSG("No source for %s found!", source.c_str());
    }else{
      promethNode.numSuccessSource++;
      INFO_MSG("Winner: %s scores %" PRIu64, bestHost.c_str(), bestScore);
    }
    H.SetBody(bestHost);
    H.setCORSHeaders();
    H.SendResponse("200", "OK", conn);
    H.Clean();
  }
  /**
   * return optimal server to start new stream on
   */
  void getIngest(Socket::Connection conn, HTTP::Parser H, const std::string ingest,
                 const std::string fback, bool repeat = true){
    H.Clean();
    H.SetHeader("Content-Type", "text/plain");
    double cpuUse = atoi(ingest.c_str());
    INFO_MSG("Finding ingest point for CPU usage %.2f", cpuUse);
    std::string bestHost = "";
    std::map<std::string, int32_t> tagAdjust;
    if (H.GetVar("tag_adjust") != ""){fillTagAdjust(tagAdjust, H.GetVar("tag_adjust"));}
    if (H.hasHeader("X-Tag-Adjust")){fillTagAdjust(tagAdjust, H.GetHeader("X-Tag-Adjust"));}
    double lat = 0;
    double lon = 0;
    if (H.GetVar("lat") != ""){
      lat = atof(H.GetVar("lat").c_str());
      H.SetVar("lat", "");
    }
    if (H.GetVar("lon") != ""){
      lon = atof(H.GetVar("lon").c_str());
      H.SetVar("lon", "");
    }
    if (H.hasHeader("X-Latitude")){lat = atof(H.GetHeader("X-Latitude").c_str());}
    if (H.hasHeader("X-Longitude")){lon = atof(H.GetHeader("X-Longitude").c_str());}

    uint64_t bestScore = 0;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->state != STATE_ACTIVE){continue;}
      uint64_t score = (*it)->details->source("", tagAdjust, cpuUse * 10, lat, lon);
      if (score > bestScore){
        bestHost = (*it)->details->host;
        bestScore = score;
      }
    }
    if (bestScore == 0){
      if (repeat){
        if (lon == 0 && lat == 0){
          extraServer();
        }else{
          extraServer(lon, lat);
        }
        getIngest(conn, H, ingest, fback, false);
        return;
      }
      if (fback.size()){
        bestHost = fback;
      }else{
        bestHost = fallback;
      }
      promethNode.numFailedIngest++;
      FAIL_MSG("No ingest point found!");
    }else{
      promethNode.numSuccessIngest++;
      INFO_MSG("Winner: %s scores %" PRIu64, bestHost.c_str(), bestScore);
    }
    H.SetBody(bestHost);
    H.setCORSHeaders();
    H.SendResponse("200", "OK", conn);
    H.Clean();
  }

  /**
   * create stream
   */
  void stream(Socket::Connection conn, HTTP::Parser H, std::string proto, std::string streamName, bool repeat){
    H.Clean();
    H.SetHeader("Content-Type", "text/plain");
    // Balance given stream
    std::map<std::string, int32_t> tagAdjust;
    if (H.GetVar("tag_adjust") != ""){
      fillTagAdjust(tagAdjust, H.GetVar("tag_adjust"));
      H.SetVar("tag_adjust", "");
    }
    if (H.hasHeader("X-Tag-Adjust")){fillTagAdjust(tagAdjust, H.GetHeader("X-Tag-Adjust"));}
    double lat = 0;
    double lon = 0;
    if (H.GetVar("lat") != ""){
      lat = atof(H.GetVar("lat").c_str());
      H.SetVar("lat", "");
    }
    if (H.GetVar("lon") != ""){
      lon = atof(H.GetVar("lon").c_str());
      H.SetVar("lon", "");
    }
    if (H.hasHeader("X-Latitude")){lat = atof(H.GetHeader("X-Latitude").c_str());}
    if (H.hasHeader("X-Longitude")){lon = atof(H.GetHeader("X-Longitude").c_str());}
    H.SetVar("proto", "");
    std::string vars = H.allVars();
    if (streamName == "favicon.ico"){
      H.Clean();
      H.SendResponse("404", "No favicon", conn);
      H.Clean();
      promethNode.numIllegalViewer++;
      return;
    }
    INFO_MSG("Balancing stream %s", streamName.c_str());
    hostEntry *bestHost = 0;
    uint64_t bestScore = 0;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->state != STATE_ACTIVE){continue;}
      uint64_t score;
      if (lon == 0 && lat == 0){
        score = (*it)->details->rate(streamName, tagAdjust, lat, lon);
      }else{
        score = (*it)->details->rate(streamName, tagAdjust);
      }
      if (score > bestScore){
        bestHost = *it;
        bestScore = score;
      }
    }
    if (!bestScore || !bestHost){
      if (repeat){
        if (lon == 0 && lat == 0){
          extraServer();
        }else{
          extraServer(lon, lat);
        }
        stream(conn, H, proto, streamName, false);
      }else{
        H.Clean();
        H.SetHeader("Content-Type", "text/plain");
        H.setCORSHeaders();
        H.SetBody(fallback);
        promethNode.numFailedViewer++;
        FAIL_MSG("All servers seem to be out of bandwidth!");
      }
    }else{
      INFO_MSG("Winner: %s scores %" PRIu64, bestHost->details->host.c_str(), bestScore);
      bestHost->details->addViewer(streamName, true);
      H.Clean();
      H.SetHeader("Content-Type", "text/plain");
      H.setCORSHeaders();
      H.SetBody(bestHost->details->host);
      promethNode.numSuccessViewer++;
      incrementAccX(bestHost->name, NVIEWERS, promethStreams, promethStreamRecords);
      incrementAccX(geohash(lat, lon), NVIEWERS, promethGeoIP, promethGeoIPRecords);
      incrementAccX(geohash(lat, lon), TOTDIST, promethGeoIP, promethGeoIPRecords,
                    geoDist(lat, lon, bestHost->details->servLati, bestHost->details->servLongi));
    }
    if (proto != "" && bestHost && bestScore){
      H.SetHeader("Content-Type", "text/plain");
      H.Clean();
      H.setCORSHeaders();
      H.SetHeader("Location", bestHost->details->getUrl(streamName, proto) + vars);
      H.SetBody(H.GetHeader("Location"));
      H.SendResponse("307", "Redirecting", conn);
      H.Clean();
    }else{
      H.SendResponse("200", "OK", conn);
      H.Clean();
    }
  }// if HTTP request received

  /**
   * add viewer to stream on server
   */
  void addViewer(std::string stream, const std::string addViewer){
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->name == addViewer){
        (*it)->details->addViewer(stream, true);
        break;
      }
    }
  }

  int saveTimeInterval = 5; // time to save after config change in minutes
  /**
   * \returns the config as a string
   */
  std::string configToString(){// TODO if value doesn't exist
    JSON::Value j;
    j["fallback"] = fallback;
    j[CONFCPU] = weight_cpu;
    j[CONFRAM] = weight_ram;
    j[CONFBW] = weight_bw;
    j[CONFWG] = weight_geo;
    j[CONFWB] = weight_bonus;
    j[CONFPASS] = passHash;
    j[CONFSPASS] = passphrase;
    j[CONFWL] = whitelist;
    j[CONFBEAR] = bearerTokens;
    j[CONFUSER] = userAuth;

    // balancing
    j[CONMINSBY] = minstandby;
    j[CONFMAXSBY] = maxstandby;
    j[CONFCAPTRIGCPUDEC] = cappacityTriggerCPUDec;
    j[CONFCAPTRIGBWDEC] = cappacitytriggerBWDec;
    j[CONFCAPTRIGRAMDEC] = cappacityTriggerRAMDec;
    j[CONFCAPTRIGCPU] = cappacityTriggerCPU;
    j[CONFCAPTRIGBW] = cappacityTriggerBW;
    j[CONFCAPTRIGRAM] = cappacityTriggerRAM;
    j[CONFHCAPTRIGCPU] = highCappacityTriggerCPU;
    j[CONFHCAPTRIGBW] = highCappacityTriggerBW;
    j[CONFHCAPTRIGRAM] = highCappacityTriggerRAM;
    j[CONFLCAPTRIGCPU] = lowCappacityTriggerCPU;
    j[CONFLCAPTRIGBW] = lowCappacityTriggerBW;
    j[CONFLCAPTRIGRAM] = lowCappacityTriggerRAM;
    j[CONFBI] = balancingInterval;
    j[SERVMONLIMKEY] = serverMonitorLimit;
    // serverlist
    std::set<std::string> servers;
    for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
      if ((*it)->thread != 0){servers.insert((*it)->name);}
    }
    j[CONFSERV] = servers;
    // loadbalancer list
    std::set<std::string> lb;
    lb.insert(myName);
    for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); it++){
      lb.insert((*it)->getName());
    }
    j[CONFLB] = lb;
    return j.asString();
  }
  /**
   * save config vars to config file
   * \param resend allows for command to be sent to other load balacners
   */
  void saveFile(bool resend){
    // send command to other load balancers
    if (resend){
      JSON::Value j;
      j["save"] = true;
      for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); it++){
        (*it)->send(j.asString());
      }
    }
    tthread::lock_guard<tthread::mutex> guard(fileMutex);
    std::ofstream file(fileLoc.c_str());

    if (file.is_open()){

      file << configToString().c_str();
      file.flush();
      file.close();
      time(&prevSaveTime);
      INFO_MSG("config saved");
    }else{
      INFO_MSG("save failed");
    }
  }
  /**
   * timer to check if enough time passed since last config change to save to the config file
   */
  void saveTimeCheck(void *){
    if (prevconfigChange < prevSaveTime){
      WARN_MSG("manual save1")
      return;
    }
    time(&now);
    double timeDiff = difftime(now, prevconfigChange);
    while (timeDiff < 60 * saveTimeInterval){
      // check for manual save
      if (prevconfigChange < prevSaveTime){return;}
      // sleep thread for 600 - timeDiff
      Util::wait(60 * saveTimeInterval - timeDiff);
      time(&now);
      timeDiff = difftime(now, prevconfigChange);
    }
    saveFile();
    saveTimer = 0;
  }
  /**
   * loads the config from a string
   */
  void configFromString(std::string s){
    // change config vars
    JSON::Value j = JSON::fromString(s);
    if (j.isMember("fallback")) fallback = j["fallback"].asString();
    if (j.isMember(CONFCPU)) weight_cpu = j[CONFCPU].asInt();
    if (j.isMember(CONFRAM)) weight_ram = j[CONFRAM].asInt();
    if (j.isMember(CONFBW)) weight_bw = j[CONFBW].asInt();
    if (j.isMember(CONFWG)) weight_geo = j[CONFWG].asInt();
    if (j.isMember(CONFWB)) weight_bonus = j[CONFWB].asInt();
    if (j.isMember(CONFPASS)) passHash = j[CONFPASS].asString();
    if (j.isMember(CONFSPASS)) passphrase = j[CONFSPASS].asStringRef();

    if (j.isMember(CONFBEAR)){
      JSON::Value a = j[CONFBEAR];
      bearerTokens = a.asSet<std::string>();
    }

    // balancing
    if (j.isMember(CONMINSBY)) minstandby = j[CONMINSBY].asInt();
    if (j.isMember(CONFMAXSBY)) maxstandby = j[CONFMAXSBY].asInt();
    if (j.isMember(CONFCAPTRIGCPUDEC))
      cappacityTriggerCPUDec = j[CONFCAPTRIGCPUDEC].asDouble(); // percentage om cpu te verminderen
    if (j.isMember(CONFCAPTRIGBWDEC))
      cappacitytriggerBWDec = j[CONFCAPTRIGBWDEC].asDouble(); // percentage om bandwidth te verminderen
    if (j.isMember(CONFCAPTRIGRAMDEC))
      cappacityTriggerRAMDec = j[CONFCAPTRIGRAMDEC].asDouble(); // percentage om ram te verminderen
    if (j.isMember(CONFCAPTRIGCPU))
      cappacityTriggerCPU = j[CONFCAPTRIGCPU].asDouble(); // max capacity trigger for balancing cpu
    if (j.isMember(CONFCAPTRIGBW))
      cappacityTriggerBW = j[CONFCAPTRIGBW].asDouble(); // max capacity trigger for balancing bandwidth
    if (j.isMember(CONFCAPTRIGRAM))
      cappacityTriggerRAM = j[CONFCAPTRIGRAM].asDouble(); // max capacity trigger for balancing ram
    if (j.isMember(CONFHCAPTRIGCPU))
      highCappacityTriggerCPU =
          j[CONFHCAPTRIGCPU].asDouble(); // capacity at which considerd almost full. should be less than cappacityTriggerCPU
    if (j.isMember(CONFHCAPTRIGBW))
      highCappacityTriggerBW =
          j[CONFHCAPTRIGBW].asDouble(); // capacity at which considerd almost full. should be less than cappacityTriggerBW
    if (j.isMember(CONFHCAPTRIGRAM))
      highCappacityTriggerRAM =
          j[CONFHCAPTRIGRAM].asDouble(); // capacity at which considerd almost full. should be less than cappacityTriggerRAM
    if (j.isMember(CONFLCAPTRIGCPU))
      lowCappacityTriggerCPU =
          j[CONFLCAPTRIGCPU].asDouble(); // capacity at which considerd almost full. should be less than cappacityTriggerCPU
    if (j.isMember(CONFLCAPTRIGBW))
      lowCappacityTriggerBW =
          j[CONFLCAPTRIGBW].asDouble(); // capacity at which considerd almost full. should be less than cappacityTriggerBW
    if (j.isMember(CONFLCAPTRIGRAM))
      lowCappacityTriggerRAM =
          j[CONFLCAPTRIGRAM].asDouble(); // capacity at which considerd almost full. should be less than cappacityTriggerRAM
    if (j.isMember(CONFBI)) balancingInterval = j[CONFBI].asInt();
    if (j.isMember(SERVMONLIMKEY)) serverMonitorLimit = j[SERVMONLIMKEY].asInt();

    if (highCappacityTriggerCPU > cappacityTriggerCPU)
      highCappacityTriggerCPU = cappacityTriggerCPU;
    if (highCappacityTriggerBW > cappacityTriggerBW) highCappacityTriggerBW = cappacityTriggerBW;
    if (highCappacityTriggerRAM > cappacityTriggerRAM)
      highCappacityTriggerRAM = cappacityTriggerRAM;
    if (lowCappacityTriggerCPU > cappacityTriggerCPU)
      lowCappacityTriggerCPU = highCappacityTriggerCPU;
    if (lowCappacityTriggerBW > cappacityTriggerBW) lowCappacityTriggerBW = highCappacityTriggerBW;
    if (lowCappacityTriggerRAM > cappacityTriggerRAM)
      lowCappacityTriggerRAM = highCappacityTriggerRAM;

    // load whitelist
    if (j.isMember(CONFWL)) whitelist = j[CONFWL].asSet<std::string>();
    // add localhost to whitelist
    if (!cfg->getBool("localmode")){
      Loadbalancer::whitelist.insert("localhost");
      Loadbalancer::whitelist.insert("::1/128");
      Loadbalancer::whitelist.insert("127.0.0.1/24");
    }
    if (j.isMember(CONFUSER))
      userAuth = j[CONFUSER].asPairMap<std::string, std::string, std::string>();

    // add new servers
    if (j.isMember(CONFSERV)){
      for (int i = 0; i < j[CONFSERV].size(); i++){
        std::string ret;
        addServer(ret, j[CONFSERV][i], true);
      }
    }

    // add new load balancers
    if (j.isMember(CONFLB)){
      jsonForEach(j[CONFLB], i){
        if ((*i).asString() == myName) continue;
        for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); it++){
          if ((*it)->getName() != (*i).asString()){
            new tthread::thread(addLB, (void *)&((*i).asStringRef()));
          }
        }
      }
    }
  }
  /**
   * load config vars from config file
   * \param resend allows for command to be sent sent to other load balancers
   */
  void loadFile(){
    tthread::lock_guard<tthread::mutex> guard(fileMutex);
    std::ifstream file(fileLoc.c_str());
    std::string data;
    std::string line;
    // read file
    if (file.is_open()){
      while (getline(file, line)){data.append(line);}

      // remove servers
      for (std::set<hostEntry *>::iterator it = hosts.begin(); it != hosts.end(); it++){
        cleanupHost(**it);
      }
      // remove loadbalancers
      std::set<LoadBalancer *>::iterator it = loadBalancers.begin();
      while (loadBalancers.size()){
        (*it)->send("close");
        (*it)->Go_Down = true;
        loadBalancers.erase(it);
        it = loadBalancers.begin();
      }
      configFromString(data);

      file.close();
      INFO_MSG("loaded config");
      checkServerMonitors();

      // send new config to other load balancers
      JSON::Value z;
      z[SCONFKEY] = configToString();
      for (std::set<LoadBalancer *>::iterator it = loadBalancers.begin(); it != loadBalancers.end(); it++){
        (*it)->send(z.asString());
      }

    }else
      WARN_MSG("cant load")
  }
}// namespace Loadbalancer