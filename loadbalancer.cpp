#include "api.h"
#include "communication_defines.h"
#include "util_load.h"
#include <mist/auth.h>
#include <mist/config.h>
#include <mist/util.h>
#include <string>

int main(int argc, char **argv){
  Util::redirectLogsIfNeeded();
  Util::Config conf(argv[0]);
  Loadbalancer::cfg = &conf;
  JSON::Value opt;

  opt["arg"] = "integer";
  opt["short"] = "p";
  opt["long"] = "port";
  opt["help"] = "TCP port to listen on";
  opt["value"].append(8042u);
  conf.addOption("port", opt);

  opt["arg"] = "string";
  opt["short"] = "P";
  opt["long"] = "passphrase";
  opt["help"] = "Passphrase (prometheus option value) to use for data retrieval.";
  opt["value"][0u] = "koekjes";
  conf.addOption("passphrase", opt);

  opt["arg"] = "string";
  opt["short"] = "i";
  opt["long"] = "interface";
  opt["help"] = "Network interface to listen on";
  opt["value"][0u] = "0.0.0.0";
  conf.addOption("interface", opt);

  opt["arg"] = "string";
  opt["short"] = "u";
  opt["long"] = "username";
  opt["help"] = "Username to drop privileges to";
  opt["value"][0u] = "root";
  conf.addOption("username", opt);

  opt["arg"] = "string";
  opt["short"] = "A";
  opt["long"] = "auth";
  opt["help"] = "load balancer authentication key";
  conf.addOption("auth", opt);

  opt.null();
  opt["short"] = "L";
  opt["long"] = "nonlocal";
  opt["help"] = "remove localhost from whitelist";
  conf.addOption("localmode", opt);

  opt.null();
  opt["short"] = "c";
  opt["long"] = "config";
  opt["help"] = "load config settings from file";
  conf.addOption("load", opt);

  opt["arg"] = "string";
  opt["short"] = "H";
  opt["long"] = "host";
  opt["help"] = "Host name and port where this load balancer can be reached";
  conf.addOption("myName", opt);

  conf.parseArgs(argc, argv);

  std::string password = "default"; // set default password for load balancer communication
  Loadbalancer::passphrase = conf.getOption("passphrase").asStringRef();
  password = conf.getString("auth");
  bool load = conf.getBool("load");
  Loadbalancer::myName = conf.getString("myName");

  conf.activate();
  
  if(Loadbalancer::myName.size()){
    if (Loadbalancer::myName.find(":") == std::string::npos){
      Loadbalancer::myName.append(":" + conf.getString("port"));
    }
    

    Loadbalancer::loadBalancers = std::set<Loadbalancer::LoadBalancer *>();
    Loadbalancer::serverMonitorLimit = 1;
    // setup saving
    Loadbalancer::saveTimer = 0;
    time(&Loadbalancer::prevSaveTime);
    // api login
    srand(time(0) + getpid()); // setup random num generator
    std::string salt = Loadbalancer::generateSalt();
    Loadbalancer::userAuth.insert(std::pair<std::string, std::pair<std::string, std::string> >(
        "admin", std::pair<std::string, std::string>(Secure::sha256("default" + salt), salt)));
    Loadbalancer::bearerTokens.insert("test1233");
    // add localhost to whitelist
    if (!conf.getBool("localmode")){
      Loadbalancer::whitelist.insert("localhost");
      Loadbalancer::whitelist.insert("::1/128");
      Loadbalancer::whitelist.insert("127.0.0.1/24");
    }

    Loadbalancer::identifier = Loadbalancer::generateSalt();
    Loadbalancer::identifiers.insert(Loadbalancer::identifier);

    if (!load){
      Loadbalancer::loadFile();
    }else{
      Loadbalancer::passHash = Secure::sha256(password);
    }

    std::map<std::string, tthread::thread *> threads;

    Loadbalancer::checkServerMonitors();

    new tthread::thread(Loadbalancer::timerAddViewer, NULL);
    new tthread::thread(Loadbalancer::checkNeedRedirect, NULL);
    conf.serveThreadedSocket(Loadbalancer::handleRequest);
    if (!conf.is_active){
      WARN_MSG("Load balancer shutting down; received shutdown signal");
    }else{
      WARN_MSG("Load balancer shutting down; socket problem");
    }
    Loadbalancer::saveFile();
    conf.is_active = false;
  

    // Join all threads
    for (std::set<Loadbalancer::hostEntry *>::iterator it = Loadbalancer::hosts.begin();
        it != Loadbalancer::hosts.end(); it++){
      if (!(*it)->name[0]){continue;}
      (*it)->state = STATE_GODOWN;
    }
    for (std::set<Loadbalancer::hostEntry *>::iterator i = Loadbalancer::hosts.begin();
        i != Loadbalancer::hosts.end(); i++){
      Loadbalancer::cleanupHost(**i);
    }
    std::set<Loadbalancer::LoadBalancer *>::iterator it = Loadbalancer::loadBalancers.begin();
    while (Loadbalancer::loadBalancers.size()){
      (*it)->send("close");
      (*it)->Go_Down = true;
      Loadbalancer::loadBalancers.erase(it);
      it = Loadbalancer::loadBalancers.begin();
    }
  }else{
    conf.is_active = false;
    ERROR_MSG("the -H cammand requires an input! received: %s", conf.getString("myName").c_str());
  }
  
}
