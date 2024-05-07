#include <ESP8266WiFiMulti.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <LittleFS.h>

ESP8266WiFiMulti wifiMulti;
WiFiUDP Udp;

JsonDocument Config;
IPAddress DNSsrv;
class cacheEntry{
    public:
    IPAddress ip;
    uint16_t port;
    unsigned long requestTime;
    uint8_t dnsBuffer[512];
    bool expired;
    cacheEntry(IPAddress ip, uint16_t port, uint8_t *dnsBuffer){
        this->ip = ip;
        this->port = port;
        this->requestTime = millis();
        memcpy(this->dnsBuffer, dnsBuffer, 512);
        expired = false;
    }
    cacheEntry(){
        ip = IPAddress(0, 0, 0, 0);
        port = 0;
        requestTime = 0;
        memset(dnsBuffer, 0, 512);
        expired = true;
    }
};
class cacheList{
    public:
    cacheEntry *entries;
    int cacheSize;
    long cacheTimeOut;
    cacheList(int cacheSize, long cacheTimeOut){
        this->entries = new cacheEntry[cacheSize];
        this->cacheSize = cacheSize;
        this->cacheTimeOut = cacheTimeOut;
    }
    bool add(IPAddress ip, uint16_t port, uint8_t *dnsBuffer, bool clear=true){
        if(clear){RefreshCache();}
        for (int i = 0; i < cacheSize; i++){
            if (entries[i].expired){
                entries[i] = cacheEntry(ip, port, dnsBuffer);
                return true;
            }
        }
        return false;
    }
    void RefreshCache(){
        for (int i = 0; i < cacheSize; i++){
            if (entries[i].requestTime + cacheTimeOut < millis()){
                entries[i].expired = true;
            }
        }
    }
    int getIndexOfEntry(byte id1, byte id2){
        for (int i = 0; i < cacheSize; i++){
            if (entries[i].dnsBuffer[0]==id1 && entries[i].dnsBuffer[1]==id2){
                return i;
            }
        }
        return -1;
    }
};
// Total RAM: 4KB = 4096 bytes; Total Cache that can be allocated = 4096/size of 1 dns packet(512B) = 8 - 1(for other variables like network config and all)
cacheList cache(7, 1000);
long ledDelay = 0, ledNow = 0;
bool pauseDns = false;

void createDnsPacket(const uint8_t *dnsBuffer, size_t bufferSize, const IPAddress &ipAddress, uint8_t *responseBuffer, size_t &responseSize){
    // Copy the transaction ID from the request to the response
    responseBuffer[0] = dnsBuffer[0];
    responseBuffer[1] = dnsBuffer[1];

    // Flags - Standard query response, no error
    responseBuffer[2] = 0x81;
    responseBuffer[3] = 0x80;

    // Questions and Answers Counts
    responseBuffer[4] = dnsBuffer[4];
    responseBuffer[5] = dnsBuffer[5];
    responseBuffer[6] = 0x00;
    responseBuffer[7] = 0x01; // One answer

    // Authority and Additional RRs
    responseBuffer[8] = 0x00;
    responseBuffer[9] = 0x00;
    responseBuffer[10] = 0x00;
    responseBuffer[11] = 0x00;

    // Copy the rest of the request into the response
    for (size_t i = 12; i < bufferSize; ++i){
        responseBuffer[i] = dnsBuffer[i];
    }

    // Add the answer section
    size_t answerIndex = bufferSize;
    responseBuffer[answerIndex++] = 0xC0; // Name compression
    responseBuffer[answerIndex++] = 0x0C;

    responseBuffer[answerIndex++] = 0x00; // Type A
    responseBuffer[answerIndex++] = 0x01;

    responseBuffer[answerIndex++] = 0x00; // Class IN
    responseBuffer[answerIndex++] = 0x01;

    responseBuffer[answerIndex++] = 0x00; // TTL
    responseBuffer[answerIndex++] = 0x00;
    responseBuffer[answerIndex++] = 0x00;
    responseBuffer[answerIndex++] = 0x64; // 100 seconds

    responseBuffer[answerIndex++] = 0x00; // Data length
    responseBuffer[answerIndex++] = 0x04; // 4 bytes for IPv4 address

    // Add the IP address to the response
    responseBuffer[answerIndex++] = ipAddress[0];
    responseBuffer[answerIndex++] = ipAddress[1];
    responseBuffer[answerIndex++] = ipAddress[2];
    responseBuffer[answerIndex++] = ipAddress[3];

    // Update the response size
    responseSize = answerIndex;
}

void createReverseDnsPacket(const uint8_t *dnsBuffer, size_t bufferSize, const char *resolvedDomain, uint8_t *responseBuffer, size_t &responseSize){
    // Build DNS header for response
    memcpy(responseBuffer, dnsBuffer, 2); // Copy the transaction ID from the query to the response
    responseSize = 2;
    responseBuffer[responseSize++] = 0x81; // Response flag (QR = 1, Opcode = 0, AA = 1)
    responseBuffer[responseSize++] = 0x80; // Recursion desired flag (RD = 1)
    responseBuffer[responseSize++] = 0x00; // Questions count (1 questions)
    responseBuffer[responseSize++] = 0x01;
    responseBuffer[responseSize++] = 0x00; // Answer RRs count (1 answers)
    responseBuffer[responseSize++] = 0x01;
    responseBuffer[responseSize++] = 0x00; // Authority RRs count (0 authority resource record)
    responseBuffer[responseSize++] = 0x00;
    responseBuffer[responseSize++] = 0x00; // Additional RRs count (0 additional resource records)
    responseBuffer[responseSize++] = 0x00; 

    // Question Section
    for (size_t i = 12; i < bufferSize-4; i++){responseBuffer[responseSize++] = dnsBuffer[i];}// Copy the query QNAME to the response
    responseBuffer[responseSize++] = 0x00; // Pointer flag
    responseBuffer[responseSize++] = 0x0c;
    responseBuffer[responseSize++] = 0x00; // IN class
    responseBuffer[responseSize++] = 0x01; 

    // Answer Section
    responseBuffer[responseSize++] = 0xc0; // Name compression flag
    responseBuffer[responseSize++] = 0x0c;
    responseBuffer[responseSize++] = 0x00; // Type PTR
    responseBuffer[responseSize++] = 0x0c;
    responseBuffer[responseSize++] = 0x00; // IN class
    responseBuffer[responseSize++] = 0x01;
    responseBuffer[responseSize++] = 0x00; // TTL
    responseBuffer[responseSize++] = 0x00;
    responseBuffer[responseSize++] = 0x52;
    responseBuffer[responseSize++] = 0x81;
    int domainLength = strlen(resolvedDomain); // Length of the PTR data (domain name)
    responseBuffer[responseSize++] = 0x00;
    responseBuffer[responseSize++] = domainLength+2;
    // Format for adding the domain: <noOfCharsBefore'.'>XXXXXX<noOfCharsAfter'.'>
    int IndexToAddtoo = responseSize++;
    int noOfChars = 0;
    for (size_t i = 0; i < domainLength; i++){
        if (resolvedDomain[i] == '.'){
            responseBuffer[IndexToAddtoo] = noOfChars;
            noOfChars = 0;
            IndexToAddtoo = responseSize++;
        }
        else{
            responseBuffer[responseSize++] = resolvedDomain[i];
            noOfChars++;
        }
    }
    responseBuffer[IndexToAddtoo] = noOfChars;
    responseBuffer[responseSize++] = 0x00;
}

String getIPfromRDR(String domainName){
    String bufferIP = "", finalIP = "";
    int dtcntr = 0;
    for (int z = 0; z < domainName.length(); z++){
        char curChar = domainName.charAt(z);
        if (curChar == '.'){
            finalIP = bufferIP + ((dtcntr > 0) ? ("." + finalIP) : finalIP);
            bufferIP = "";
            dtcntr++;
        }
        else{
            bufferIP += curChar;
        }
        if (dtcntr >= 4){
            break;
        }
    }
    return finalIP;
}

String getDomainNameFromBuffer(byte packetBuffer[], int packetSize){
    String domainName = "";
    int pos = 12;
    while (pos < packetSize){
        int len = packetBuffer[pos];
        if (len == 0){
            break;
        }
        pos++;
        for (int i = 0; i < len; i++){
            domainName += (char)packetBuffer[pos + i];
        }
        if (packetBuffer[pos] != 0){
            domainName += ".";
        }
        pos += len;
    }
    if (domainName.endsWith(".")){
        domainName.remove(domainName.length() - 1);
    }
    return domainName;
}

void sendPacket(IPAddress sendIp, uint16_t port, const uint8_t *buffer, size_t size, bool blinkDISABLED = false){
    if (!blinkDISABLED){
        digitalWrite(LED_BUILTIN, HIGH);
    }
    Udp.beginPacket(sendIp, port);
    Udp.write(buffer, size);
    Udp.endPacket();
    if (!blinkDISABLED){
        digitalWrite(LED_BUILTIN, LOW);
    }
}

void toggleLED(){
    if(ledNow<=millis() && ledDelay !=0){
        digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
        ledNow += ledDelay;
    }
}

int countNoOfChars(String str, char ch){
    int cntr = 0;
    for (size_t i = 0; i < str.length(); i++){
        if(str.charAt(i)==ch){cntr++;}
    }
    return cntr;
}

void HandleCommand(String Command, bool execute = false){
    if(Command.indexOf(",")> -1 && !execute){
        String CurrentCommand = "";
        for (int i = 0; i<Command.length(); i++){
            if(Command.charAt(i) == ',' && CurrentCommand.charAt(CurrentCommand.length()-1)!='\\'){
                HandleCommand(CurrentCommand, true);
                CurrentCommand = "";
            }
            else{
                CurrentCommand += Command.charAt(i);
            }
        }
        if(CurrentCommand.length()>0){
            HandleCommand(CurrentCommand);
            CurrentCommand = "";
        }
        return;
    }
    Command.replace("\\,", ",");
    String lowercaseCommand = Command; lowercaseCommand.toLowerCase();
    if(lowercaseCommand.indexOf("help")> -1){
        Serial.println("\n\nAvailable commands(Use ',' to run multiple commands at once): ");
        Serial.println("Use \\, to use ',' as a character");
        Serial.println("show wifi\n=>Shows all of the added WiFi networks"); //DONE
        Serial.println("\nwifi remove /id:<ID>:id\\\n=>removes the specified WiFi network(Use WiFi Show to get the ID of the network)"); //DONE
        Serial.println("\nwifi add /s:<SSID>:s\\ /p:<Password>:p\\\n=>Adds the given WiFi network"); //DONE
        Serial.println("\nnode ap /s:<SSID>:s\\ /p:<Password>:p\\\n=>Sets Node MCU's AP"); 
        Serial.println("\nmap add /d:<DOMAIN>:d\\ /ip:<IP>:ip\\\n=>Maps the domain to the specified Domain(Use $gateway$ and $ip$ to refrer to the gateway's IP and Node MCU IP respectively)"); //DONE
        Serial.println("\nmap remove /d:<DOMAIN>:d\\\n=>Removes the mapped domain"); //DONE
        Serial.println("\nshow map\n=>Lists all mapped domains"); //DONE
        Serial.println("\nshow cache\n=>Prints the currently cached/pending DNS Resolve requests"); //DONE
        Serial.println("\nshow config\n=>Prints the complete configuration"); //DONE
        Serial.println("\nsave config\n=>Saves the configuration(use reboot to apply this saved configuration`)"); //DONE
        Serial.println("\nreboot\n=>restarts the NodeMCU"); //DONE
        Serial.println("\nhelp\t=>Displays this message"); //DONE
    }
    else if(lowercaseCommand.indexOf("show wifi")>-1){
        Serial.println("\n\nAdded WiFi Networks: ");
        for (int i = 0; i < Config["networks"].size(); i++){
            Serial.println("ID: " + String(i) + " | Name: " + Config["networks"][i]["name"].as<String>() + " | Password: " + Config["networks"][i]["pass"].as<String>() + " | Self-AP: " + String(Config["networks"][i]["self-AP"].as<String>()));
        }
    }
    else if (lowercaseCommand.indexOf("wifi add") > -1){
        if(lowercaseCommand.indexOf("/s:")>-1 && lowercaseCommand.indexOf(":s\\")>-1){
            String SSID = Command.substring(lowercaseCommand.indexOf("/s:")+3, lowercaseCommand.indexOf(":s\\"));
            String SSIDpass = (lowercaseCommand.indexOf("/p:")+3==lowercaseCommand.indexOf(":p\\") || lowercaseCommand.indexOf("/p:")==-1) ? "" : Command.substring(lowercaseCommand.indexOf("/p:")+3, lowercaseCommand.indexOf(":p\\"));
            Serial.print("SSID: ");
            Serial.print(SSID);
            Serial.print(" | Password: ");
            Serial.println(SSIDpass==""? "(Open)":SSIDpass);
            JsonDocument currentNetworkToAdd;
            currentNetworkToAdd["name"] = SSID;
            currentNetworkToAdd["pass"] = SSIDpass;
            currentNetworkToAdd["self-AP"] = false;
            Config["networks"].add(currentNetworkToAdd);
            Serial.println("Network Added Successfully(Use command 'save config' and then restart node mcu for the changes to take effect)");
        }
        else{
            Serial.println("Invalid Command format, use 'help' for more info");
        }
    }
    else if(lowercaseCommand.indexOf("wifi remove")>-1){
        int ID = -1;
        if (lowercaseCommand.indexOf("/id:")>-1 && lowercaseCommand.indexOf(":id\\")>-1){
            ID = Command.substring(lowercaseCommand.indexOf("/id:")+4, lowercaseCommand.indexOf(":id\\")).toInt();
        }
        else{
            Command.replace("wifi remove", "");
            Command.trim();
            ID = Command.toInt();
        }
        if(ID<Config["networks"].size() && ID>=0){
            if(Config["networks"][ID]["self-AP"]){
                Serial.println("\nCannot remove Self-AP network");
            }
            else{
                Serial.printf("\nNetwork(ID: %d | Name: %s | Password: %s) Removed Successfully\n", ID, Config["networks"][ID]["name"].as<String>().c_str(), Config["networks"][ID]["pass"].as<String>());
                Config["networks"].remove(ID);
            }
        }
        else{
            Serial.println("\nInvalid ID");
        }
    }
    else if (lowercaseCommand.indexOf("map add")>-1){
        String domain, ip;
        if(lowercaseCommand.indexOf("/d:")>-1 && lowercaseCommand.indexOf(":d\\")>-1 && lowercaseCommand.indexOf("/ip:")>-1 && lowercaseCommand.indexOf(":ip\\")>-1){
            domain = Command.substring(lowercaseCommand.indexOf("/d:")+3, lowercaseCommand.indexOf(":d\\")), ip = Command.substring(lowercaseCommand.indexOf("/ip:")+4, lowercaseCommand.indexOf(":ip\\"));
        }
        else if (countNoOfChars(Command, ' ')==3) {
            String Rdomain = Command.substring(lowercaseCommand.indexOf("map add")+strlen("map add")), domain="";
            Rdomain.trim();
            String ip = Rdomain;
            for(int i=0; i<Rdomain.length(); i++){
                if(Rdomain.charAt(i)==' '){break;}
                domain+=Rdomain.charAt(i);
            }
            ip.replace(domain, ""); ip.trim();
        }
        else{
            Serial.printf("Invalid Command(%s) format, use 'help' for more info\n", Command);
            return;
        }
        Serial.print("Domain: ");
        Serial.print(domain);
        Serial.print(" | IP: ");
        Serial.println(ip);
        Config["maps"][domain] = ip;
        Serial.println("Mapping Added Successfully(Use command 'save config' and then restart node mcu for the changes to take effect)");
    }
    else if (lowercaseCommand.indexOf("map remove")>-1){
        String domain;
        if(lowercaseCommand.indexOf("/d:")>-1 && lowercaseCommand.indexOf(":d\\")>-1){
            domain = Command.substring(lowercaseCommand.indexOf("/d:")+3, lowercaseCommand.indexOf(":d\\")); domain.trim();
        }
        else if (countNoOfChars(Command, ' ')==3) {
            domain = Command.substring(lowercaseCommand.indexOf("map remove")+strlen("map remove"));
            domain.trim();
        }
        else{
            Serial.printf("Invalid Command(%s) format, use 'help' for more info\n", Command);
        }
        if(Config["maps"].containsKey(domain)==false){
            Serial.println("INVALID DOMAIN, No Maps found");
            Serial.println("Use 'show maps' to see the mapped domains");
        }
        else{
            Serial.print("Removing Domain: ");
            Serial.println(domain);
            Config["maps"].remove(domain);
        }
    }
    else if(lowercaseCommand.indexOf("show map")>-1){
        Serial.println("\n\nMapped domains and their IP address: ");
        serializeJsonPretty(Config["maps"], Serial);
        Serial.println();
    }
    else if(lowercaseCommand.indexOf("show cache")>-1){
        Serial.println("\n\nCached/Pending DNS Resolve Requests: ");
        Serial.print("Current Time(ms): ");
        Serial.println(millis());
        for(int i=0; i<7; i++){
            Serial.printf("Index: %d | RequestFrom: %s:%d | RequestTime: %d | Expired: %s\n", i, cache.entries[i].ip.toString().c_str(), cache.entries[i].port, cache.entries[i].requestTime, cache.entries[i].expired ? "true":"false");
        }
    }
    else if(lowercaseCommand.indexOf("show config")>-1){
        serializeJsonPretty(Config, Serial);
        Serial.println();
    }
    else if(lowercaseCommand.indexOf("save config")>-1){
        File configFile = LittleFS.open("/config.json", "w");
        serializeJson(Config, configFile);
        configFile.close();
        Serial.println("Configuration Saved Successfully");
    }
    else if(lowercaseCommand.indexOf("reboot")>-1){
        Serial.println("Restarting NodeMCU");
        ESP.restart();
    }
    else{
        Serial.printf("Invalid command: '%s', Use help to see available commands\n", Command);
    }
}

void setup(){
    Serial.begin(74880);
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, HIGH); // turns LED Off
    Serial.println("\nProgram Started"); //DEBUG 1
    Serial.println("Performing inititialization"); //DEBUG 1
    if (!LittleFS.begin()) {
        Serial.println("LittleFS mount failed"); //DEBUG 1
        Serial.println("Running off of Default Configuration"); //DEBUG 2
        deserializeJson(Config, "{\"networks\": [{ \"name\": \"NodeMCU DNS Server\", \"pass\": \"nodeMCU1\", \"self-AP\": true }],\"Extrenal-DNS\": \"8.8.8.8\",\"wifi-multi-trials\": 3,\"maps\":{\"gateway.local\": \"$gateway$\",\"node.local\": \"$self$\"},\"NameMAC_bindings\": {}}");
    }
    else{
        if(LittleFS.exists("/config.json")){
            File configFile = LittleFS.open("/config.json", "r");
            DeserializationError err = deserializeJson(Config, configFile);
            configFile.close();
            Serial.println("Previous configuration loaded successfully");
        }
        else{
            deserializeJson(Config, "{\"networks\": [{ \"name\": \"NodeMCU DNS Server\", \"pass\": \"nodeMCU1\", \"self-AP\": true }],\"Extrenal-DNS\": \"8.8.8.8\",\"wifi-multi-trials\": 3,\"maps\":{\"gateway.local\": \"$gateway$\",\"node.local\": \"$self$\"},\"NameMAC_bindings\": {}}");
            File configFile = LittleFS.open("/config.json", "w");
            serializeJson(Config, configFile);
            configFile.close();
            Serial.println("Default Configuration saved Successfully");
        }
    }
    DNSsrv.fromString(Config["Extrenal-DNS"].as<String>());
    Serial.print("Final Configuration for this session: ");
    serializeJsonPretty(Config, Serial);
    Serial.println();

    bool NetworksAdded = false;
    JsonDocument SelfAP;
    for(JsonVariant cur : Config["networks"].as<JsonArray>()){
        if(!cur["self-AP"]){
            NetworksAdded = true;
            wifiMulti.addAP(cur["name"].as<const char*>(), cur["pass"].as<const char*>());
        }
        else{
            SelfAP = cur;
        }
    }
    if (NetworksAdded){
        int currentTrial = 1;
        while (wifiMulti.run() != WL_CONNECTED && currentTrial <= Config["wifi-multi-trials"]){
            Serial.printf("Trying %d times out of %d\n", currentTrial, Config["wifi-multi-trials"].as<int>());
            currentTrial++;
        }
        if(currentTrial > Config["wifi-multi-trials"]){
            NetworksAdded = false;
            Serial.println("Network cannot be connected");
        }
    }
    if(!NetworksAdded){
        Serial.print("Connection to a host AP failed, Use Serial monitor to configure your network settings. For more help use: help");
        // Serial.print("Connection to a host AP failed, connect to NodeMCU's AP or Use Serial monitor to configure your network settings\nSSID: ");
        // Serial.print(SelfAP["name"].as<const char *>());
        // Serial.print(" | Password: ");
        // Serial.println(SelfAP["pass"].as<const char *>());

        // WiFi.mode(WIFI_AP_STA);
        // WiFi.softAPConfig(IPAddress(192, 168, 1, 1), IPAddress(192, 168, 1, 1), IPAddress(255, 255, 255, 0));
        // WiFi.softAP(SelfAP["name"].as<const char *>(), SelfAP["pass"].as<const char *>());
        // use the serial monitor or the AP to configure network settings and when connected successfully resume the script
        bool paused = true;
        ledDelay = 500;
        while (paused){
            toggleLED();
            if (Serial.available()>0){
                String cmd = Serial.readString();cmd.trim();cmd.replace("\n", "");
                HandleCommand(cmd);
            }
        }
    }

    Serial.println("Connected to: " + WiFi.SSID() + " | IP: " + WiFi.localIP().toString()); //DEBUG 1
    Udp.begin(53);
    Serial.printf("Now listening at IP %s, UDP port %d\n", WiFi.localIP().toString().c_str(), 53); //DEBUG 1
    digitalWrite(LED_BUILTIN, LOW); // turns on led
}

void loop(){
    int packetSize = Udp.parsePacket();
    if (packetSize && !pauseDns){
        Serial.printf("\n\nReceived %d bytes from %s, port %d\n", packetSize, Udp.remoteIP().toString().c_str(), Udp.remotePort()); //DEBUG 2
        byte packetBuffer[packetSize];
        Udp.read(packetBuffer, packetSize);
        if(Udp.remoteIP()==DNSsrv){
            Serial.println("got packet from DNS Server"); //DEBUG 3
            int idOfEnt = cache.getIndexOfEntry(packetBuffer[0], packetBuffer[1]);
            if(idOfEnt>-1){
                cacheEntry curEnt = cache.entries[idOfEnt];
                sendPacket(curEnt.ip, curEnt.port, packetBuffer, packetSize);
                Serial.println("Transaction ID found in cache AND Packet forwaded to: "+curEnt.ip.toString()+":"+String(curEnt.port)); //DEBUG 3
                cache.entries[idOfEnt].expired = true;
            }
            else{
                Serial.println("Transaction ID not found in cache"); //DEBUG 2
            }
        }
        else if (packetBuffer[2] == 0x01 && packetBuffer[3] == 0x00){
            Serial.println("DNS query packet from a user received"); //DEBUG 3            
            String domainName = getDomainNameFromBuffer(packetBuffer, packetSize);
            Serial.println("Domain Name: " + domainName); //DEBUG 2
            if (domainName.indexOf("in-addr.arpa") > -1)
            {
                Serial.println("Reverse DNS lookup for " + domainName); //DEBUG 2
                String ipToresolve = getIPfromRDR(domainName);
                String resolvedDomain = "";
                for (JsonPair pair : Config["maps"].as<JsonObject>()){
                    String IPFromMaps = pair.value();
                    IPFromMaps.replace("$gateway$", WiFi.gatewayIP().toString());
                    IPFromMaps.replace("$self$", WiFi.localIP().toString());
                    if (IPFromMaps == ipToresolve){
                        resolvedDomain = pair.key().c_str();
                        break;
                    }
                }
                if (resolvedDomain!=""){
                    uint8_t dnsResponseBuffer[512];
                    size_t responseSize = 0;
                    createReverseDnsPacket(packetBuffer, packetSize, resolvedDomain.c_str(), dnsResponseBuffer, responseSize);
                    sendPacket(Udp.remoteIP(), Udp.remotePort(), dnsResponseBuffer, responseSize);
                }
                else{
                    sendPacket(DNSsrv, 53, packetBuffer, packetSize);
                    if(!cache.add(Udp.remoteIP(), Udp.remotePort(), packetBuffer)){
                        Serial.println("Cache Full Deleting Entry 0"); //DEBUG 2
                        cache.entries[0].expired = true;
                        cache.add(Udp.remoteIP(), Udp.remotePort(), packetBuffer);
                    }
                }
            }
            else if (Config["maps"].containsKey(domainName)){
                String responseIP = Config["maps"][domainName];
                if(responseIP.indexOf("$gateway$")>-1){
                    responseIP.replace("$gateway$", WiFi.gatewayIP().toString());
                }
                if(responseIP.indexOf("$self$")>-1){
                    responseIP.replace("$self$", WiFi.localIP().toString());
                }
                IPAddress ResponseIP;
                ResponseIP.fromString(responseIP);
                uint8_t dnsResponseBuffer[512];
                size_t responseSize = 0;
                createDnsPacket(packetBuffer, packetSize, ResponseIP, dnsResponseBuffer, responseSize);
                sendPacket(Udp.remoteIP(), Udp.remotePort(), dnsResponseBuffer, responseSize);
            }
            else{
                Serial.println("No entery Found"); //DEBUG 2
                Serial.println(">>>forwading DNS packet from " + Udp.remoteIP().toString() + " to 8.8.8.8"); //DEBUG 3
                sendPacket(DNSsrv, 53, packetBuffer, packetSize);
                cache.RefreshCache();
                if(!cache.add(Udp.remoteIP(), Udp.remotePort(), packetBuffer)){
                    Serial.println("Cache Full Deleting Entry 0"); //DEBUG 2
                    cache.entries[0].expired = true;
                    cache.add(Udp.remoteIP(), Udp.remotePort(), packetBuffer);
                }
            }
        }
        else{
            Serial.println("Non-DNS query packet received, ignoring."); //DEBUG 2
        }
    }
    if (Serial.available()>0){
        String cmd = Serial.readString();cmd.trim();cmd.replace("\n", "");
        HandleCommand(cmd);
    }
    
}
