#include <ESP8266WiFiMulti.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>

ESP8266WiFiMulti wifiMulti;
WiFiUDP Udp;

JsonDocument Maps;
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
IPAddress lastUserIP(0, 0, 0, 0);
unsigned int lastUserPort = 0;

IPAddress DNSsrv(8, 8, 8, 8);
#define BlinkForPacket 1
cacheList cache(7, 1000);

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
    if (BlinkForPacket && !blinkDISABLED){
        digitalWrite(LED_BUILTIN, HIGH);
    }
    Udp.beginPacket(sendIp, port);
    Udp.write(buffer, size);
    Udp.endPacket();
    if (!blinkDISABLED){
        digitalWrite(LED_BUILTIN, LOW);
    }
}

void setup(){
    Serial.begin(74880);
    delay(100);
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, HIGH); // turns LED Off
    Serial.println("\nProgram Started "); //DEBUG 1

    wifiMulti.addAP("SSID", "PASS");
    while (wifiMulti.run() != WL_CONNECTED){
        delay(100);
    }

    Maps["router.local"] = WiFi.gatewayIP().toString();
    Maps["node.local"] = WiFi.localIP().toString();

    Serial.println("Connected to: " + WiFi.SSID() + " | IP: " + WiFi.localIP().toString()); //DEBUG 1
    Udp.begin(53);
    Serial.printf("Now listening at IP %s, UDP port %d\n", WiFi.localIP().toString().c_str(), 53); //DEBUG 1
    digitalWrite(LED_BUILTIN, LOW); // turns on led
}

void loop(){
    int packetSize = Udp.parsePacket();
    if (packetSize){
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
            lastUserIP = Udp.remoteIP();
            lastUserPort = Udp.remotePort();
            
            String domainName = getDomainNameFromBuffer(packetBuffer, packetSize);
            Serial.println("Domain Name: " + domainName); //DEBUG 2
            if (domainName.indexOf("in-addr.arpa") > -1)
            {
                Serial.println("Reverse DNS lookup for " + domainName); //DEBUG 2
                String ipToresolve = getIPfromRDR(domainName);
                String resolvedDomain = "";
                for (JsonPair pair : Maps.as<JsonObject>()){
                    if (pair.value() == ipToresolve){
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
            else if (Maps.containsKey(domainName)){
                String responseIP = Maps[domainName];
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
}
