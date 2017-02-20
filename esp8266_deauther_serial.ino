/*
 * Wifi and U-BLOX GPS scanner / Wifi deauther
 * Same as https://github.com/spacehuhn/esp8266_deauther
 * but using serial instead of http for commands
 * and outputing messages in NMEA+JSON format
 * 
 */
#define DEBUG false

#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <WiFiUdp.h>


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

// MOTD
#define helpMessageSize 17
String helpMessages[helpMessageSize] = {
      "Command List:",
      "  apjson [ap id]      Print Scan Result for AP xx [sendAPResult(xx)]",
      "  apscan              Start AP Scan [startAPScan]",
      "  aplist              Prints AP Scan List",
      "  clear               NameList clear",
      "  apget [ap mac/name] Search, Select and Print AP mac or name [getResultByAPName(blah)]",
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
}

void SerialPrintJSON(String msg) {
  Serial.println("{\"message\":[\""+msg+"\"]}");
}


void handleSerialClient() {

  // serial command received!
  String msg = incomingSerialData;
  String msgNumStr;
  int msgNum;
  
  msg.trim();
  
  if(msg=="*") {
    SerialPrintJSON( helpMessages[helpMessagesPos] );
    helpMessagesPos++;
    if( helpMessagesPos < helpMessageSize ) {
      // continue with async printing
      return;
    }
    helpMessagesPos = 0;

  } else if(msg=="cscan") { // startClientScan
    if(apScan.selected > -1 && !clientScan.sniffing) {
      SerialPrintJSON("CLIENT SCAN START");
      clientScan.start(10);
      attack.stop(0);
    } else {
      SerialPrintJSON("CLIENT SCAN SKIPPED");
    }
    
  } else if(msg=="apscan") { // startAPScan

    if(apScan.start()) {
      attack.stopAll();
      apScan.setAsyncIndex();
      incomingSerialData = "aplist";
      return;      
    }

  } else if(msg=="aplist") { // 
    if(apScan.results==0) {
      incomingSerialData = "apscan";
      return;
    }

    if(apScan.asyncIndex>=0) {
      Serial.println(apScan.getResult(apScan.asyncIndex));
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
    Serial.println(clientScan.getResults());
    
  } else if(msg=="attackinfo") { // sendAttackInfo
    Serial.println(  attack.getResults() );
    
  } else if(msg.startsWith("cselect ")) { // selectClient(x)
    msgNumStr = msg.substring(8);
    msgNum = msgNumStr.toInt();
    if(msgNum>-1) {
      SerialPrintJSON("SELECTED Client #" + msgNumStr);
      clientScan.select(msgNum);
      attack.stop(0);
    } else {
      SerialPrintJSON("INVALID Client #" + msgNumStr);
    }
    Serial.println( clientScan.getResults() ); 
    
  } else if(msg.startsWith("apjson ")) { // sendAPResults(xx)
    msgNumStr = msg.substring(7);
    msgNum = msgNumStr.toInt();
    if(msgNum>-1) {
      Serial.println( apScan.getResult(msgNum) );
    } else {
      SerialPrintJSON("ERROR INVALID AP ");
    }
    
  } else if(msg=="reset") {
    ESP.reset(); 
    
  } else if(msg=="clear") {
    nameList.clear(); 
    
  } else if(msg.startsWith("apget ")) { // getResultByAPName('blah')
    msgNumStr = msg.substring(6);
    if(msgNumStr!="") {
      int apNum = apScan.getResultByAPName(msgNumStr);
      if(apNum>-1) {
        Serial.println(apScan.getResult(apNum));
      } else {
        SerialPrintJSON("ERROR,AP Not Found:" + msgNumStr);
      }
    } else {
      SerialPrintJSON("ERROR INVALID AP ");
    }
    
  } else if(msg.startsWith("apselect ")) { // selectAP(x)
    msgNumStr = msg.substring(9);
    msgNum = msgNumStr.toInt();
    if(msgNum>-1) {
      if(apScan.select(msgNum)>-1) {
        SerialPrintJSON("SELECTED AP #" + String(msgNum) + "/" +  msgNumStr);
      } else {
        SerialPrintJSON("UNSELECTED AP #" + String(msgNum) + "/" +  msgNumStr);
      }
      attack.stopAll();
    } else {
      SerialPrintJSON("ERROR INVALID AP ");
    }
    
  } else if(msg.startsWith("cset ")) { // setClientName(x)
    msgNumStr = msg.substring(5);
    //msgNum = msgNumStr.toInt();
    if(msgNumStr!="") {
      SerialPrintJSON("Adding " + msgNumStr + " to namelist");
      nameList.add(clientScan.getClientMac(clientScan.lastSelected), msgNumStr);
    } else {
      SerialPrintJSON("ERROR INVALID Client");
    }
    
  } else if(msg.startsWith("attack ")) { // attack(x)
    msgNumStr = msg.substring(7);
    msgNum = msgNumStr.toInt();
    if(msgNum>-1) {
      if(apScan.selected > -1 || msgNum == 3){
        attack.start(msgNum);
        SerialPrintJSON("ATTACK Client #" + msgNumStr);
      } else {
        SerialPrintJSON("ERROR no AP selected");
      }
    } else {
      SerialPrintJSON("ERROR INVALID Client");
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
  // send MOTD
  incomingSerialData = "*";
  incomingSerialDataReady = true;
}


void loop() {
  bool show_hidden = false;
  byte inByte = 0;
  byte outByte = 0;

  if(clientScan.sniffing){
    if(clientScan.stop()){
      SerialPrintJSON( "CLIENT SCAN DONE" );
      Serial.println( clientScan.getResults() );
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



