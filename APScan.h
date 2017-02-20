#ifndef APScan_h
#define APScan_h

#define ApScanMaxResults 30

#include "ESP8266WiFi.h"
#include "Mac.h"
#include "MacList.h"

extern String data_getVendor(uint8_t first,uint8_t second,uint8_t third);

class APScan{
  public:
    APScan();

    int scan();
    bool process(int i);
    bool start();
    bool setAsyncIndex();
    String getResult(int i);
    String getResults();
    int getResultByAPName(String apName);
    int select(int num);
    
    String getAPName(int num);
    String getAPEncryption(int num);
    String getAPVendor(int num);
    String getAPMac(int num);
    String getAPSelected(int num);
    int getAPRSSI(int num);
    int getAPChannel(int num);

    Mac getTarget();

    int results = 0;
    int selected = -1;
    int asyncIndex = -1;
  private:
    MacList aps;
    int channels[ApScanMaxResults];
    int rssi[ApScanMaxResults];
    char names[ApScanMaxResults][33];
    char encryption[ApScanMaxResults][5];
    char vendors[ApScanMaxResults][9];

    String getEncryption(int code);
};

#endif
