#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WiFiClient.h>
//#include <ESP8266mDNS.h>
#include <WiFiUdp.h>
#include <ArduinoOTA.h>
#include <ESP8266WebServer.h>
//#include <WebSocketsServer.h>

#include <Hash.h>
#include <EEPROM.h>
#include "Timer.h"
#include <tinyaes.h>
#include "Base64.h"

#define HTTPPORT  8088
#define WSPORT 81
#define CHARGERTIMESECONDON 7200
#define CHARGERTIMESECONDOFF 3600
#define CHARGERTIMESECONDTOTAL (CHARGERTIMESECONDON + CHARGERTIMESECONDOFF)

Timer timerObj;
unsigned long long chargerTimeSecond = 0;
unsigned long long chargerTimeSecond_old = 5;

const char* ssid = "UWIFI1234";    // ganti ssid ini dengan nama koneksi wifi yang tersedia
const char* password = "12345678"; // password untuk wifi.
const char* idstr = "wemos-00";    // id untuk device ini, nantinya akan dipanggil.
//MDNSResponder mdns;

ESP8266WebServer server(HTTPPORT);

//WebSocketsServer webSocket(WSPORT);

/* WEMOS D1 Mini Lite
TX	TXD	TXD
RX	RXD	RXD
A0	Analog input, max 3.3V input	A0
D0	IO	GPIO16
D1	IO, SCL	GPIO5
D2	IO, SDA	GPIO4
D3	IO, 10k Pull-up	GPIO0
D4	IO, 10k Pull-up, BUILTIN_LED	GPIO2
D5	IO, SCK	GPIO14
D6	IO, MISO	GPIO12
D7	IO, MOSI	GPIO13
D8	IO, 10k Pull-down, SS	GPIO15
G	Ground	GND
5V	5V	-
3V3	3.3V	3.3V
RST	Reset	RST
*/

// WEMOS D1
//16 => D2
//15 => D10
//14 => D5
//13 => D7
//12 => D6
//4 => D14
//5 => D15
//2 => LED

// D0	      RX	                      GPIO3
// D1	      TX	                      GPIO1
// D2	      IO	                      GPIO16
// D3 (D15)	IO, SCL	                  GPIO5
// D4 (D14)	IO, SDA	                  GPIO4
// D5 (D13)	IO, SCK	                  GPIO14
// D6 (D12)	IO, MISO	                GPIO12
// D7 (D11)	IO, MOSI	                GPIO13
// D8	      IO, Pull-up	              GPIO0
// D9	      IO, Pull-up, BUILTIN_LED	GPIO2
// D10	    IO, Pull-down,SS	        GPIO15
// A0	      Analog Input	            A0
#define CHARGER_ENABLE

uint8_t tglint[4]={13, 12, 14, 16};
uint8_t ledint[4]={2, 0, 4, 5};


#ifdef CHARGER_ENABLE
const uint8_t chargerPinIdx = 3;
bool chargerOnFlag = true;
#endif

// aeskey is used to encrypt / decrypt data
// values: 33 ~ 76
// generated every 2 hours by timerObj
const uint8_t aesKeyLen = 32;
const uint8_t aesIvLen = aesKeyLen / 2;
const uint8_t aesBufferSize = aesKeyLen * 2;
const uint8_t aesKeyMin = 33;
const uint8_t aesKeyMax = 76;

uint8_t aeskey[] = {0xe1, 0x86, 0x33, 0x15, 0x71, 0xed, 0xe5, 0x2e, 0x2f, 0x73, 0x1d, 0x82, 0x94, 0xa4, 0x83, 0x39,
                    0x18, 0xc5, 0x2d, 0x18, 0x51, 0xd1, 0xe7, 0x0f, 0x72, 0x76, 0x7a, 0x14, 0x9d, 0x00, 0x51, 0xb2};

// passkey is used to encrypt aeskey val: 0 ~ 46
uint8_t passkey[] = {20, 41, 37, 16, 18, 0, 23, 31,
                              21, 3, 11, 10, 14, 35, 42, 1,
                              28, 40, 7, 13, 5, 4, 6, 25,
                              8, 17, 2, 15, 22, 34, 12, 30};

//AES MASTER KEY
uint8_t aesMasterKey[] = {0x50, 0x5e, 0xdf, 0xc6, 0x9c, 0x2d, 0x74, 0x18, 0x4c, 0x43, 0x65, 0x85, 0xde, 0x26, 0x92, 0xcc,
                                   0x06, 0x8d, 0x8e, 0xb2, 0x9d, 0xab, 0x1e, 0x7e, 0x3c, 0x42, 0x37, 0x3f, 0x50, 0x33, 0x6e, 0x22};

uint8_t aesMasterIv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

uint8_t aesIv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

uint8_t aesStateTemp[] = {0xc3, 0x48, 0xf7, 0x9d, 0x46, 0x5e, 0x3c, 0x94, 0x9b, 0x47, 0xd0, 0x1b, 0x67, 0xe5, 0x45, 0x20,
                          0xbe, 0x21, 0xc9, 0x7f, 0xc8, 0x50, 0xc7, 0x01, 0x03, 0x4a, 0x89, 0xf2, 0x4b, 0x51, 0xd4, 0x4e,
                          0xd2, 0xc4, 0x5a, 0x5a, 0xc7, 0x5d, 0xa5, 0x73, 0x63, 0xe7, 0x5b, 0x63, 0xce, 0xfe, 0xc1, 0x35,
                          0xcc, 0xe5, 0x99, 0xc5, 0xc8, 0xbc, 0x6e, 0xb2, 0xe0, 0x0c, 0x80, 0xf0, 0x39, 0x78, 0x7e, 0xe0};

uint8_t aesOutTemp[] = {0xbe, 0xc1, 0x74, 0x19, 0x39, 0x9b, 0x88, 0xdd, 0xe9, 0x70, 0xcd, 0x76, 0xc5, 0x08, 0xcb, 0xe5,
                        0x6c, 0xd7, 0x60, 0x8c, 0x3d, 0x9f, 0xa2, 0x4a, 0x91, 0xd0, 0x6f, 0x0a, 0xb9, 0xd1, 0xf8, 0xaf,
                        0x36, 0x62, 0x87, 0xeb, 0x6c, 0x9d, 0x99, 0xf0, 0x62, 0x19, 0xbf, 0xb8, 0x59, 0x3e, 0x9b, 0x0f,
                        0xc1, 0x7d, 0xcb, 0x72, 0x35, 0x0f, 0x4c, 0x49, 0x35, 0x33, 0xe8, 0xe6, 0x04, 0x13, 0x2f, 0x0e };

String lnkStatStr = "";
String lnkStatStrBase64 = "";
String tgl = "";

bool reqKeyFlag = false;
uint8_t reqKeyTimeSecond = 0;

// byte ledCnt;
byte switchState, switchState_old;
byte ledState, ledState_old;
byte serialCnt;

int EEPROMaddr = 0;

bool connectFlag = false;

String StrToSHex(String _chstr, int _len) {
  String strOut = "";
  char buf[3];
  for(int i=0;i<_len;i++) {
    sprintf(buf, "%02X", (uint8_t)_chstr[i]);
    strOut += buf;
  }

  return strOut;
}

// Generate a random initialization vector
uint8_t getrnd() {
    uint8_t really_random = *(volatile uint8_t *)0x3FF20E44;
    return really_random;
}

void gen_iv(uint8_t  *iv) {
    for (int i = 0 ; i < aesIvLen ; i++ ) {
        iv[i]= (uint8_t) getrnd();
        // iv[i]= (uint8_t) random(aesKeyMin, aesKeyMax);
    }
}

String b64EncStr(char *_in, int _len) {
  String strout = "";
  int b64Len = Base64.encodedLength(_len);
  char b64Out[b64Len];

  Base64.encode(b64Out, _in, _len);

  strout += b64Out;
  return strout;
}

String aesEncryptIvOverlap(uint8_t *_msg, const int _msgLen, const uint8_t *_key, const uint8_t *_iv) {
  uint8_t dLen = aesBufferSize - aesIvLen;
  uint8_t msgin[aesBufferSize];
  uint8_t buf[aesBufferSize];

  memcpy(msgin, aesOutTemp, aesBufferSize);
  memcpy(msgin, _msg, _msgLen);

  AES_CBC_encrypt_buffer(buf, msgin, aesBufferSize, _key, _iv);

  for (int i = dLen; i < aesBufferSize; i++) {
    buf[i] = _iv[i - dLen];
  }

  return b64EncStr((char *)buf, sizeof(buf));
}

String aesEncryptIvTail(uint8_t *_msg, const int _msgLen, const uint8_t *_key, const uint8_t *_iv) {
  uint8_t msgin[aesBufferSize];
  uint8_t buf[aesBufferSize];
  uint8_t outLen = aesBufferSize + aesIvLen;
  uint8_t buffOut[outLen];

  memcpy(msgin, aesOutTemp, aesBufferSize);
  memcpy(msgin, _msg, _msgLen);

  AES_CBC_encrypt_buffer(buf, msgin, aesBufferSize, _key, _iv);

  for (int i = 0; i < aesBufferSize; i++) {
    buffOut[i] = buf[i];
  }

  for (int i = 0; i < aesIvLen; i++) {
    buffOut[i + aesBufferSize] = _iv[i];
  }

  return b64EncStr((char *)buffOut, sizeof(buffOut));
}

String aesEncryptIv(uint8_t *_msg, const int _msgLen, const uint8_t *_key, const uint8_t *_iv) {
  if(aesBufferSize > (_msgLen + aesIvLen)) {return aesEncryptIvOverlap(_msg, _msgLen, _key, _iv);}
  else {return aesEncryptIvTail(_msg, _msgLen, _key, _iv);}
}

String aesEncrypt(uint8_t *_msg, const int _msgLen, const uint8_t *_key, const uint8_t *_iv) {
  uint8_t msgin[aesBufferSize];
  uint8_t buf[aesBufferSize];

  memcpy(msgin, aesOutTemp, aesBufferSize);
  memcpy(msgin, _msg, _msgLen);

  AES_CBC_encrypt_buffer(buf, msgin, aesBufferSize, _key, _iv);

  return b64EncStr((char *)buf, sizeof(buf));
}

void handleKes(void){
  String strout;

  if(reqKeyFlag) {
    generateRandomKey();
  }

  reqKeyFlag = true;

  lnkStatStrBase64 = aesEncrypt(aesStateTemp, sizeof(aesStateTemp), aeskey, aesIv);
  lnkStatStr = StrToSHex(lnkStatStrBase64, lnkStatStrBase64.length());

  //strout = (enc[aeskey(32) aesIv(16)])[aesMasterIv(16)]
  gen_iv(aesMasterIv);
  for(int i=aesKeyLen; i < (aesKeyLen + aesIvLen); i++) {
    aesOutTemp[i] = aesIv[i - aesKeyLen];
  }

  strout = aesEncryptIv(aeskey, sizeof(aeskey), aesMasterKey, aesMasterIv);

  generateRandomKey();
  server.send(200, "text/plain", strout);
};

void handleLnk(void){
  // uint8_t j = 0;
  // uint8_t pinIdx = 0;
  // char pinIdxBuf[4];
  // uint8_t hexNum = 0;
  String strout = "ok";
  String mors;
  String stat;
  byte ledIn;

  if(reqKeyFlag) {
    reqKeyFlag = false;
    stat = server.arg("stat");
    mors = server.arg("mors");
    tgl = server.arg("tgl");

    // stat.trim();
    // stat.replace("+", " ");
    // stat.replace(" ", "");
    //
    // lnkStatStr.trim();
    // lnkStatStr.replace("+", " ");
    // lnkStatStr.replace(" ", "");

    if(lnkStatStr == "noinput") {strout = "forbidden";}
    else if(stat == lnkStatStr) {
      ledIn = chexToUint((uint8_t)mors[8]) << 4 | chexToUint((uint8_t)mors[9]);
      if(tgl == "and") ledState &= ledIn;
      else if(tgl == "or") ledState |= ledIn;
      else if(tgl == "xor") ledState ^= ledIn;
      else ledState = ledIn;
    }

    strout = "ledRes" + String(ledState);
  }

  lnkStatStr = "noinput";
  generateRandomKey();

  server.send(200, "text/plain", strout);
};

void handleSte(void) {
  String strout = "ok";
  String mors;
  String stat;
  byte pin = (uint8_t)mors[1] * 10 + (uint8_t)mors[0];
  byte ledIn;
  byte ledOut = 0x00;

  if(reqKeyFlag) {
    reqKeyFlag = false;
    stat = server.arg("stat");
    mors = server.arg("mors");
    tgl = server.arg("tgl");

    if(lnkStatStr == "noinput") {strout = "forbidden";}
    else if(stat == lnkStatStr) {
      ledIn = chexToUint((uint8_t)mors[8]) << 4 | chexToUint((uint8_t)mors[9]);
      if(tgl == "and") ledOut = ledState & ledIn;
      else if(tgl == "or") ledOut = ledState | ledIn;
      else if(tgl == "xor") ledOut = ledState ^ ledIn;
      else ledOut = ledState;

      strout = String(ledOut);
    }
  }

  lnkStatStr = "noinput";
  generateRandomKey();

  server.send(200, "text/plain", strout);
}

void readLedState(void) {
  ledState = EEPROM.read(EEPROMaddr);
}

void writeLedState(void) {
  EEPROM.write(EEPROMaddr, ledState);
  EEPROM.commit();
}

void generateRandomKey(void) {
  for(int i = 0; i < aesKeyLen; i++) {
    aeskey[i] = random(aesKeyMin, aesKeyMax);
  }
  gen_iv(aesIv);
  reqKeyTimeSecond = 0;
}

String getBinString(int _val) {
  String strout;
  byte temp;
  for(int i = 7; i >=0; i--) {
    temp = _val & (1 << i);
    if(temp) strout+="1";
    else strout+="0";
  }

  return strout;
}

// void webSocketEvent(uint8_t num, WStype_t type, uint8_t * payload, size_t length) {
//     int numval;
//     String str;
//     switch(type) {
//         case WStype_DISCONNECTED:
//             // Serial.printf("[%u] Disconnected!\n", num);
//             break;
//         case WStype_CONNECTED: {
//             IPAddress ip = webSocket.remoteIP(num);
//             // Serial.Printf("[%u] Connected from %d.%d.%d.%d url: %s\n", num, ip[0], ip[1], ip[2], ip[3], payload);

//             // send message to client
//             webSocket.sendTXT(num, "Connected");
//         }
//             break;
//         case WStype_TEXT:
//             // Serial.Printf("[%u] get Text: %s\n", num, payload);
//             switch (payload[0]) {
//               case '#':
//                 numval = (int)(payload[1] - 48);
//                 ledState = ledState_old ^ (1 << numval);

//                 str = "*" + getBinString(ledState);
//                 // send message to client
//                 webSocket.sendTXT(num, str);

//                 // send data to all connected clients
//                 // webSocket.broadcastTXT("message here");
//                 break;

//               case '?':
//                 str = "*" + getBinString(switchState);
//                 webSocket.sendTXT(num, str);
//                 break;
//             }

//             break;
//     }

// }

void printHtmlHome(String _wsaddr) {
  String styleStr = "<style> .button { border: none; color: white; padding: 15px 32px; text-align: center; text-decoration: none; display: inline-block; font-size: 32px; margin: 8px 16px; cursor: pointer; } .inputtxt {font-size: 32px;} .blue {background-color: #008CBA;} .green {background-color: #4CAF50;} .red {background-color: #f44336;} .black {background-color: #555555;} </style>";

  String scriptHeadStr = "<script language=\"javascript\">function switchon(a){disableButton(),ws.send(a)}function send(){var a=document.getElementById(\"txtSend\").value;ws.send(a)}function disableButton(){for(i=0;i<8;i++){var a=document.getElementById(\"btn\"+i);a.classList.remove(\"black\"),a.classList.remove(\"red\"),a.innerHTML=\"Tunggu\",a.disabled=!0}}function enableButton(){for(i=0;i<8;i++){var a=document.getElementById(\"btn\"+i);a.innerHTML=\"Tombol \"+(i+1),a.disabled=!1}}function setButton(a){var b=a.length-1;for(i=0;i<b;i++){var c=document.getElementById(\"btn\"+(b-i-1));\"0\"==a[i+1]?(c.classList.remove(\"black\"),c.classList.add(\"red\")):\"1\"==a[i+1]&&(c.classList.remove(\"red\"),c.classList.add(\"black\"))}msgState=a}function connect(){connectToIp(document.getElementById(\"ipaddress\").value)}function connectToIp(a){\"WebSocket\"in window?(ws=new WebSocket(\"ws://\"+a),ws.onopen=function(){ws.send(\"?\")},ws.onmessage=function(a){var b=a.data;document.getElementById(\"txtRecv\").value=b,\"*\"==b[0]&&(enableButton(),setButton(b))},ws.onclose=function(){alert(\"Sambungan sudah ditutup...\")}):alert(\"WebSocket TIDAK didukung oleh Browser Anda!\")}var ws,msgState=\"*22222222\";</script>";

  String scriptBodyStr = "<script language=\"javascript\">connectToIp(\"" + _wsaddr + "\");document.getElementById(\"ipaddress\").value=\"" + _wsaddr + "\";</script>";

  String bodyStr = "<input type=\"text\" name=\"ip\" class=\"inputtxt\" id=\"ipaddress\"><button type=\"button\" class=\"button green\" onclick=\"connect()\">Sambung</button><br> <input type=\"text\" name=\"txtSend\" class=\"inputtxt\" id=\"txtSend\"><button type=\"button\" class=\"button green\" onclick=\"send()\">Kirim</button><br> <button type=\"button\" class=\"button\" id=\"btn0\" onclick=\"switchon('#0')\">Tombol 1</button><button type=\"button\" class=\"button\" id=\"btn7\" onclick=\"switchon('#7')\">Tombol 8</button><br> <button type=\"button\" class=\"button\" id=\"btn1\" onclick=\"switchon('#1')\">Tombol 2</button><button type=\"button\" class=\"button\" id=\"btn6\" onclick=\"switchon('#6')\">Tombol 7</button><br> <button type=\"button\" class=\"button\" id=\"btn2\" onclick=\"switchon('#2')\">Tombol 3</button><button type=\"button\" class=\"button\" id=\"btn5\" onclick=\"switchon('#5')\">Tombol 6</button><br> <button type=\"button\" class=\"button\" id=\"btn3\" onclick=\"switchon('#3')\">Tombol 4</button><button type=\"button\" class=\"button\" id=\"btn4\" onclick=\"switchon('#4')\">Tombol 5</button><br> <input type=\"text\" name=\"txtRecv\" id=\"txtRecv\">";

  String htmlStr = "<!DOCTYPE HTML><html><head>" + styleStr + scriptHeadStr + "</head>" + "<body>" + bodyStr + scriptBodyStr + "</body></html>";

  server.send(200, "text/html", htmlStr);
}

void handleRoot() {
  String wsAddrStr = server.arg("wsaddr");

  if (wsAddrStr.length() == 0) {
    IPAddress ip = WiFi.localIP();
    wsAddrStr = String(ip[0]) + "." + String(ip[1]) + "." + String(ip[2])
                  + "." + String(ip[3]) + ":" + String(WSPORT);
  }

  printHtmlHome(wsAddrStr);
}

void handleNotFound(){
  String message = "File Not Found\n\n";
  message += "URI: ";
  message += server.uri();
  message += "\nMethod: ";
  message += (server.method() == HTTP_GET)?"GET":"POST";
  message += "\nArguments: ";
  message += server.args();
  message += "\n";
  for (uint8_t i=0; i<server.args(); i++){
    message += " " + server.argName(i) + ": " + server.arg(i) + "\n";
  }
  server.send(404, "text/plain", message);
}

void handleDebug(void) {
  String strout = "";
  char buf[50];
  sprintf(buf, "chargerTimeSecond: %lu\n\r", chargerTimeSecond);
  strout += buf;
  sprintf(buf, "chargerTimeSecond_old: %lu\n\r", chargerTimeSecond_old);
  strout += buf;

  #ifdef CHARGER_ENABLE
  sprintf(buf, "chargerFlag: %d\n\r", chargerOnFlag);
  #endif

  strout += buf;
  strout += "ledState: ";
  strout += getBinString(ledState);
  strout += "\n\rledState_old: ";
  strout += getBinString(ledState_old);

  strout += "\n\rswitchState: ";
  strout += getBinString(switchState);
  strout += "\n\rswitchState_old: ";
  strout += getBinString(switchState_old);
  // strout += "\n\rlstrStateBase64: ";
  // strout += lnkStatStrBase64;
  // strout += "\n\rlstrState: ";
  // strout += lnkStatStr;
  server.send(200, "text/plain", strout);
};

uint8_t chexToUint(uint8_t uchrIn) {
    if((uchrIn > 0x2F) && (uchrIn < 0x3A)) return (uchrIn - 48);
    else if((uchrIn > 0x40) && (uchrIn < 0x47)) return (uchrIn - 55);
    return 48;
}

void initWebServer(void) {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  // Serial.Println("");

  // Wait for connection
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    //Serial.print(".");
  }
  // Serial.println("");
  // Serial.print("Connected to ");
  // Serial.println(ssid);
  // Serial.print("IP address: ");
  // Serial.println(WiFi.localIP());

  //if (mdns.begin(idstr, WiFi.localIP())) {
    // Serial.println("MDNS responder started");
  //  connectFlag = true;
  //}

  // server.on("/", handleRoot);

  server.on("/id", [](){
    server.send(200, "text/plain", idstr);
  });

  // server.on("/debug", handleDebug);
  server.on("/kes", handleKes);
  server.on("/lnk", handleLnk);
  server.on("/ste", handleSte);

  // server.on("/hexstr", handleHexStr);
  // server.on("/key", handleKey);
  // server.on("/cmd", handleCmd);
  // server.on("/chkes", handleChkes);
  // server.on("/aes", handleAes);

  server.onNotFound(handleNotFound);

  server.begin();
  // Serial.Println("HTTP server started");

  // start webSocket server
  //webSocket.begin();
  //webSocket.onEvent(webSocketEvent);

  // Add service to MDNS
  //MDNS.addService("http", "tcp", HTTPPORT);
  //MDNS.addService("ws", "tcp", WSPORT);
}

void printLED() {
  if(ledState != ledState_old) {
    writeLedState();
    for(int i=0;i<4;i++) {
      if(ledState & (1 << i)) digitalWrite(ledint[i], HIGH);
       else digitalWrite(ledint[i], LOW);
    }
    ledState_old = ledState;
  }
}

void initSwitchPin(void) {
  readLedState();

  //#ifdef CHARGER_ENABLE
  //ledState &= ~(1 << chargerPinIdx);
  //ledState |= (1 << chargerPinIdx);
  //#endif

  for(int i=0;i<4;i++) {
    pinMode(ledint[i], OUTPUT);
    if(ledState & (1 << i)) digitalWrite(ledint[i], HIGH);
    else digitalWrite(ledint[i], LOW);
    pinMode(tglint[i], INPUT);
  }

  ledState_old = ledState;
  switchState = 0xff;
  switchState_old = 0xff;

  delay(100);
}

#ifdef CHARGER_ENABLE
void chargerRoutine() {
  if(chargerTimeSecond_old < chargerTimeSecond) {
    if(chargerOnFlag) {
      chargerOnFlag = false;
      // ledState &=  ~(1 << chargerPinIdx);
      ledState |= 1 << chargerPinIdx;
      chargerTimeSecond_old = CHARGERTIMESECONDON;
    } else {
      chargerOnFlag = true;
      //if (ledState == (0xff ^ (1 << chargerPinIdx))) {
        // ledState |= 1 << chargerPinIdx;
        ledState &=  ~(1 << chargerPinIdx);
      //}
      chargerTimeSecond_old = CHARGERTIMESECONDOFF;
    }
    chargerTimeSecond = 0;
  }
}
#endif

//   if(chargerTimeSecond > CHARGERTIMESECONDTOTAL) {
//     chargerTimeSecond = 0;
//   }
// }

void check_switch(void) {
  int i, val;
  String bstr;

  switchState = 0x00;
  for(i=0;i<4;i++) {
    val = digitalRead(tglint[i]);
    if(val) switchState |= 1 << i;
  }

  // Serial.println(switchState, BIN);

  if(switchState_old != switchState) {
    for(i=0;i<4;i++) {
      if((switchState & (1 << i)) > (switchState_old & (1 << i))) {
        // Serial.print("Toggle: "); Serial.println(i);
        ledState = ledState_old ^ (1 << i);
      }
    }
    bstr = "*" + getBinString(ledState);
    //webSocket.broadcastTXT(bstr);
  }

  switchState_old = switchState;
}

void setupArduinoOTA(void) {
  // Port defaults to 8266
  // ArduinoOTA.setPort(8266);

  // Hostname defaults to esp8266-[ChipID]
  // ArduinoOTA.setHostname("myesp8266");

  // No authentication by default
  ArduinoOTA.setPassword("panjul1017");

  // Password can be set with it's md5 value as well
  // MD5(admin) = 21232f297a57a5a743894a0e4a801fc3
  // ArduinoOTA.setPasswordHash("21232f297a57a5a743894a0e4a801fc3");

  ArduinoOTA.onStart([]() {
    // String type;
    // if (ArduinoOTA.getCommand() == U_FLASH)
    //   type = "sketch";
    // else // U_SPIFFS
    //   type = "filesystem";

    // NOTE: if updating SPIFFS this would be the place to unmount SPIFFS using SPIFFS.end()
    //Serial.println("Start updating ");// + type);
  });
  ArduinoOTA.onEnd([]() {
    //Serial.println("\nEnd");
  });
  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    //Serial.printf("Progress: %u%%\r", (progress / (total / 100)));
  });
  ArduinoOTA.onError([](ota_error_t error) {
    // Serial.printf("Error[%u]: ", error);
    // if (error == OTA_AUTH_ERROR) Serial.println("Auth Failed");
    // else if (error == OTA_BEGIN_ERROR) Serial.println("Begin Failed");
    // else if (error == OTA_CONNECT_ERROR) Serial.println("Connect Failed");
    // else if (error == OTA_RECEIVE_ERROR) Serial.println("Receive Failed");
    // else if (error == OTA_END_ERROR) Serial.println("End Failed");
  });
  ArduinoOTA.begin();
}

void secondTicking(void) {
  chargerTimeSecond++;
  if(reqKeyFlag) reqKeyTimeSecond++;
}

void initTimer(void) {
  timerObj.every(7200000, generateRandomKey);
  timerObj.every(1000, secondTicking);
}

void reqKeyRoutine(void) {
  if(reqKeyTimeSecond > 2) {
    generateRandomKey();
    reqKeyFlag = false;
  }
}

// void printPINStatus(void) {
//   String str = "Pin: "
//   for(i=0;i<8;i++) {
//     val = digitalRead(pinstatus[i]);
//     if(val) str += "1";
//     else str += "0";
//   }
//   Serial.println(str);
// }

void setup(void){
  // Serial.begin(115200);
  EEPROM.begin(512);
  initTimer();
  initSwitchPin();
  //setupArduinoOTA();
  initWebServer();
  generateRandomKey();
}

void loop(void){
  timerObj.update();

  //ArduinoOTA.handle();
  //webSocket.loop();
  server.handleClient();
  check_switch();

  // serialCnt++;
  // if(serialCnt == 100) {
  //   if(connectFlag == false) connectFlag = true;
  //   Serial.println(WiFi.localIP());
  //   printPINStatus();
  //   serialCnt = 0;
  // }
  
  printLED();
  
  #ifdef CHARGER_ENABLE
  chargerRoutine();
  #endif
  
  reqKeyRoutine();
  // delay(5);
}

// void handleAes(void) {
//   String strprint = "";
//
//   // encoding
//   char inputString[] = "Base64EncodeExample";
//
//   int inputStringLength = sizeof(inputString);
//   int encodedLength = Base64.encodedLength(inputStringLength);
//   char encodedString[encodedLength];
//
//   Base64.encode(encodedString, inputString, inputStringLength);
//
//   strprint += "Input string:\t";
//   strprint += inputString;
//   strprint += "\n\rEncoded string:\t";
//   strprint += encodedString;
//
//
//   uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
//                       0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
//
//   uint8_t out[] = { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
//                       0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
//                       0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
//                       0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };
//
//   uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
//   uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
//                     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
//                     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
//                     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
//
//   uint8_t in2[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
//                     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
//                     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
//                     0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };
//
//   strprint += "\n\rin (base64): ";
//   strprint += b64EncStr((char *) in, sizeof(in));
//   strprint += "\n\rkey (base64): ";
//   strprint += b64EncStr((char *) key, sizeof(key));
//   strprint += "\n\riv (base64): ";
//   strprint += b64EncStr((char *) iv, sizeof(iv));
//   String encryptedOut = aesEncryptIv(in, sizeof(in), key, iv);
//   String encryptedOut2 = aesEncryptIv(in2, sizeof(in2), key, iv);
//
//   strprint += "\n\rin (base64): ";
//   strprint += b64EncStr((char *) in, sizeof(in));
//   strprint += "\n\rkey (base64): ";
//   strprint += b64EncStr((char *) key, sizeof(key));
//   strprint += "\n\riv (base64): ";
//   strprint += b64EncStr((char *) iv, sizeof(iv));
//
//   String encryptedOutIv = aesEncryptIv(in, sizeof(in), key, iv);
//   strprint += "\n\rin (base64): ";
//   strprint += b64EncStr((char *) in, sizeof(in));
//   strprint += "\n\rkey (base64): ";
//   strprint += b64EncStr((char *) key, sizeof(key));
//   strprint += "\n\riv (base64): ";
//   strprint += b64EncStr((char *) iv, sizeof(iv));
//
//   String encodedOut = b64EncStr((char *) out, sizeof(out));
//
//   strprint += "\n\rCBC encrypt (base64): ";
//   strprint += encryptedOut;
//   strprint += "\n\rCBC2 encrypt (base64): ";
//   strprint += encryptedOut2;
//   strprint += "\n\rOut encrypt (base64): ";
//   strprint += encodedOut;
//   strprint += "\n\rOut encryptIv (base64): ";
//   strprint += encryptedOutIv;
//
//   strprint += "\n\rAesStateTemp (base64): ";
//   strprint += b64EncStr((char *) aesStateTemp, sizeof(aesStateTemp));
//
//   // if(encryptedOut == encodedOut)
//   if(encryptedOut == encodedOut)
//   {
//     strprint += "\n\rSUCCESS!\n";
//   }
//   else
//   {
//     strprint += "\n\rFAILURE!\n";
//   }
//
//   server.send(200, "text/plain", strprint);
// }
//
// void handleChkes(void) {
//   String statStr = server.arg("stat");
//   String strout = "";
//
//   statStr.trim();
//   lnkStatStr.trim();
//
//   statStr.replace("+", " ");
//   statStr.replace(" ", "");
//   lnkStatStr.replace("+", " ");
//   lnkStatStr.replace(" ", "");
//
//   int cmpInt = lnkStatStr.compareTo(statStr);
//   if(cmpInt == 0) {
//     strout = "ok";
//   }
//   // if(lnkStatStr == "noinput") {strout = "forbidden";}
//   //
//   // lnkStatStr = "noinput";
//   strout += String(cmpInt);
//   server.send(200, "text/plain", strout + " : " + lnkStatStr + " :vs: " + statStr);
// }

// void handleCmd(void) {
//   uint8_t j = 0;
//   uint8_t pinIdx = 0;
//   char pinIdxBuf[4];
//   uint8_t hexNum = 0;
//   String strout;
//   String strprint = "ok";
//   String state = "";
//
//   if(reqKeyFlag) {
//     reqKeyFlag = false;
//     state = server.arg("state");
//     for(int i = 0; i < sizeof(state); i+=2) {
//       hexNum = chexToUint((uint8_t)state[i]) << 4 | chexToUint((uint8_t)state[i + 1]);
//       strout +=  (char)(hexNum ^ aeskey[j]);
//       j++;
//       if(j >= aesKeyLen) j = 0;
//     }
//
//     pinIdx = strout[5] - 48;
//
//     if(strout.substring(0,5) == "ledon") {
//       strprint = "ledon";
//       sprintf(pinIdxBuf, "%X", pinIdx);
//       strprint += pinIdxBuf;
//       ledState &= ~(1 << pinIdx);
//     }
//     else if(strout.substring(0,5) == "ledof") {
//       strprint = "ledof";
//       sprintf(pinIdxBuf, "%X", pinIdx);
//       strprint += pinIdxBuf;
//       ledState |= (1 << pinIdx);
//     }
//   }
//
//   generateRandomKey();
//
//   server.send(200, "text/plain", strprint);
// }
// void handleKey(void) {
//   if(reqKeyFlag) {
//     generateRandomKey();
//   }
//
//   reqKeyFlag = true;
//   String strout = "";
//   strout += (char)(random(0, 25) + 65);
//   for(int i = 0; i < aesKeyLen; i++) {
//     strout += (char)(aeskey[i] + passkey[i]);
//   }
//
//   server.send(200, "text/plain", strout);
// };
// void handleHexStr(void) {
//   String num = server.arg("num");
//   String strout = StrToSHex(num, num.length());
//   server.send(200, "text/plain", strout);
// }
