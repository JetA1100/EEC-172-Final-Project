//*****************************************************************************
//
// Copyright (C) 2014 Texas Instruments Incorporated - http://www.ti.com/ 
// 
// 
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//
//    Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer.
//
//    Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the 
//    documentation and/or other materials provided with the   
//    distribution.
//
//    Neither the name of Texas Instruments Incorporated nor the names of
//    its contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
//  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
//  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
//  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//*****************************************************************************


//*****************************************************************************
//
// Application Name     -   SSL Demo
// Application Overview -   This is a sample application demonstrating the
//                          use of secure sockets on a CC3200 device.The
//                          application connects to an AP and
//                          tries to establish a secure connection to the
//                          Google server.
// Application Details  -
// docs\examples\CC32xx_SSL_Demo_Application.pdf
// or
// http://processors.wiki.ti.com/index.php/CC32xx_SSL_Demo_Application
//
//*****************************************************************************


//*****************************************************************************
//
//! \addtogroup ssl
//! @{
//
//*****************************************************************************

// Simplelink includes
#include "simplelink.h"

//Driverlib includes
#include "stdio.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "hw_types.h"
#include "hw_ints.h"
#include "hw_memmap.h"
#include "hw_common_reg.h"
#include "spi.h"
#include "rom.h"
#include "rom_map.h"
#include "interrupt.h"
#include "prcm.h"
#include "utils.h"
#include "uart.h"
#include "Adafruit_GFX.h"
#include "Adafruit_SSD1351.h"
#include "glcdfont.h"
#include "hw_apps_rcm.h"
#include "gpio.h"


//Common interface includes
#include "pin_mux_config.h"
#include "gpio_if.h"
#include "common.h"
#include "uart_if.h"
#include "i2c_if.h"


#define MAX_URI_SIZE 128
#define URI_SIZE MAX_URI_SIZE + 1


#define APPLICATION_NAME        "I2C+SNS"
#define APPLICATION_VERSION     "1.4.0.EEC.Spring2021"
#define SERVER_NAME                "a29dslx75xc5x-ats.iot.us-west-2.amazonaws.com"
#define GOOGLE_DST_PORT             8443

#define SL_SSL_CA_CERT "/lab 4/starfieldclass2ca.crt.der"
#define SL_SSL_PRIVATE "/lab 4/private.der"
#define SL_SSL_CLIENT  "/lab 4/client.der"

//NEED TO UPDATE THIS FOR IT TO WORK!
#define DATE                7    /* Current Date */
#define MONTH               06     /* Month 1-12 */
#define YEAR                2021  /* Current year */
#define HOUR                5    /* Time - hours */
#define MINUTE              0    /* Time - minutes */
#define SECOND              0     /* Time - seconds */

#define POSTHEADER "POST /things/CC3200_Thing/shadow HTTP/1.1\n\r"
#define GETHEADER "GET /things/CC3200_Thing/shadow HTTP/1.1\n\r"
#define HOSTHEADER "Host: a29dslx75xc5x-ats.iot.us-west-2.amazonaws.com\r\n"
#define CHEADER "Connection: Keep-Alive\r\n"
#define CTHEADER "Content-Type: application/json; charset=utf-8\r\n"
#define CLHEADER1 "Content-Length: "
#define CLHEADER2 "\r\n\r\n"

#define DATA1 "{\"state\": {\n\r\"desired\" : {\n\r\"default\" : \"Game Over! Score %d! (High Score %d)\",\n\r\"sms\" : \"Game Over! Score %d! (High Score %d)\",\n\r\"email\" : \"Game Over! Score %d! (High Score %d)\"\n\r}}}\n\r\n\r"

#define MASTER_MODE      1

#define SPI_IF_BIT_RATE  100000
#define TR_BUFF_SIZE     100
#define BLACK           0x0000
#define WHITE           0xFFFF
#define RED             0xF800
#define YELLOW          0xFFE0
#define GREEN           0x07E0
#define BLUE            0x001F

// Application specific status/error codes
typedef enum{
    // Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
    LAN_CONNECTION_FAILED = -0x7D0,
    INTERNET_CONNECTION_FAILED = LAN_CONNECTION_FAILED - 1,
    DEVICE_NOT_IN_STATION_MODE = INTERNET_CONNECTION_FAILED - 1,

    STATUS_CODE_MAX = -0xBB8
}e_AppStatusCodes;

typedef struct
{
   /* time */
   unsigned long tm_sec;
   unsigned long tm_min;
   unsigned long tm_hour;
   /* date */
   unsigned long tm_day;
   unsigned long tm_mon;
   unsigned long tm_year;
   unsigned long tm_week_day; //not required
   unsigned long tm_year_day; //not required
   unsigned long reserved[3];
}SlDateTime;


//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************
volatile unsigned long  g_ulStatus = 0;//SimpleLink Status
unsigned long  g_ulPingPacketsRecv = 0; //Number of Ping Packets received
unsigned long  g_ulGatewayIP = 0; //Network Gateway IP address
unsigned char  g_ucConnectionSSID[SSID_LEN_MAX+1]; //Connection SSID
unsigned char  g_ucConnectionBSSID[BSSID_LEN_MAX]; //Connection BSSID
signed char    *g_Host = SERVER_NAME;
int level = 1;
int x = 15;
int y = 111;
int rollx = 0;
int rolly = 0;
int coin[10];
SlDateTime g_time;
#if defined(ccs) || defined(gcc)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************


//****************************************************************************
//                      LOCAL FUNCTION PROTOTYPES
//****************************************************************************
static long WlanConnect();
static int set_time();
static long InitializeAppVariables();
static int tls_connect();
static int connectToAccessPoint();
void drawString(int x, int y, char* str, unsigned int color, int size);
int get_setup();
void post_setup();
static int http_post(int, int, int);
static int http_get(int);
long printErrConvenience(char * msg, long retVal);
//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- Start
//*****************************************************************************


//*****************************************************************************
//
//! \brief The Function Handles WLAN Events
//!
//! \param[in]  pWlanEvent - Pointer to WLAN Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent) {
    if(!pWlanEvent) {
        return;
    }

    switch(pWlanEvent->Event) {
        case SL_WLAN_CONNECT_EVENT: {
            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);

            //
            // Information about the connected AP (like name, MAC etc) will be
            // available in 'slWlanConnectAsyncResponse_t'.
            // Applications can use it if required
            //
            //  slWlanConnectAsyncResponse_t *pEventData = NULL;
            // pEventData = &pWlanEvent->EventData.STAandP2PModeWlanConnected;
            //

            // Copy new connection SSID and BSSID to global parameters
            memcpy(g_ucConnectionSSID,pWlanEvent->EventData.
                   STAandP2PModeWlanConnected.ssid_name,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.ssid_len);
            memcpy(g_ucConnectionBSSID,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.bssid,
                   SL_BSSID_LENGTH);

            UART_PRINT("[WLAN EVENT] STA Connected to the AP: %s , "
                       "BSSID: %x:%x:%x:%x:%x:%x\n\r",
                       g_ucConnectionSSID,g_ucConnectionBSSID[0],
                       g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                       g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                       g_ucConnectionBSSID[5]);
        }
        break;

        case SL_WLAN_DISCONNECT_EVENT: {
            slWlanConnectAsyncResponse_t*  pEventData = NULL;

            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

            // If the user has initiated 'Disconnect' request,
            //'reason_code' is SL_USER_INITIATED_DISCONNECTION
            if(SL_USER_INITIATED_DISCONNECTION == pEventData->reason_code) {
                UART_PRINT("[WLAN EVENT]Device disconnected from the AP: %s,"
                    "BSSID: %x:%x:%x:%x:%x:%x on application's request \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            else {
                UART_PRINT("[WLAN ERROR]Device disconnected from the AP AP: %s, "
                           "BSSID: %x:%x:%x:%x:%x:%x on an ERROR..!! \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
            memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
        }
        break;

        default: {
            UART_PRINT("[WLAN EVENT] Unexpected event [0x%x]\n\r",
                       pWlanEvent->Event);
        }
        break;
    }
}

//*****************************************************************************
//
//! \brief This function handles network events such as IP acquisition, IP
//!           leased, IP released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent) {
    if(!pNetAppEvent) {
        return;
    }

    switch(pNetAppEvent->Event) {
        case SL_NETAPP_IPV4_IPACQUIRED_EVENT: {
            SlIpV4AcquiredAsync_t *pEventData = NULL;

            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            //Ip Acquired Event Data
            pEventData = &pNetAppEvent->EventData.ipAcquiredV4;

            //Gateway IP address
            g_ulGatewayIP = pEventData->gateway;

            UART_PRINT("[NETAPP EVENT] IP Acquired: IP=%d.%d.%d.%d , "
                       "Gateway=%d.%d.%d.%d\n\r",
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,0),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,0));
        }
        break;

        default: {
            UART_PRINT("[NETAPP EVENT] Unexpected event [0x%x] \n\r",
                       pNetAppEvent->Event);
        }
        break;
    }
}


//*****************************************************************************
//
//! \brief This function handles HTTP server events
//!
//! \param[in]  pServerEvent - Contains the relevant event information
//! \param[in]    pServerResponse - Should be filled by the user with the
//!                                      relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent, SlHttpServerResponse_t *pHttpResponse) {
    // Unused in this application
}

//*****************************************************************************
//
//! \brief This function handles General Events
//!
//! \param[in]     pDevEvent - Pointer to General Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent) {
    if(!pDevEvent) {
        return;
    }

    //
    // Most of the general errors are not FATAL are are to be handled
    // appropriately by the application
    //
    UART_PRINT("[GENERAL EVENT] - ID=[%d] Sender=[%d]\n\n",
               pDevEvent->EventData.deviceEvent.status,
               pDevEvent->EventData.deviceEvent.sender);
}


//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]      pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock) {
    if(!pSock) {
        return;
    }

    switch( pSock->Event ) {
        case SL_SOCKET_TX_FAILED_EVENT:
            switch( pSock->socketAsyncEvent.SockTxFailData.status) {
                case SL_ECLOSE: 
                    UART_PRINT("[SOCK ERROR] - close socket (%d) operation "
                                "failed to transmit all queued packets\n\n", 
                                    pSock->socketAsyncEvent.SockTxFailData.sd);
                    break;
                default: 
                    UART_PRINT("[SOCK ERROR] - TX FAILED  :  socket %d , reason "
                                "(%d) \n\n",
                                pSock->socketAsyncEvent.SockTxFailData.sd, pSock->socketAsyncEvent.SockTxFailData.status);
                  break;
            }
            break;

        default:
            UART_PRINT("[SOCK EVENT] - Unexpected Event [%x0x]\n\n",pSock->Event);
          break;
    }
}


//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- End
//*****************************************************************************


//*****************************************************************************
//
//! \brief This function initializes the application variables
//!
//! \param    0 on success else error code
//!
//! \return None
//!
//*****************************************************************************
static long InitializeAppVariables() {
    g_ulStatus = 0;
    g_ulGatewayIP = 0;
    g_Host = SERVER_NAME;
    memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
    memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
    return SUCCESS;
}


//*****************************************************************************
//! \brief This function puts the device in its default state. It:
//!           - Set the mode to STATION
//!           - Configures connection policy to Auto and AutoSmartConfig
//!           - Deletes all the stored profiles
//!           - Enables DHCP
//!           - Disables Scan policy
//!           - Sets Tx power to maximum
//!           - Sets power policy to normal
//!           - Unregister mDNS services
//!           - Remove all filters
//!
//! \param   none
//! \return  On success, zero is returned. On error, negative is returned
//*****************************************************************************
static long ConfigureSimpleLinkToDefaultState() {
    SlVersionFull   ver = {0};
    _WlanRxFilterOperationCommandBuff_t  RxFilterIdMask = {0};

    unsigned char ucVal = 1;
    unsigned char ucConfigOpt = 0;
    unsigned char ucConfigLen = 0;
    unsigned char ucPower = 0;

    long lRetVal = -1;
    long lMode = -1;

    lMode = sl_Start(0, 0, 0);
    ASSERT_ON_ERROR(lMode);

    // If the device is not in station-mode, try configuring it in station-mode 
    if (ROLE_STA != lMode) {
        if (ROLE_AP == lMode) {
            // If the device is in AP mode, we need to wait for this event 
            // before doing anything 
            while(!IS_IP_ACQUIRED(g_ulStatus)) {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
            }
        }

        // Switch to STA role and restart 
        lRetVal = sl_WlanSetMode(ROLE_STA);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Stop(0xFF);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Start(0, 0, 0);
        ASSERT_ON_ERROR(lRetVal);

        // Check if the device is in station again 
        if (ROLE_STA != lRetVal) {
            // We don't want to proceed if the device is not coming up in STA-mode 
            return DEVICE_NOT_IN_STATION_MODE;
        }
    }
    
    // Get the device's version-information
    ucConfigOpt = SL_DEVICE_GENERAL_VERSION;
    ucConfigLen = sizeof(ver);
    lRetVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &ucConfigOpt, 
                                &ucConfigLen, (unsigned char *)(&ver));
    ASSERT_ON_ERROR(lRetVal);
    
    UART_PRINT("Host Driver Version: %s\n\r",SL_DRIVER_VERSION);
    UART_PRINT("Build Version %d.%d.%d.%d.31.%d.%d.%d.%d.%d.%d.%d.%d\n\r",
    ver.NwpVersion[0],ver.NwpVersion[1],ver.NwpVersion[2],ver.NwpVersion[3],
    ver.ChipFwAndPhyVersion.FwVersion[0],ver.ChipFwAndPhyVersion.FwVersion[1],
    ver.ChipFwAndPhyVersion.FwVersion[2],ver.ChipFwAndPhyVersion.FwVersion[3],
    ver.ChipFwAndPhyVersion.PhyVersion[0],ver.ChipFwAndPhyVersion.PhyVersion[1],
    ver.ChipFwAndPhyVersion.PhyVersion[2],ver.ChipFwAndPhyVersion.PhyVersion[3]);

    // Set connection policy to Auto + SmartConfig 
    //      (Device's default connection policy)
    lRetVal = sl_WlanPolicySet(SL_POLICY_CONNECTION, 
                                SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove all profiles
    lRetVal = sl_WlanProfileDel(0xFF);
    ASSERT_ON_ERROR(lRetVal);

    

    //
    // Device in station-mode. Disconnect previous connection if any
    // The function returns 0 if 'Disconnected done', negative number if already
    // disconnected Wait for 'disconnection' event if 0 is returned, Ignore 
    // other return-codes
    //
    lRetVal = sl_WlanDisconnect();
    if(0 == lRetVal) {
        // Wait
        while(IS_CONNECTED(g_ulStatus)) {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
        }
    }

    // Enable DHCP client
    lRetVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE,1,1,&ucVal);
    ASSERT_ON_ERROR(lRetVal);

    // Disable scan
    ucConfigOpt = SL_SCAN_POLICY(0);
    lRetVal = sl_WlanPolicySet(SL_POLICY_SCAN , ucConfigOpt, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Set Tx power level for station mode
    // Number between 0-15, as dB offset from max power - 0 will set max power
    ucPower = 0;
    lRetVal = sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, 
            WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (unsigned char *)&ucPower);
    ASSERT_ON_ERROR(lRetVal);

    // Set PM policy to normal
    lRetVal = sl_WlanPolicySet(SL_POLICY_PM , SL_NORMAL_POLICY, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Unregister mDNS services
    lRetVal = sl_NetAppMDNSUnRegisterService(0, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove  all 64 filters (8*8)
    memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
    lRetVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                       sizeof(_WlanRxFilterOperationCommandBuff_t));
    ASSERT_ON_ERROR(lRetVal);

    lRetVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(lRetVal);

    InitializeAppVariables();
    
    return lRetVal; // Success
}


//*****************************************************************************
//
//! Board Initialization & Configuration
//!
//! \param  None
//!
//! \return None
//
//*****************************************************************************
static void BoardInit(void) {
/* In case of TI-RTOS vector table is initialize by OS itself */
#ifndef USE_TIRTOS
  //
  // Set vector table base
  //
#if defined(ccs)
    MAP_IntVTableBaseSet((unsigned long)&g_pfnVectors[0]);
#endif
#if defined(ewarm)
    MAP_IntVTableBaseSet((unsigned long)&__vector_table);
#endif
#endif
    //
    // Enable Processor
    //
    MAP_IntMasterEnable();
    MAP_IntEnable(FAULT_SYSTICK);

    PRCMCC3200MCUInit();
}


//****************************************************************************
//
//! \brief Connecting to a WLAN Accesspoint
//!
//!  This function connects to the required AP (SSID_NAME) with Security
//!  parameters specified in te form of macros at the top of this file
//!
//! \param  None
//!
//! \return  0 on success else error code
//!
//! \warning    If the WLAN connection fails or we don't aquire an IP
//!            address, It will be stuck in this function forever.
//
//****************************************************************************
static long WlanConnect() {
    SlSecParams_t secParams = {0};
    long lRetVal = 0;

    secParams.Key = SECURITY_KEY;
    secParams.KeyLen = strlen(SECURITY_KEY);
    secParams.Type = SECURITY_TYPE;

    UART_PRINT("Attempting connection to access point: ");
    UART_PRINT(SSID_NAME);
    UART_PRINT("... ...");
    lRetVal = sl_WlanConnect(SSID_NAME, strlen(SSID_NAME), 0, &secParams, 0);
    ASSERT_ON_ERROR(lRetVal);

    UART_PRINT(" Connected!!!\n\r");


    // Wait for WLAN Event
    while((!IS_CONNECTED(g_ulStatus)) || (!IS_IP_ACQUIRED(g_ulStatus))) {
        // Toggle LEDs to Indicate Connection Progress
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOff(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOn(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
    }

    return SUCCESS;

}

//*****************************************************************************
//
//! This function updates the date and time of CC3200.
//!
//! \param None
//!
//! \return
//!     0 for success, negative otherwise
//!
//*****************************************************************************

static int set_time() {
    long retVal;

    g_time.tm_day = DATE;
    g_time.tm_mon = MONTH;
    g_time.tm_year = YEAR;
    g_time.tm_sec = HOUR;
    g_time.tm_hour = MINUTE;
    g_time.tm_min = SECOND;

    retVal = sl_DevSet(SL_DEVICE_GENERAL_CONFIGURATION,
                          SL_DEVICE_GENERAL_CONFIGURATION_DATE_TIME,
                          sizeof(SlDateTime),(unsigned char *)(&g_time));

    ASSERT_ON_ERROR(retVal);
    return SUCCESS;
}

//*****************************************************************************
//
//! This function demonstrates how certificate can be used with SSL.
//! The procedure includes the following steps:
//! 1) connect to an open AP
//! 2) get the server name via a DNS request
//! 3) define all socket options and point to the CA certificate
//! 4) connect to the server via TCP
//!
//! \param None
//!
//! \return  0 on success else error code
//! \return  LED1 is turned solid in case of success
//!    LED2 is turned solid in case of failure
//!
//*****************************************************************************
static int tls_connect() {
    SlSockAddrIn_t    Addr;
    int    iAddrSize;
    unsigned char    ucMethod = SL_SO_SEC_METHOD_TLSV1_2;
    unsigned int uiIP,uiCipher = SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    long lRetVal = -1;
    int iSockID;

    lRetVal = sl_NetAppDnsGetHostByName(g_Host, strlen((const char *)g_Host),
                                    (unsigned long*)&uiIP, SL_AF_INET);

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't retrieve the host name \n\r", lRetVal);
    }

    Addr.sin_family = SL_AF_INET;
    Addr.sin_port = sl_Htons(GOOGLE_DST_PORT);
    Addr.sin_addr.s_addr = sl_Htonl(uiIP);
    iAddrSize = sizeof(SlSockAddrIn_t);
    //
    // opens a secure socket 
    //
    iSockID = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, SL_SEC_SOCKET);
    if( iSockID < 0 ) {
        return printErrConvenience("Device unable to create secure socket \n\r", lRetVal);
    }

    //
    // configure the socket as TLS1.2
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECMETHOD, &ucMethod,\
                               sizeof(ucMethod));
    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }
    //
    //configure the socket as ECDHE RSA WITH AES256 CBC SHA
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECURE_MASK, &uiCipher,\
                           sizeof(uiCipher));
    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }

    //
    //configure the socket with CA certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
                           SL_SO_SECURE_FILES_CA_FILE_NAME, \
                           SL_SSL_CA_CERT, \
                           strlen(SL_SSL_CA_CERT));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }

    //configure the socket with Client Certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
                SL_SO_SECURE_FILES_CERTIFICATE_FILE_NAME, \
                                    SL_SSL_CLIENT, \
                           strlen(SL_SSL_CLIENT));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }

    //configure the socket with Private Key - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
            SL_SO_SECURE_FILES_PRIVATE_KEY_FILE_NAME, \
            SL_SSL_PRIVATE, \
                           strlen(SL_SSL_PRIVATE));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }


    /* connect to the peer device - Google server */
    lRetVal = sl_Connect(iSockID, ( SlSockAddr_t *)&Addr, iAddrSize);

    if(lRetVal < 0) {
        UART_PRINT("Device couldn't connect to server:");
        UART_PRINT(SERVER_NAME);
        UART_PRINT("\n\r");
        return printErrConvenience("Device couldn't connect to server \n\r", lRetVal);
    }
    else {
        UART_PRINT("Device has connected to the website:");
        UART_PRINT(SERVER_NAME);
        UART_PRINT("\n\r");
    }

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOn(MCU_GREEN_LED_GPIO);
    return iSockID;
}



long printErrConvenience(char * msg, long retVal) {
    UART_PRINT(msg);
    GPIO_IF_LedOn(MCU_RED_LED_GPIO);
    return retVal;
}



int connectToAccessPoint() {
    long lRetVal = -1;
    GPIO_IF_LedConfigure(LED1|LED3);

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOff(MCU_GREEN_LED_GPIO);

    lRetVal = InitializeAppVariables();
    ASSERT_ON_ERROR(lRetVal);

    //
    // Following function configure the device to default state by cleaning
    // the persistent settings stored in NVMEM (viz. connection profiles &
    // policies, power policy etc)
    //
    // Applications may choose to skip this step if the developer is sure
    // that the device is in its default state at start of applicaton
    //
    // Note that all profiles and persistent settings that were done on the
    // device will be lost
    //
    lRetVal = ConfigureSimpleLinkToDefaultState();
    if(lRetVal < 0) {
      if (DEVICE_NOT_IN_STATION_MODE == lRetVal)
          UART_PRINT("Failed to configure the device in its default state \n\r");

      return lRetVal;
    }

    UART_PRINT("Device is configured in default state \n\r");

    CLR_STATUS_BIT_ALL(g_ulStatus);

    ///
    // Assumption is that the device is configured in station mode already
    // and it is in its default state
    //
    lRetVal = sl_Start(0, 0, 0);
    if (lRetVal < 0 || ROLE_STA != lRetVal) {
        UART_PRINT("Failed to start the device \n\r");
        return lRetVal;
    }

    UART_PRINT("Device started as STATION \n\r");

    //
    //Connecting to WLAN AP
    //
    lRetVal = WlanConnect();
    if(lRetVal < 0) {
        UART_PRINT("Failed to establish connection w/ an AP \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    UART_PRINT("Connection established w/ AP and IP is aquired \n\r");
    return 0;
}

void drawString(int x, int y, char* str, unsigned int color, int size) {
    const int n = strlen(str);
    int i;
    for (i = 0; i < n; i++) {
        drawChar(x, y, str[i], color, BLACK, size);
        x += (5*size);
    }
}

void renderLevel() {
    int i;
    // Reset coins
    for (i = 0; i < sizeof(coin); i++) {
        coin[i] = 0;
    }
    switch (level) {
    case 1:
        fillRect(0, 25, 128,103, BLACK);
        drawChar(30, 4, '1', WHITE, BLACK, 1);

        // Player Start
        x = 15;
        y = 111;
        rollx = 0;
        rolly = 0;
        // Walls
        fillRect(50, 95, 5, 33, WHITE);
        fillRect(0, 63, 35, 5, WHITE);
        fillRect(50, 25, 5, 20, WHITE);
        fillRect(90, 40, 5, 40, WHITE);
        fillRect(110, 63, 18, 5, WHITE);
        fillRect(110, 95, 5, 33, WHITE);
        // Danger Zones
        fillCircle(20, 42, 4, RED);
        fillCircle(118, 81, 4, RED);
        fillCircle(69, 116, 4, RED);
        // Coins
        fillCircle(36, 30, 2, YELLOW);
        coin[0] = 1;
        fillCircle(63, 63, 2, YELLOW);
        coin[1] = 1;
        fillCircle(82, 108, 2, YELLOW);
        coin[2] = 1;
        // Goal
        fillCircle(113, 44, 4, GREEN);
        break;
    case 2:
        fillRect(0, 25, 128, 103, BLACK);
        drawChar(30, 4, '2', WHITE, BLACK, 1);
        // Player Start
        x = 10;
        y = 111;
        rollx = 0;
        rolly = 0;
        // Walls
        fillRect(30, 90, 5, 38, WHITE);
        fillRect(25, 25, 5, 42, WHITE);
        fillRect(64, 50, 5, 42, WHITE);
        fillRect(100, 60, 28, 5, WHITE);
        fillRect(105, 95, 5, 33, WHITE);
        // Danger Zones
        fillCircle(12, 36, 4, RED);
        fillCircle(52, 109, 4, RED);
        fillCircle(120, 75, 4, RED);
        //Coins
        fillCircle(4, 45, 2, YELLOW);
        coin[0] = 1;
        fillCircle(18, 45, 2, YELLOW);
        coin[1] = 1;
        fillCircle(114, 42, 2, YELLOW);
        coin[2] = 1;
        fillCircle(66, 110, 2, YELLOW);
        coin[3] = 1;
        // Goal
        fillCircle(120, 111, 4, GREEN);
        break;
    case 3:
        fillRect(0, 25, 128, 103, BLACK);
        drawChar(30, 4, '3', WHITE, BLACK, 1);
        // Player Start
        x = 115;
        y = 115;
        rollx = 0;
        rolly = 0;
        // Walls
        fillRect(100, 93, 5, 34, WHITE);
        fillRect(100, 25, 5, 34, WHITE);
        fillRect(75, 59, 5, 34, WHITE);
        fillRect(50, 93, 5, 34, WHITE);
        fillRect(50, 25, 5, 34, WHITE);
        fillRect(25, 59, 5, 34, WHITE);
        // Danger Zones
        fillCircle(115, 34, 4, RED);
        fillCircle(77, 48, 4, RED);
        fillCircle(77, 106, 4, RED);
        fillCircle(28, 34, 4, RED);
        fillCircle(28, 120, 4, RED);
        // Coins
        fillCircle(77, 34, 2, YELLOW);
        coin[0] = 1;
        fillCircle(77, 120, 2, YELLOW);
        coin[1] = 1;
        fillCircle(52, 76, 2, YELLOW);
        coin[2] = 1;
        fillCircle(28, 48, 2, YELLOW);
        coin[3] = 1;
        fillCircle(28, 106, 2, YELLOW);
        coin[4] = 1;
        // Goal
        fillCircle(12, 76, 4, GREEN);
        break;
    case 4:
        fillRect(0, 25, 128, 103, BLACK);
        drawChar(30,4, '4', WHITE, BLACK, 1);
        // Player Start
        x = 115;
        y = 34;
        rollx = 0;
        rolly = 0;
        // Walls
        fillRect(96, 25, 5, 73, WHITE);
        fillRect(32, 93, 64, 5, WHITE);
        fillRect(32, 59, 5, 39, WHITE);
        fillRect(32, 59, 44, 5, WHITE);
        fillRect(64, 93, 5, 17, WHITE);
        fillRect(16, 76, 16, 5, WHITE);
        fillRect(64, 42, 5, 17, WHITE);
        // Danger Zones
        fillCircle(118, 118, 4, RED);
        fillCircle(78, 105, 4, RED);
        fillCircle(9, 118, 4, RED);
        fillCircle(55, 50, 4, RED);
        fillCircle(87, 34, 4, RED);
        // Coins
        fillCircle(55, 105, 2, YELLOW);
        coin[0] = 1;
        fillCircle(9, 34, 2, YELLOW);
        coin[1] = 1;
        fillCircle(87, 84, 2, YELLOW);
        coin[2] = 1;
        // Goal
        fillCircle(45, 76, 4, GREEN);



    }
}
void checkBounds(int xpos, int ypos, int *x, int *y, int *rollx, int *rolly, int oldx, int oldy, int *ox, int *oy, int *score, int *lives, char* scoreStr) {
    switch (level) {
    case 1:
        if (xpos > 45 && xpos < 59 && ypos > 90) {
            if (oldx <= 45) {
                *x = 45;
            } else if (oldx >= 59) {
                *x = 59;
            }
            if (oldy <= 90) {
                *y = 90;
            }
            *rollx = 0;
            *rolly = 0;
        } else if (xpos < 39 && ypos > 58 && ypos < 72) {
            if (oldy <= 58) {
                *y = 58;
            } else if (oldy >= 72) {
                *y = 72;
            }
            if (oldx >= 39) {
                *x = 39;
            }
            *rollx = 0;
            *rolly = 0;
        } else if (xpos > 45 && xpos < 59 && ypos < 49) {
            if (oldx <= 45) {
                *x = 45;
            } else if (oldx >= 59) {
                *x = 59;
            }
            if (oldy >= 49) {
                *y = 49;
            }
            *rollx = 0;
            *rolly = 0;
        } else if (xpos > 85 && xpos < 99 && ypos > 35 && ypos < 84) { // might fix
            if (oldx <= 85) {
                *x = 85;
            } else if (oldx >= 99) {
                *x = 99;
            }
            if (oldy <= 35) {
                *y = 35;
            } else if (oldy >= 84) {
                *y = 84;
            }
            *rollx = 0;
            *rolly = 0;
        } else if (xpos > 105 && ypos > 58 && ypos < 72) {
            if (oldy <= 58) {
                *y = 58;
            } else if (oldy >= 72) {
                *y = 72;
            }
            if (oldx <= 105) {
                *x = 105;
            }
            *rollx = 0;
            *rolly = 0;
        } else if (xpos > 105 && xpos < 119 && ypos > 91) {
            if (oldx <= 105) {
                *x = 105;
            } else if (oldx >=119) {
                *x = 119;
            }
            if (oldy <= 91) {
                *y = 91;
            }
            *rollx = 0;
            *rolly = 0;
        }
        // Danger Zones
        if (xpos > 12 && xpos < 28 && ypos > 34 && ypos < 50) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 15;
            *y = 111;
            *rollx = 0;
            *rolly = 0;
        }
        else if (xpos > 110 && xpos < 126 && ypos > 73 && ypos < 89) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 15;
            *y = 111;
            *rollx = 0;
            *rolly = 0;
        }
        else if (xpos > 61 && xpos < 77 && ypos > 108 && ypos < 124) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 15;
            *y = 111;
            *rollx = 0;
            *rolly = 0;
        }
        // Coins
        if (coin[0] == 1) {
            if (xpos > 29 && xpos < 43 && ypos > 23 && ypos < 37) {
                fillCircle(36, 30, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[0] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        if (coin[1] == 1) {
            if (xpos > 56 && xpos < 70 && ypos > 56 && ypos < 70) {
                fillCircle(63, 63, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[1] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        if (coin[2] == 1) {
            if (xpos > 75 && xpos < 89 && ypos > 101 && ypos < 115) {
                fillCircle(82, 108, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[2] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        // Goal
        if (xpos > 106 && xpos < 121 && ypos > 37 && ypos < 51) {
            *score += 100;
            sprintf(scoreStr, "%d", *score);
            drawString(107, 14, scoreStr, WHITE, 1);
            level++;
            renderLevel();
        }
        break;
    case 2:
        // Walls
        //fillRect(30, 90, 5, 38, WHITE);
        if (xpos > 25 && xpos < 39 && ypos > 85) {
            if (oldx <= 25) {
                *x = 25;
            } else if (oldx >= 39) {
                *x = 39;
            }
            if (oldy <= 85) {
                *y = 85;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(25, 25, 5, 42, WHITE);
        else if (xpos > 20 && xpos < 34 && ypos < 71) {
            if (oldx <= 20) {
                *x = 20;
            } else if (oldx >= 34) {
                *x = 34;
            }
            if (oldy >= 71) {
                *y = 71;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(64, 50, 5, 42, WHITE);
        else if (xpos > 59 && xpos < 73 && ypos > 45 && ypos < 96) {
            if (oldx <= 59) {
                *x = 59;
            } else if (oldx >= 73) {
                *x = 73;
            }
            if (oldy <= 45) {
                *y = 45;
            } else if (oldy >= 96) {
                *y = 96;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(100, 60, 28, 5, WHITE);
        else if (xpos > 95 && ypos > 55 && ypos < 69) {
            if (oldx <= 95) {
                *x = 95;
            }
            if (oldy <= 55) {
                *y = 55;
            }
            else if (oldy >= 69) {
                *y = 69;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(105, 95, 5, 33, WHITE);
        else if (xpos > 100 && xpos < 114 && ypos > 90) {
            if (oldx <= 100) {
                *x = 100;
            } else if (oldx >= 114) {
                *x = 114;
            }
            if (oldy <= 90) {
                *y = 90;
            }
            *rollx = 0;
            *rolly = 0;
        }
        // Danger Zones
        //fillCircle(12, 36, 4, RED);
        if (xpos > 4 && xpos < 21 && ypos > 28 && ypos < 44) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 15;
            *y = 111;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(52, 109, 4, RED);
        else if (xpos > 44 && xpos < 60 && ypos > 101 && ypos < 117) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 15;
            *y = 111;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(120, 75, 4, RED);
        else if (xpos > 112 && xpos < 128 && ypos > 67 && ypos < 83) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 15;
            *y = 111;
            *rollx = 0;
            *rolly = 0;
        }
        // Coins
        //fillCircle(4, 45, 2, YELLOW);
        if (coin[0] == 1) {
            if (xpos > 0 && xpos < 11 && ypos > 38 && ypos < 52) {
                fillCircle(4, 45, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[0] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(18, 45, 2, YELLOW);
        if (coin[1] == 1) {
            if (xpos > 11 && xpos < 25 && ypos > 38 && ypos < 52) {
                fillCircle(18, 45, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[1] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(114, 42, 2, YELLOW);
        if (coin[2] == 1) {
            if (xpos > 107 && xpos < 121 && ypos > 35 && ypos < 49) {
                fillCircle(114, 42, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[2] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(66, 110, 2, YELLOW);
        if (coin[3] == 1) {
            if (xpos > 59 && xpos < 73 && ypos > 103 && ypos < 117) {
                fillCircle(66, 110, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[3] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        // Goal
        //fillCircle(120, 111, 4, GREEN);
        if (xpos > 112 && xpos < 128 && ypos > 103 && ypos < 118) {
             *score += 100;
             sprintf(scoreStr, "%d", *score);
             drawString(107, 14, scoreStr, WHITE, 1);
             level++;
             renderLevel();
         }
        break;
    case 3:
        // Walls
        //fillRect(100, 93, 5, 34, WHITE);
        if (xpos > 95 && xpos < 109 && ypos > 88) {
            if (oldx <= 95) {
                *x = 95;
            } else if (oldx >= 109) {
                *x = 109;
            }
            if (oldy <= 88) {
                *y = 88;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(100, 25, 5, 34, WHITE);
        else if (xpos > 95 && xpos < 109 && ypos < 63) {
            if (oldx <= 95) {
                *x = 95;
            } else if (oldx >= 109) {
                *x = 109;
            }
            if (oldy >= 63) {
                *y = 63;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(75, 59, 5, 34, WHITE);
        else if (xpos > 70 && xpos < 84 && ypos > 54 && ypos < 97) {
            if (oldx <= 70) {
                *x = 70;
            } else if (oldx >= 84) {
                *x = 84;
            }
            if (oldy <= 54) {
                *y = 54;
            } else if (oldy >= 97) {
                *y = 97;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(50, 93, 5, 34, WHITE);
        else if (xpos > 45 && xpos < 59 && ypos > 88) {
            if (oldx <= 45) {
                *x = 45;
            } else if (oldx >= 59) {
                *x = 59;
            }
            if (oldy <= 88) {
                *y = 88;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(50, 25, 5, 34, WHITE);
        else if (xpos > 45 && xpos < 59 && ypos < 63) {
            if (oldx <= 45) {
                *x = 45;
            } else if (oldx >= 59) {
                *x = 59;
            }
            if (oldy >= 63) {
                *y = 63;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(25, 59, 5, 34, WHITE);
        else if (xpos > 20 && xpos < 34 && ypos > 54 && ypos < 97) {
            if (oldx <= 20) {
                *x = 20;
            } else if (oldx >= 34) {
                *x = 34;
            }
            if (oldy <= 54) {
                *y = 54;
            } else if (oldy >= 97) {
                *y = 97;
            }
            *rollx = 0;
            *rolly = 0;
        }
        // Danger Zones
        //fillCircle(115, 34, 4, RED);
        if (xpos > 107 && xpos < 123 && ypos > 26 && ypos < 42) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 115;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(78, 48, 4, RED);
        else if (xpos > 70 && xpos < 86 && ypos > 40 && ypos < 56) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 115;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(78, 106, 4, RED);
        else if (xpos > 70 && xpos < 86 && ypos > 98 && ypos < 114) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 111;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(28, 34, 4, RED);
        else if (xpos > 20 && xpos < 36 && ypos > 26 && ypos < 42) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 115;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(28, 120, 4, RED);
        else if (xpos > 20 && xpos < 36 && ypos > 112 && ypos < 128) {
            //*lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            //drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 115;
            *rollx = 0;
            *rolly = 0;
        }
        // Coins
        //fillCircle(77, 34, 2, YELLOW);
        if (coin[0] == 1) {
            if (xpos > 70 && xpos < 84 && ypos > 27 && ypos < 41) {
                fillCircle(77, 34, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[0] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(77, 120, 2, YELLOW);
        if (coin[1] == 1) {
            if (xpos > 70 && xpos < 84 && ypos > 113 && ypos < 127) {
                fillCircle(77, 120, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[1] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(52, 76, 2, YELLOW);
        if (coin[2] == 1) {
            if (xpos > 45 && xpos < 59 && ypos > 69 && ypos < 84) {
                fillCircle(52, 76, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[2] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(28, 48, 2, YELLOW);
        if (coin[3] == 1) {
            if (xpos > 21 && xpos < 35 && ypos > 41 && ypos < 55) {
                fillCircle(28, 48, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[3] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(28, 106, 2, YELLOW);
        if (coin[4] == 1) {
            if (xpos > 21 && xpos < 35 && ypos > 99 && ypos < 113) {
                fillCircle(28, 106, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[4] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        // Goal
        //fillCircle(12, 76, 4, GREEN);
        if (xpos > 4 && xpos < 20 && ypos > 68 && ypos < 84) {
             *score += 100;
             sprintf(scoreStr, "%d", *score);
             drawString(107, 14, scoreStr, WHITE, 1);
             *ox = 115;
             *oy = 34;
             level++;
             renderLevel();
         }
        break;

    case 4:
        // Walls
        //fillRect(96, 25, 5, 73, WHITE);
        if (xpos > 91 && xpos < 105 && ypos < 102) {
            if (oldx <= 91) {
                *x = 91;
            } else if (oldx >= 105) {
                *x = 105;
            }
            if (oldy >= 102) {
                *y = 102;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(32, 93, 64, 5, WHITE);
        else if (xpos > 27 && xpos < 100 && ypos > 88 && ypos < 102) {
            if (oldx <= 27) {
                *x = 27;
            } else if (oldx >= 100) {
                *x = 100;
            }
            if (oldy <= 88) {
                *y = 88;
            }
            else if (oldy >= 102) {
                *y = 102;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(32, 59, 5, 39, WHITE);
        if (xpos > 27 && xpos < 41 && ypos > 55 && ypos < 98) {
            if (oldx <= 27) {
                *x = 27;
            } else if (oldx >= 41) {
                *x = 41;
            }
            if (oldy <= 55) {
                *y = 55;
            }
            else if (oldy >= 102) {
                *y = 102;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(32, 59, 44, 5, WHITE);
        if (xpos > 27 && xpos < 80 && ypos > 54 && ypos < 68) {
            if (oldx <= 27) {
                *x = 27;
            } else if (oldx >= 80) {
                *x = 80;
            }
            if (oldy <= 54) {
                *y = 54;
            }
            else if (oldy >= 68) {
                *y = 68;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(64, 93, 5, 17, WHITE);
        if (xpos > 59 && xpos < 73 && ypos > 93 && ypos < 114) {
            if (oldx <= 59) {
                *x = 59;
            } else if (oldx >= 73) {
                *x = 73;
            }
            if (oldy <= 93) {
                *y = 93;
            }
            else if (oldy >= 114) {
                *y = 114;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(16, 76, 16, 5, WHITE);
        if (xpos > 11 && xpos < 32 && ypos > 71 && ypos < 85) {
            if (oldx <= 11) {
                *x = 11;
            } else if (oldx >= 32) {
                *x = 32;
            }
            if (oldy <= 71) {
                *y = 71;
            }
            else if (oldy >= 85) {
                *y = 85;
            }
            *rollx = 0;
            *rolly = 0;
        }
        //fillRect(64, 42, 5, 17, WHITE);
        if (xpos > 59 && xpos < 73 && ypos > 37 && ypos < 63) {
            if (oldx <= 59) {
                *x = 59;
            } else if (oldx >= 73) {
                *x = 73;
            }
            if (oldy <= 37) {
                *y = 37;
            }
            else if (oldy >= 63) {
                *y = 63;
            }
            *rollx = 0;
            *rolly = 0;
        }
        // Danger Zones
        //fillCircle(118, 118, 4, RED);
        if (xpos > 110 && xpos < 126 && ypos > 110 && ypos < 126) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 34;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(78, 105, 4, RED);
        if (xpos > 70 && xpos < 86 && ypos > 97 && ypos < 113) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 34;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(9, 118, 4, RED);
        if (xpos > 1 && xpos < 17 && ypos > 110 && ypos < 126) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 34;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(55, 50, 4, RED);
        if (xpos > 47 && xpos < 63 && ypos > 42 && ypos < 58) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 34;
            *rollx = 0;
            *rolly = 0;
        }
        //fillCircle(87, 34, 4, RED);
        if (xpos > 79 && xpos < 95 && ypos > 26 && ypos < 42) {
            *lives -= 1;
            Report("Ouch! Lives = %d\n\r", *lives);
            drawCircle(34 + (10 * *lives), 17, 4, BLACK);
            *x = 115;
            *y = 34;
            *rollx = 0;
            *rolly = 0;
        }
        // Coins
        //fillCircle(55, 105, 2, YELLOW);
        if (coin[0] == 1) {
            if (xpos > 48 && xpos < 62 && ypos > 98 && ypos < 112) {
                fillCircle(55, 105, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[0] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(9, 34, 2, YELLOW);
        if (coin[1] == 1) {
            if (xpos > 2 && xpos < 16 && ypos > 27 && ypos < 41) {
                fillCircle(9, 34, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[1] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //fillCircle(87, 84, 2, YELLOW);
        if (coin[2] == 1) {
            if (xpos > 80 && xpos < 94 && ypos > 77 && ypos < 91) {
                fillCircle(87, 84, 2, BLACK);
                *score += 10;
                sprintf(scoreStr, "%d", *score);
                coin[2] = 0;
                drawString(107, 14, scoreStr, WHITE, 1);
            }
        }
        //Goal
        //fillCircle(45, 76, 4, GREEN);
        if (xpos > 37 && xpos < 52 && ypos > 69 && ypos < 83) {
             *score += 100;
             sprintf(scoreStr, "%d", *score);
             drawString(107, 14, scoreStr, WHITE, 1);
             *ox = 10;
             *oy = 111;
             level = 1;
             renderLevel();
         }
        break;

    }
}

void game() {
    unsigned char ucDevAddr = 0x18;
    unsigned char ucRegOffsetX = 0x3;
    unsigned char ucRegOffsetY = 0x5;
    unsigned char aucRdDataBufX[256];
    unsigned char aucRdDataBufY[256];
    int score = 0;
    int lives = 3;
    char scoreStr[50];


    int high_score = get_setup();
    Report("HighScore:%d\n\r", high_score);
    sprintf(scoreStr, "HighScore:%d", high_score);
    drawLine(0, 24, 127, 24, WHITE);
    drawString(0, 4, "Level:", WHITE, 1);
    drawString(57, 4, scoreStr, WHITE, 1);
    drawString(0, 14, "Lives:", WHITE, 1);
    int i;
    int cx = 34;
    for (i = 0; i < lives; i++) {
        drawCircle(cx,17,4,WHITE);
        cx += 10;
    }
    drawString(77, 14, "Score:0", WHITE, 1);
    sprintf(scoreStr, "%d", score);


    renderLevel();

    while(lives != 0)
    {
        // Draw circle
        drawCircle(x,y,4,WHITE);

        // Read x tilt
        I2C_IF_Write(ucDevAddr, &ucRegOffsetX, 1, 0);
        I2C_IF_Read(ucDevAddr, &aucRdDataBufX[0], 1);

        // Read y tilt
        I2C_IF_Write(ucDevAddr, &ucRegOffsetY, 1, 0);
        I2C_IF_Read(ucDevAddr, &aucRdDataBufY[0], 1);

        // Set dx and dy (change accordingly to how it appears when connected)
        // divide by 4 for no movement at no tilt
        int dy = ((signed char)aucRdDataBufX[0])/4;
        int dx = ((signed char)aucRdDataBufY[0])/4;
        dy = dy*4;
        dx = dx*4;

        // Set old position
        int oldx = x;
        int oldy = y;

        // Change x and y coordinates
        // With Roll
        x = x + ((dx + rollx)/6);
        y = y + ((dy + rolly)/6);

        rollx = rollx/1.025 + dx/2.5;
        rolly = rolly/1.025 + dy/2.5;

        // Without Roll
        //x = x + (dx/4);
        //y = y + (dy/4);

        // Bounds
        if (x > 122) {
            x = 122;
            rollx = 0;
        }
        if (x < 4) {
            x = 4;
            rollx = 0;
        }
        if (y > 122) {
            y = 122;
            rolly = 0;
        }
        if (y < 29) {
            y = 29;
            rolly = 0;
        }

        checkBounds(x, y, &x, &y, &rollx, &rolly, oldx, oldy, &oldx, &oldy, &score, &lives, scoreStr);

        Report("x: %d, y: %d \n\r", x, y);
        //Report("dx: %d, dy: %d \n\r", dx, dy);
        //Report("level: %d \n\r", level);
        //Report("rollx: %d, rolly: %d \n\r", rollx, rolly);

        // Erase last position
        drawCircle(oldx,oldy,4,BLACK);
    }
    drawString(25, 45, "Game Over", RED, 2);
    sprintf(scoreStr, "Score:%d", score);
    drawString(25, 65, scoreStr, BLUE, 2);
    if (score > high_score) {
        high_score = score;
        drawString(15, 85, "High Score!", GREEN, 2);
    }
    post_setup(score, high_score);
}

//*****************************************************************************
//
//! Main 
//!
//! \param  none
//!
//! \return None
//!
//*****************************************************************************
void main() {
    //
    // Initialize board configuration
    //
    BoardInit();

    PinMuxConfig();

    InitTerm();
    ClearTerm();
    UART_PRINT("Hello world!\n\r");

    // I2C Init
    //
    I2C_IF_Open(I2C_MASTER_MODE_FST);

    //
    // Display the banner followed by the usage description
    //
    // Enable the SPI module clock
    MAP_PRCMPeripheralClkEnable(PRCM_GSPI,PRCM_RUN_MODE_CLK);

    // Reset SPI
    MAP_SPIReset(GSPI_BASE);

    // Configure SPI interface
    MAP_SPIConfigSetExpClk(GSPI_BASE,MAP_PRCMPeripheralClockGet(PRCM_GSPI),
                     SPI_IF_BIT_RATE,SPI_MODE_MASTER,SPI_SUB_MODE_0,
                     (SPI_SW_CTRL_CS |
                     SPI_4PIN_MODE |
                     SPI_TURBO_OFF |
                     SPI_CS_ACTIVELOW |
                     SPI_WL_8));

    // Enable SPI for communication
    MAP_SPIEnable(GSPI_BASE);

    // Initialize the OLED
    Adafruit_Init();
    fillScreen(BLACK);
    game();

}
//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//*****************************************************************************
int get_setup() {
    long lRetVal = -1;
    //Connect the CC3200 to the local access point
    lRetVal = connectToAccessPoint();
    //Set time so that encryption can be used
    lRetVal = set_time();
    if(lRetVal < 0) {
        UART_PRINT("Unable to set time in the device");
        return 10;
    }
    //Connect to the website with TLS encryption
    lRetVal = tls_connect();
    if(lRetVal < 0) {
        ERR_PRINT(lRetVal);
        return 10;
    }
    int score = http_get(lRetVal);
    sl_Stop(SL_STOP_TIMEOUT);
    return score;
}
void post_setup(int score, int high_score) {
    long lRetVal = -1;
    //Connect the CC3200 to the local access point
    lRetVal = connectToAccessPoint();
    //Set time so that encryption can be used
    lRetVal = set_time();
    if(lRetVal < 0) {
        UART_PRINT("Unable to set time in the device");
    }
    //Connect to the website with TLS encryption
    lRetVal = tls_connect();
    if(lRetVal < 0) {
        ERR_PRINT(lRetVal);
    }
    http_post(lRetVal, score, high_score);
    sl_Stop(SL_STOP_TIMEOUT);

}
static int http_post(int iTLSSockID, int score, int high_score){
    char acSendBuff[512];
    char acRecvbuff[1460];
    char cCLLength[200];
    char* pcBufHeaders;
    int lRetVal = 0;

    char DATASend[1000];
    sprintf(DATASend, DATA1, score, high_score, score, high_score, score, high_score);

    pcBufHeaders = acSendBuff;
    strcpy(pcBufHeaders, POSTHEADER);
    pcBufHeaders += strlen(POSTHEADER);
    strcpy(pcBufHeaders, HOSTHEADER);
    pcBufHeaders += strlen(HOSTHEADER);
    strcpy(pcBufHeaders, CHEADER);
    pcBufHeaders += strlen(CHEADER);
    strcpy(pcBufHeaders, "\r\n\r\n");

    int dataLength = strlen(DATASend);

    strcpy(pcBufHeaders, CTHEADER);
    pcBufHeaders += strlen(CTHEADER);
    strcpy(pcBufHeaders, CLHEADER1);

    pcBufHeaders += strlen(CLHEADER1);
    sprintf(cCLLength, "%d", dataLength);

    strcpy(pcBufHeaders, cCLLength);
    pcBufHeaders += strlen(cCLLength);
    strcpy(pcBufHeaders, CLHEADER2);
    pcBufHeaders += strlen(CLHEADER2);

    strcpy(pcBufHeaders, DATASend);
    pcBufHeaders += strlen(DATASend);

    int testDataLength = strlen(pcBufHeaders);

    UART_PRINT(acSendBuff);


    //
    // Send the packet to the server */
    //
    lRetVal = sl_Send(iTLSSockID, acSendBuff, strlen(acSendBuff), 0);
    if(lRetVal < 0) {
        UART_PRINT("POST failed. Error Number: %i\n\r",lRetVal);
        sl_Close(iTLSSockID);
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }
    lRetVal = sl_Recv(iTLSSockID, &acRecvbuff[0], sizeof(acRecvbuff), 0);
    if(lRetVal < 0) {
        UART_PRINT("Received failed. Error Number: %i\n\r",lRetVal);
        //sl_Close(iSSLSockID);
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
           return lRetVal;
    }
    else {
        acRecvbuff[lRetVal+1] = '\0';
        UART_PRINT(acRecvbuff);
        UART_PRINT("\n\r\n\r");
    }

    return 0;
}
static int http_get(int iTLSSockID){
    char acSendBuff[512];
    char acRecvbuff[1460];
    char* pcBufHeaders;
    int lRetVal = 0;

    pcBufHeaders = acSendBuff;
    strcpy(pcBufHeaders, GETHEADER);
    pcBufHeaders += strlen(GETHEADER);
    strcpy(pcBufHeaders, HOSTHEADER);
    pcBufHeaders += strlen(HOSTHEADER);
    strcpy(pcBufHeaders, CHEADER);
    pcBufHeaders += strlen(CHEADER);
    strcpy(pcBufHeaders, "\r\n\r\n");

    int testDataLength = strlen(pcBufHeaders);

    UART_PRINT(acSendBuff);

    //
    // Send the packet to the server */
    //
    lRetVal = sl_Send(iTLSSockID, acSendBuff, strlen(acSendBuff), 0);
    if(lRetVal < 0) {
        UART_PRINT("POST failed. Error Number: %i\n\r",lRetVal);
        sl_Close(iTLSSockID);
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }
    lRetVal = sl_Recv(iTLSSockID, &acRecvbuff[0], sizeof(acRecvbuff), 0);
    if(lRetVal < 0) {
        UART_PRINT("Received failed. Error Number: %i\n\r",lRetVal);
        //sl_Close(iSSLSockID);
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
           return lRetVal;
    }
    else {
        acRecvbuff[lRetVal+1] = '\0';
        char* scoreString = strstr(acRecvbuff, "High Score ");
        char* str = scoreString + strlen("High Score ");
        int score;
        sscanf(str, "%d", &score);
        return score;
    }
}
