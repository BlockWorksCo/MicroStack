//
// Copyright (C) BlockWorks Consulting Ltd - All Rights Reserved.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Proprietary and confidential.
// Written by Steve Tickle <Steve@BlockWorks.co>, September 2014.
//





#ifndef __APPCONFIGURATION_H__
#define __APPCONFIGURATION_H__






//
// Break out the CombinationTypes for this class.
//
#define STACK_TYPES_BREAKOUT    \
    typedef typename StackType::ApplicationLayerType    ApplicationLayerType;   \
    typedef typename StackType::TCPTransportLayerType   TCPTransportLayerType;  \
    typedef typename StackType::UDPTransportLayerType   UDPTransportLayerType;  \
    typedef typename StackType::ICMPTransportLayerType  ICMPTransportLayerType; \
    typedef typename StackType::ARPTransportLayerType   ARPTransportLayerType;  \
    typedef typename StackType::InternetLayerType       InternetLayerType;      \
    typedef typename StackType::LinkLayerType           LinkLayerType;



//
// TODO: put somewhere proper.
//
typedef enum 
{
    Unknown,
    Claimed,
    Rejected,

} PacketProcessingState;


#include <stdint.h>

#include "TUN.h"
#include "PCAP.h"
#include "PCAPStream.h"
#include "IPv4.h"
#include "TCP.h"
#include "UDP.h"
#include "ARP.h"
#include "ICMP.h"
#include "HelloWorldPageGenerator.h"
#include "StdoutLog.h"
#include "NullLog.h"


typedef StdoutLog<128>      LoggerType;
typedef NullLog<1>          NullLoggerType;

const uint32_t      IPAddress       = 0xc0a802fd;


struct StackType
{
    //
    // 
    //
    static void IPv4NewPacket(IP::ProtocolType protocolType);
    static PacketProcessingState IPv4LayerState(IP::ProtocolType protocolType);
    static void IPv4PushIntoLayer(IP::ProtocolType protocolType, uint8_t byte);
    static uint8_t IPv4PullFromLayer(IP::ProtocolType protocolType, bool& dataAvailable,  uint16_t position);
    static IP::ConnectionState& IPv4ConnectionState(IP::ProtocolType protocolType);

    static void LinkIdle();
    static void LinkNewPacket();
    static PacketProcessingState LinkLayerState();
    static void LinkPushIntoLayer(uint8_t byte);
    static uint8_t LinkPullFromLayer(bool& dataAvailable,  uint16_t position);
    static uint32_t DestinationIP(IP::ProtocolType protocol);
    static uint16_t PacketLength(IP::ProtocolType protocol);

    typedef HelloWorldPageGenerator<LoggerType,    
                                    StackType>  ApplicationLayerType;
    typedef TCP<    LoggerType,
                    StackType,
                    IPAddress>                  TCPTransportLayerType;
    typedef UDP<    LoggerType,
                    StackType>                  UDPTransportLayerType;
    typedef IPv4<   LoggerType,
                    StackType, 
                    IPAddress, 
                    IPv4NewPacket, 
                    IPv4LayerState, 
                    IPv4PushIntoLayer, 
                    IPv4PullFromLayer,
                    DestinationIP,
                    PacketLength,
                    IPv4ConnectionState >       InternetLayerType;
    typedef PCAPStream<   
                    LoggerType,
                    StackType,
                    LinkIdle,
                    LinkNewPacket, 
                    LinkLayerState, 
                    LinkPushIntoLayer, 
                    LinkPullFromLayer >         LinkLayerType;
    typedef ARP<    NullLoggerType, 
                    StackType>                  ARPTransportLayerType;
    typedef ICMP<   LoggerType,
                    StackType>                  ICMPTransportLayerType;
};



#endif



