//
// Copyright (C) BlockWorks Consulting Ltd - All Rights Reserved.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Proprietary and confidential.
// Written by Steve Tickle <Steve@BlockWorks.co>, September 2014.
//






#include "AppConfiguration.h"
#include "Utilities.h"


volatile uint32_t    panicCode   = 0;

//
// Instantiations.
//
StackType::UDPTransportLayerType   udpLayer;
StackType::ICMPTransportLayerType  icmpLayer;
StackType::ApplicationLayerType    tcpApplicationLayer;
StackType::ARPTransportLayerType   arpLayer;
StackType::TCPTransportLayerType   tcpLayer(tcpApplicationLayer);
StackType::InternetLayerType       internetLayer;
StackType::LinkLayerType           linkLayer;


//
// IPv4->TCP,UDP,ICMP coupling.
//
void StackType::IPv4NewPacket(IP::ProtocolType protocolType)
{
    switch(protocolType) { case IP::TCP:tcpLayer.NewPacket();break; case IP::UDP:udpLayer.NewPacket();break; case IP::ICMP:icmpLayer.NewPacket();break; }
}

PacketProcessingState StackType::IPv4LayerState(IP::ProtocolType protocolType)
{
    switch(protocolType) { case IP::TCP: return tcpLayer.State();break; case IP::UDP: return udpLayer.State();break; case IP::ICMP:return icmpLayer.State();break; default:return Rejected;break;}
}

void StackType::IPv4PushIntoLayer(IP::ProtocolType protocolType, uint8_t byte)
{
    switch(protocolType) { case IP::TCP:tcpLayer.PushInto(byte);break; case IP::UDP:udpLayer.PushInto(byte);break; case IP::ICMP:icmpLayer.PushInto(byte);break; }     
}

uint8_t StackType::IPv4PullFromLayer(IP::ProtocolType protocolType, bool& dataAvailable,  uint16_t position)
{ 
    switch(protocolType) {case IP::TCP:return tcpLayer.PullFrom(dataAvailable,position);break;  case IP::UDP:return udpLayer.PullFrom(dataAvailable,position);break; case IP::ICMP:return icmpLayer.PullFrom(dataAvailable,position);break; default:dataAvailable=false;return 0;break;}
} 

uint32_t StackType::DestinationIP(IP::ProtocolType protocolType)
{
    switch(protocolType) { case IP::TCP: return tcpLayer.DestinationIP();break; case IP::UDP: return udpLayer.DestinationIP();break; case IP::ICMP:return icmpLayer.DestinationIP();break; default:return 0x00000000;break;}
}

uint16_t StackType::PacketLength(IP::ProtocolType protocolType)
{
    switch(protocolType) { case IP::TCP: return tcpLayer.PacketLength();break; case IP::UDP: return udpLayer.PacketLength();break; case IP::ICMP:return icmpLayer.PacketLength();break; default:return 0;break;}
}

IP::ConnectionState& StackType::IPv4ConnectionState(IP::ProtocolType protocolType)
{
    switch(protocolType) { case IP::TCP: return tcpLayer.ConnectionState();break; case IP::UDP: return udpLayer.ConnectionState();break; case IP::ICMP:return icmpLayer.ConnectionState();break; default:PANIC(1);break;}    
}



//
// Link->IPv4,ARP coupling.
//
void StackType::LinkIdle()
{
    internetLayer.Idle();    
    arpLayer.Idle();
}

void StackType::LinkNewPacket()
{
    internetLayer.NewPacket();    
    arpLayer.NewPacket();
}

PacketProcessingState StackType::LinkLayerState()
{
    arpLayer.State();
    return internetLayer.State();
}

void StackType::LinkPushIntoLayer(uint8_t byte)
{
    internetLayer.PushInto(byte);
    arpLayer.PushInto(byte);
}

uint8_t StackType::LinkPullFromLayer(bool& dataAvailable,  uint16_t position)
{ 
    arpLayer.PullFrom(dataAvailable, position);
    return internetLayer.PullFrom(dataAvailable, position);
} 


//
//
//
int main(int argc, char **argv)
{
    printf("\nBLOCK::WORKS IPStack Demo\n");

    linkLayer.SetFileNames(argv[1], argv[2]);

    while(true)
    {
        linkLayer.Iterate();    
    }

    return 0;
}

