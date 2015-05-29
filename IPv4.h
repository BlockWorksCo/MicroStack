//
// Copyright (C) BlockWorks Consulting Ltd - All Rights Reserved.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Proprietary and confidential.
// Written by Steve Tickle <Steve@BlockWorks.co>, September 2014.
//







#ifndef __IPV4_H__
#define __IPV4_H__


//
// Generic public IP definitions.
//
struct IP
{       
    //
    // IANA specified IP protocol numbers.
    // See: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    //
    typedef enum
    {
        ICMP    = 1,
        TCP     = 6,
        UDP     = 17,

    } ProtocolType;    

    //
    //
    //
    typedef struct
    {
        uint32_t    sourceIP;
        uint32_t    destinationIP;
        uint16_t    length;

    } ConnectionState;
};




//
// IPv4 class:
// Provides all the functionality of the IPv4/internet layer.
//
template <  typename LoggerType,
            typename StackType, 
            uint32_t IPAddress,
            void newPacket(IP::ProtocolType),
            PacketProcessingState layerState(IP::ProtocolType),
            void pushIntoLayer(IP::ProtocolType, uint8_t), 
            uint8_t pullFromLayer(IP::ProtocolType, bool&,  uint16_t),
            uint32_t destinationIP(IP::ProtocolType),
            uint16_t packetLength(IP::ProtocolType),
            IP::ConnectionState& connectionState(IP::ProtocolType)
            >
class IPv4
{
    //
    // Break out the StackType helper types.
    //
    STACK_TYPES_BREAKOUT;


public:

    //
    // Constructor for the IPv4 layer. 
    // Simply resets the stack right now.
    //
    IPv4() :
        packetState(Unknown)
    {
    }

    //
    // Idle:
    // Provided for general timing/timeout behaviour.
    //
    void Idle()
    {
        LoggerType::printf("(IPv4) Idle.\n");
    }

    //
    // Reset the packet detector.
    //
    void NewPacket()
    {
        position        = 0;
        packetState     = Unknown;

        LoggerType::printf("\n\n-->NewPacket:\n");
    }

    //
    // Push some received data into this packet processor...
    //
    void PushInto(uint8_t byte)
    {
        //
        // Header portion of the packet.
        //
        switch(position)
        {
            case 0:
                if( byte == 0x45)
                {
                    LoggerType::printf("(IPv4) Claimed, Header Length = %x.\n", byte&0xf);
                    packetState   = Claimed;
                }
                else
                {
                    LoggerType::printf("(IPv4) Rejected.\n");
                    packetState   = Rejected;
                }
                break;


            case 1:
                // DSCP
                break;

            case 2:
                rxLength  = byte<<8;
                break;

            case 3:
                rxLength  |= byte;
                LoggerType::printf("(IPv4) Packet Length = %d\n", rxLength);
                break;

            case 4:
                // Identification field
                break;

            case 5:
                // Identification field
                break;

            case 6:
                fragmentOffset  = (byte & 0x1f) << 8;
                fragmentFlags   = (byte & 0xe0) >> 5;
                LoggerType::printf("(IPv4) Fragment flags: %d\n", fragmentFlags);
                break;

            case 7:
                fragmentOffset    |= byte;                
                LoggerType::printf("(IPv4) Fragment offset: %d\n", fragmentOffset);

                if(fragmentFlags != 2)
                {
                    //
                    // We don't support fragmentation yet...
                    //
                    packetState     = Rejected;
                }
                break;

            case 8:
                LoggerType::printf("(IPv4) TTL: %d\n",byte);
                break;

            case 9:
                protocol    = static_cast<IP::ProtocolType>(byte);
                LoggerType::printf("(IPv4) Protocol: %d\n",byte);

                //
                // Now we know what protocol we have, we can bring in the upper layers to store state.
                //
                connectionState(protocol).length    = rxLength - sizeofIPHeader;

                break;

            case 10:
                headerChecksum  = byte << 8;
                break;

            case 11:
                headerChecksum  |= byte;
                LoggerType::printf("(IPv4) headerChecksum: %04x\n", headerChecksum);
                break;

            case 12:
                sourceIP    = byte << 24;
                break;

            case 13:
                sourceIP    |= byte<<16;
                break;

            case 14:
                sourceIP    |= byte<<8;
                break;

            case 15:
                sourceIP    |= byte;
                connectionState(protocol).sourceIP  = sourceIP;
                LoggerType::printf("(IPv4) SourceIP: %08x\n", sourceIP);
                break;

            case 16:
                if( byte != ((IPAddress>>24)&0xff) )
                {
                    Reject();
                }
                break;

            case 17:
                if( byte != ((IPAddress>>16)&0xff) )
                {
                    Reject();
                }
                break;

            case 18:
                if( byte != ((IPAddress>>8)&0xff) )
                {
                    Reject();
                }
                break;

            case 19:
                if( byte != (IPAddress&0xff) )
                {
                    Reject();
                }
                else
                {
                    connectionState(protocol).destinationIP  = IPAddress;
                    LoggerType::printf("DestIP: %08x\n", IPAddress);
                }
                break;

            case 20:
                LoggerType::printf("(IPv4) TransportDataStart.\n");
                newPacket(protocol);
                // Fallthrough intended.
            default:
                LoggerType::printf("(IPv4) data.\n");

                //
                // Data portion of the IP packet.
                //
                PacketProcessingState state   = layerState(protocol);
                if(state != Rejected)
                {
                    pushIntoLayer(protocol, byte);
                }
                
                break;
        }
            

        //
        // Ready for next byte.
        //
        position++;
    }

    //
    //
    //
    PacketProcessingState State()
    {
        return packetState;
    }


    //
    //
    //
    void UpdateAccumulatedChecksum(uint16_t value)
    {
        accumulatedChecksum     += value;
        if( accumulatedChecksum > 0xffff )
        {
            accumulatedChecksum -= 0xffff;
        }
    }


    //
    // Pull some packet data out of the processor for transmission.
    //
    uint8_t PullFrom(bool& dataAvailable, uint16_t position)
    {
        uint8_t         byteToTransmit          = 0x00;

        const uint8_t   versionAndIHL           = (0x04 << 4)| (sizeofIPHeader/4);          // IPv4 + 20 byte header.
        const uint8_t   DSCP                    = 0x00;                                     // ununsed.
        uint16_t        length                  = packetLength(protocol)+sizeofIPHeader;    // unknown. Assume a constant size greater than the actual size and pad with zeroes. Checksum is not affected by zeroes.
        const uint16_t  fragmentationID         = 0x1234;                                   // unused.
        const uint8_t   fragmentationFlags      = 0x40;                                     // Dont Fragment.
        const uint8_t   fragmentationOffset     = 0x00;                                     // unused.
        const uint8_t   TTL                     = 64;                                       // Seconds/hops
        IP::ProtocolType protocol               = IP::TCP;                                  // 6=TCP, 11=UDP, etc...
        uint32_t        destIP                  = destinationIP(protocol);                  // target... dynamic.


        if( position < sizeofIPHeader )
        {

            dataAvailable   = true;

            switch(position)
            {
                case 0:
                    byteToTransmit      = versionAndIHL;
                    break;

                case 1:
                    byteToTransmit      = DSCP;
                    break;

                case 2:
                    byteToTransmit      = length >> 8;
                    break;

                case 3:
                    byteToTransmit      = length & 0xff;
                    break;

                case 4:
                    byteToTransmit      = fragmentationID >> 8;
                    break;

                case 5:
                    byteToTransmit      = fragmentationID & 0xff;
                    break;

                case 6:
                    byteToTransmit      = fragmentationFlags; 
                    break;

                case 7:
                    byteToTransmit      = fragmentationOffset;
                    break;

                case 8:
                    byteToTransmit      = TTL;
                    break;

                case 9:
                    byteToTransmit      = protocol;
                    break;

                case 10:

                    accumulatedChecksum     = 0;                    
                    UpdateAccumulatedChecksum( ( ((uint16_t)versionAndIHL<<8) | (uint16_t)DSCP) );
                    UpdateAccumulatedChecksum( length );
                    UpdateAccumulatedChecksum( fragmentationID );
                    UpdateAccumulatedChecksum( (( ((uint16_t)fragmentationFlags)<<8) | (uint16_t)fragmentationOffset) );
                    UpdateAccumulatedChecksum( (( ((uint16_t)TTL)<<8) | (uint16_t)protocol) );
                    UpdateAccumulatedChecksum( (uint16_t)(IPAddress >> 16) );
                    UpdateAccumulatedChecksum( (uint16_t)(IPAddress & 0xffff) );
                    UpdateAccumulatedChecksum( (uint16_t)(destIP >> 16) );
                    UpdateAccumulatedChecksum( (uint16_t)(destIP & 0xffff) );
                    accumulatedChecksum    = ~accumulatedChecksum;

                    byteToTransmit      = accumulatedChecksum >> 8;
                    break;

                case 11:
                    byteToTransmit      = accumulatedChecksum & 0xff;
                    break;

                case 12:
                    byteToTransmit      = IPAddress >> 24;
                    break;

                case 13:
                    byteToTransmit      = (IPAddress >> 16) & 0xff;
                    break;

                case 14:
                    byteToTransmit      = (IPAddress >> 8) & 0xff;
                    break;

                case 15:
                    byteToTransmit      = IPAddress & 0xff;
                    break;

                case 16:
                    byteToTransmit      = destIP >> 24;
                    break;

                case 17:
                    byteToTransmit      = (destIP >> 16) & 0xff;
                    break;

                case 18:
                    byteToTransmit      = (destIP >> 8) & 0xff;
                    break;

                case 19:
                    byteToTransmit      = destIP & 0xff;
                    break;

                default:
                    break;
            }
        }
        else
        {
            //
            // Not the header, lets pull the data from the layer above...
            //
            byteToTransmit  = pullFromLayer(protocol, dataAvailable, position-sizeofIPHeader );            
        }

        return byteToTransmit;
    }


private:

    //
    // Set the current packet as rejected.
    //
    void Reject()
    {
        packetState     = Rejected;
    }



    //
    //
    //
    typedef struct
    {
        IP::ProtocolType  protocol;
        uint32_t        ip;    

    } PacketState;


    const uint16_t  sizeofIPHeader          = 20;                                       // standard/minimum size.

    //
    //
    //
    uint16_t                position;
    PacketProcessingState   packetState;

    uint32_t                accumulatedChecksum;

    uint16_t                fragmentOffset;
    uint8_t                 fragmentFlags;
    uint16_t                headerChecksum;
    uint32_t                sourceIP;
    IP::ProtocolType        protocol;

    uint16_t                rxLength;

};





#endif



