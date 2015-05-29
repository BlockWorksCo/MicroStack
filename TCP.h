//
// Copyright (C) BlockWorks Consulting Ltd - All Rights Reserved.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Proprietary and confidential.
// Written by Steve Tickle <Steve@BlockWorks.co>, September 2014.
//








#ifndef __TCP_H__
#define __TCP_H__





//
// Generic public IP definitions.
//
struct TCPIP
{       

    typedef enum
    {
        TCP_NONE          = 0x00,

        TCP_FIN           = 0x01,
        TCP_SYN           = 0x02,
        TCP_RST           = 0x04,
        TCP_PSH           = 0x08,
        TCP_ACK           = 0x10,
        TCP_URG           = 0x20,        

        TCP_ECE           = 0x40,        
        TCP_CWR           = 0x80,        

    } TCPFlags;


    typedef enum
    {
        CLOSED            = 0,
        LISTEN            = 1,
        SYN_SENT          = 2,
        SYN_RCVD          = 3,
        ESTABLISHED       = 4,
        FIN_WAIT_1        = 5,
        FIN_WAIT_2        = 6,
        CLOSE_WAIT        = 7,
        CLOSING           = 8,
        LAST_ACK          = 9,
        TIME_WAIT         = 10,    

    } TCPState;


    //
    //
    //
    typedef struct
    {
        IP::ConnectionState     ipState;

        uint16_t                position;
        PacketProcessingState   packetState;

        uint32_t                accumulatedChecksum;

        uint16_t                sourcePort;
        uint16_t                destinationPort;
        uint32_t                sequenceNumber;
        uint32_t                ackNumber;
        TCPFlags                flags;
        uint16_t                windowSize;
        uint16_t                checksum;
        uint16_t                urgentPointer;
        uint8_t                 dataOffset;

        TCPFlags                packetToSend;
        TCPState                nextTCPState;  

    } ConnectionState;
};




//
//
//
template <  typename LoggerType,
            typename StackType,
            uint32_t IPAddress >
class TCP
{
    //
    // Break out the StackType helper types.
    //
    STACK_TYPES_BREAKOUT;


public:

    TCP(ApplicationLayerType& _applicationLayer) :
        applicationLayer(_applicationLayer)
    {
        NewPacket();   
    }


    //
    //
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
        applicationLayer.ConnectionState().position          = 0;
        applicationLayer.ConnectionState().packetState       = Unknown;
        applicationLayer.ConnectionState().dataOffset        = 20;   // 5 words minimum.
        applicationLayer.ConnectionState().position          = 0;
        applicationLayer.ConnectionState().packetState       = Unknown;
        applicationLayer.ConnectionState().packetToSend      = TCPIP::TCP_NONE;
    }

    //
    // Push some received data into this packet processor...
    //
    void PushInto(uint8_t byte)
    {
        //
        // Header portion of the packet.
        //
        switch( applicationLayer.ConnectionState().position )
        {
            case 0:
                applicationLayer.ConnectionState().sourcePort  = byte << 8;
                break;

            case 1:
                applicationLayer.ConnectionState().sourcePort  |= byte;
                LoggerType::printf("(TCP) sourcePort: %d\n", applicationLayer.ConnectionState().sourcePort);
                break;

            case 2:
                applicationLayer.ConnectionState().destinationPort  = byte << 8;
                break;

            case 3:
                applicationLayer.ConnectionState().destinationPort  |= byte;

                //
                // TODO: Switch which applicationLayer & ConnectionState() we use here, based on the destinationPort.
                //
                LoggerType::printf("(TCP) destinationPort: %d\n", applicationLayer.ConnectionState().destinationPort);
                break;

            case 4:
                applicationLayer.ConnectionState().sequenceNumber  = byte << 24;
                break;

            case 5:
                applicationLayer.ConnectionState().sequenceNumber  |= byte << 16;
                break;

            case 6:
                applicationLayer.ConnectionState().sequenceNumber  |= byte << 8;
                break;

            case 7:
                applicationLayer.ConnectionState().sequenceNumber  |= byte;
                LoggerType::printf("(TCP) sequenceNumber: %08x\n", applicationLayer.ConnectionState().sequenceNumber);
                break;

            case 8:
                applicationLayer.ConnectionState().ackNumber  = byte << 24;
                break;

            case 9:
                applicationLayer.ConnectionState().ackNumber  |= byte << 16;
                break;

            case 10:
                applicationLayer.ConnectionState().ackNumber  |= byte << 8;
                break;

            case 11:
                applicationLayer.ConnectionState().ackNumber  |= byte;
                LoggerType::printf("(TCP) ackNumber: %08x\n", applicationLayer.ConnectionState().ackNumber);
                break;

            case 12:
                applicationLayer.ConnectionState().dataOffset  = byte >> 4;
                applicationLayer.ConnectionState().dataOffset  *= 4;
                LoggerType::printf("(TCP) dataOffset: %d\n", applicationLayer.ConnectionState().dataOffset);
                break;

            case 13:
                applicationLayer.ConnectionState().flags   = static_cast<TCPIP::TCPFlags>(byte);
                LoggerType::printf("(TCP) Flags: %02x\n", applicationLayer.ConnectionState().flags);
                break;

            case 14:
                applicationLayer.ConnectionState().windowSize  = byte << 8;
                break;

            case 15:
                applicationLayer.ConnectionState().windowSize  |= byte;
                LoggerType::printf("(TCP) windowSize: %d\n", applicationLayer.ConnectionState().windowSize);
                break;

            case 16:
                applicationLayer.ConnectionState().checksum  = byte << 8;
                break;

            case 17:
                applicationLayer.ConnectionState().checksum  |= byte;
                LoggerType::printf("(TCP) checksum: %04x\n", applicationLayer.ConnectionState().checksum);
                break;

            case 18:
                applicationLayer.ConnectionState().urgentPointer  = byte << 8;
                break;

            case 19:
                applicationLayer.ConnectionState().urgentPointer  |= byte;
                LoggerType::printf("(TCP) urgentPointer: %02x\n", applicationLayer.ConnectionState().urgentPointer);
                break;

            case 20:
                LoggerType::printf("(TCP) AppDataStart\n");
                applicationLayer.NewPacket();

            default:

                if( applicationLayer.ConnectionState().position >= applicationLayer.ConnectionState().dataOffset )
                {
                    LoggerType::printf("(TCP) AppData.\n");
                    
                    //
                    // Data portion of the IP packet.
                    //
                    if(applicationLayer.State() != Rejected)

                    {
                        applicationLayer.PushInto(byte);
                    }                    

                }
                else
                {
                    //
                    // Variable length option data.
                    //
                    LoggerType::printf("(TCP) OptionData.\n");
                }

                //
                // Detect the end of the data.
                //
                LoggerType::printf("dataByte index = %d, max = %d\n", applicationLayer.ConnectionState().position, applicationLayer.ConnectionState().ipState.length );
                if( applicationLayer.ConnectionState().position >= applicationLayer.ConnectionState().ipState.length - 1)
                {
                    LoggerType::printf(">>> message received....process response.\n" );

                    //
                    // Walk thru the state machine.
                    //
                    StateMachine();
                }

                break;
        }
        

        //
        // Ready for next byte.
        //
        applicationLayer.ConnectionState().position++;
    }


    //
    //
    //
    PacketProcessingState State()
    {
        return applicationLayer.ConnectionState().packetState;
    }

    //
    // Pull some packet data out of the processor for transmission.
    //
    uint8_t PullFrom()
    {
        return 0;
    }


    //
    //
    //
    void StateMachine()
    {
        TCPIP::TCPState    currentState;
        TCPIP::TCPState    tempState;

        applicationLayer.GetTCPState(currentState, tempState);

        switch( currentState )
        {
            case TCPIP::LISTEN:
                if( (applicationLayer.ConnectionState().flags&TCPIP::TCP_SYN) != 0)
                {
                    LoggerType::printf("[In LISTEN, received a SYN. Transmit a SYN+ACK, move to SYN_SENT.]\n");

                    //
                    // Send a SynAck packet.
                    //
                    applicationLayer.ConnectionState().packetToSend    = static_cast<TCPIP::TCPFlags>(TCPIP::TCP_ACK | TCPIP::TCP_SYN);
                    applicationLayer.ConnectionState().nextTCPState    = TCPIP::SYN_SENT;
                }

                break;

            case TCPIP::SYN_SENT:
                if( (applicationLayer.ConnectionState().flags&TCPIP::TCP_ACK) != 0)
                {
                    LoggerType::printf("[In SYN_SENT, received an ACK. Transmit an ACK, move to ESTABLISHED.]\n");
                    
                    //
                    // Connection established.
                    //
                    applicationLayer.ConnectionState().packetToSend    = static_cast<TCPIP::TCPFlags>(TCPIP::TCP_NONE);
                    applicationLayer.ConnectionState().nextTCPState    = TCPIP::ESTABLISHED;
                }

                break;

            default:
                break;
        }

    }



    //
    //
    //
    void UpdateAccumulatedChecksum(uint16_t value)
    {
        applicationLayer.ConnectionState().accumulatedChecksum     += value;
        if( applicationLayer.ConnectionState().accumulatedChecksum > 0xffff )
        {
            applicationLayer.ConnectionState().accumulatedChecksum -= 0xffff;
        }
    }    

    //
    // Pull some packet data out of the processor for transmission.
    //
    uint8_t PullFrom(bool& dataAvailable, uint16_t position)
    {
        const uint8_t   dataOffset          = (sizeofTCPHeader / 4) << 4;
        uint8_t         byteToSend          = 0x00;

        applicationLayer.ConnectionState().destinationPort     = 0x1234;
        applicationLayer.ConnectionState().sourcePort          = 80;
        applicationLayer.ConnectionState().sequenceNumber      = 0x123;
        applicationLayer.ConnectionState().ackNumber           = 0x0000;
        applicationLayer.ConnectionState().urgentPointer       = 0x0000;
        applicationLayer.ConnectionState().windowSize          = 822;
        applicationLayer.ConnectionState().flags               = static_cast<TCPIP::TCPFlags>(0);

        dataAvailable   = true;

        switch(position)
        {
            case 0:
                byteToSend  = applicationLayer.ConnectionState().sourcePort >> 8;
                break;

            case 1:
                byteToSend  = applicationLayer.ConnectionState().sourcePort & 0xff;
                break;

            case 2:
                byteToSend  = applicationLayer.ConnectionState().destinationPort >> 8;
                break;

            case 3:
                byteToSend  = applicationLayer.ConnectionState().destinationPort & 0xff;
                break;

            case 4:
                byteToSend  = (applicationLayer.ConnectionState().sequenceNumber >> 24) & 0xff;
                break;

            case 5:
                byteToSend  = (applicationLayer.ConnectionState().sequenceNumber >> 16) & 0xff;
                break;

            case 6:
                byteToSend  = (applicationLayer.ConnectionState().sequenceNumber >> 8) & 0xff;
                break;

            case 7:
                byteToSend  = (applicationLayer.ConnectionState().sequenceNumber) & 0xff;
                break;

            case 8:
                byteToSend  = (applicationLayer.ConnectionState().ackNumber >> 24) & 0xff;
                break;

            case 9:
                byteToSend  = (applicationLayer.ConnectionState().ackNumber >> 16) & 0xff;
                break;

            case 10:
                byteToSend  = (applicationLayer.ConnectionState().ackNumber >> 8) & 0xff;
                break;

            case 11:
                byteToSend  = (applicationLayer.ConnectionState().ackNumber) & 0xff;
                break;

            case 12:
                byteToSend  = dataOffset;
                break;

            case 13:
                byteToSend  = applicationLayer.ConnectionState().packetToSend;      // flags
                break;

            case 14:
                byteToSend  = applicationLayer.ConnectionState().windowSize >> 8;
                break;

            case 15:
                byteToSend  = applicationLayer.ConnectionState().windowSize & 0xff;
                break;

            case 16:

                applicationLayer.ConnectionState().accumulatedChecksum     = 0;                    

                //
                // Psuedo header portion of the checksum.
                //
                UpdateAccumulatedChecksum( ConnectionState().destinationIP >> 16 );       // source IP, us.
                UpdateAccumulatedChecksum( ConnectionState().destinationIP & 0xffff );    //
                UpdateAccumulatedChecksum( ConnectionState().sourceIP >> 16 );            // Dest IP, remote.
                UpdateAccumulatedChecksum( ConnectionState().sourceIP & 0xffff );         //
                UpdateAccumulatedChecksum( IP::TCP );                                   // always 6, TCP
                UpdateAccumulatedChecksum( PacketLength() );                            // *Note: the whole TCP segment, length, not just the applications.

                //
                // TCP header portion of the checksum
                //
                UpdateAccumulatedChecksum( applicationLayer.ConnectionState().sourcePort );
                UpdateAccumulatedChecksum( applicationLayer.ConnectionState().destinationPort );
                UpdateAccumulatedChecksum( applicationLayer.ConnectionState().sequenceNumber >> 16 );
                UpdateAccumulatedChecksum( applicationLayer.ConnectionState().sequenceNumber &0xffff );
                UpdateAccumulatedChecksum( applicationLayer.ConnectionState().ackNumber >> 16 );
                UpdateAccumulatedChecksum( applicationLayer.ConnectionState().ackNumber & 0xffff );
                UpdateAccumulatedChecksum( ((uint16_t)dataOffset<<8) | (uint16_t)applicationLayer.ConnectionState().packetToSend );
                UpdateAccumulatedChecksum( applicationLayer.ConnectionState().windowSize );
                UpdateAccumulatedChecksum( applicationLayer.ConnectionState().urgentPointer );

                //
                // Data portion of the checksum
                //
                for(uint16_t i=0; i<applicationLayer.PacketLength(); i+=2)
                {
                    bool        moreDataAvailable   = false;
                    uint8_t     hiByte              = applicationLayer.PullFrom(moreDataAvailable, i);
                    uint8_t     loByte              = applicationLayer.PullFrom(moreDataAvailable, i+1);
                    UpdateAccumulatedChecksum( ((uint16_t)hiByte<<8) | (uint16_t)loByte  );
                }
                applicationLayer.ConnectionState().accumulatedChecksum    = ~applicationLayer.ConnectionState().accumulatedChecksum;
                LoggerType::printf("TCP Checksum: %04x", applicationLayer.ConnectionState().accumulatedChecksum );

                // 
                byteToSend  = applicationLayer.ConnectionState().accumulatedChecksum >> 8;
                break;

            case 17:
                byteToSend  = applicationLayer.ConnectionState().accumulatedChecksum & 0xff;
                break;

            case 18:
                byteToSend  = applicationLayer.ConnectionState().urgentPointer >> 8;
                break;

            case 19:
                byteToSend  = applicationLayer.ConnectionState().urgentPointer & 0xff;
                break;

            default:
                byteToSend  = applicationLayer.PullFrom(dataAvailable, position-sizeofTCPHeader);

                //
                // At the end of the packet, move to the next TCP state.
                //
                if ( position-sizeofTCPHeader >= applicationLayer.PacketLength() )
                {
                    LoggerType::printf(">>> End of TCP packet tx. %d %d, newState = %d\n", position-sizeofTCPHeader, applicationLayer.PacketLength(), applicationLayer.ConnectionState().nextTCPState );
                    applicationLayer.SetTCPState( applicationLayer.ConnectionState().nextTCPState );
                }

                break;
        }

        return byteToSend;
    }


    uint32_t DestinationIP()
    {
        return ConnectionState().sourceIP;
        //return applicationLayer.DestinationIP();
    }

    uint16_t PacketLength()
    {
        return applicationLayer.PacketLength() + sizeofTCPHeader;
    }

    IP::ConnectionState& ConnectionState()
    {
        return applicationLayer.ConnectionState().ipState;
    }

private:


    const uint16_t  sizeofTCPHeader     = 20;

    //
    //
    //

    ApplicationLayerType&   applicationLayer;

};






#endif













