//
// Copyright (C) BlockWorks Consulting Ltd - All Rights Reserved.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Proprietary and confidential.
// Written by Steve Tickle <Steve@BlockWorks.co>, September 2014.
//




#ifndef __PCAP_H__
#define __PCAP_H__


#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <linux/if_tun.h>
#include <netinet/in.h>





//
//
//
template <  typename LoggerType,
            typename StackType,
            void (*idle)(),
            void (*newPacket)() ,
            PacketProcessingState (*layerState)(),
            void (*pushInto)(uint8_t), 
            uint8_t (*pullFrom)(bool&,  uint16_t)
            >
class PCAP
{
    //
    // Break out the StackType helper types.
    //
    STACK_TYPES_BREAKOUT;


public:

    PCAP() :
        dropFlag(0)
    {
    }


    void SetFileNames(const char* inputFileName, const char* _outputFileName)
    {
        char tun_name[IFNAMSIZ];

        outputFileName  = _outputFileName;

        printf("pcap_pkthdr size = %d\n",(int)sizeof(pcap_pkthdr));
        printf("pcap_file_header size = %d\n",(int)sizeof(pcap_file_header));

        strcpy(tun_name, "tun0");
        fd = open(inputFileName, O_RDWR);
        if(fd == -1)
        {
            perror("PCAP: dev_init: open");
            exit(1);
        }
        else
        {
            LoggerType::printf("PCAP device handle: %d", fd);
        }

        //
        //
        //
        int r   = read(fd, &fileHeader, sizeof(fileHeader));
        LoggerType::printf("r: %d\n", r);
        LoggerType::printf("magic %04d\n", fileHeader.magic);
        LoggerType::printf("major %04d\n", fileHeader.version_major);
        LoggerType::printf("minor %04d\n", fileHeader.version_minor);

    }


    void Iterate()
    {
        pcap_pkthdr         packetHeader;
        static uint32_t     packetCount     = 0;

        if(0)
        {
            //
            // Timeout.
            //

            //
            // Send any packets that may have been produced.
            //
            PullFromStackAndSend();

            idle();
        }
        else
        {
            //
            // Data available.
            //
            int r = read(fd, &packetHeader, sizeof(packetHeader));
            if( r != -1 )
            {
                bytes_left = read(fd, inbuf, packetHeader.caplen);
                if(bytes_left == -1)
                {   
                    perror("PCAP: dev_get: read\n");
                }
                else
                {
                    //
                    // Packet received, send it up the stack.
                    //
                    LoggerType::printf("<got %d bytes from pcap, packet %d>\n",packetHeader.len, packetCount);
                    LoggerType::printf("<");
                    newPacket();
                    for(int i=14; i<packetHeader.len; i++)
                    {
                        if(layerState() != Rejected)
                        {
                            LoggerType::printf("Accept: %02x ", inbuf[i]);                                            
                            pushInto( inbuf[i] );                        
                        }
                        else
                        {
                            LoggerType::printf("Reject: %02x ", inbuf[i]);                                            
                        }

                    }
                    LoggerType::printf(">\n");

                    //
                    // Send any packets that may have been produced.
                    //
                    PullFromStackAndSend();
                    LoggerType::printf("Done...\n");
                }

                packetCount++;
            }
        }

        exit(0);
    }

    typedef enum
    {
        ARP     = 0x0806,
        IPv4    = 0x0800,
        IPv6    = 0x86dd,

    } EtherType;

    //
    //
    //
    void PullFromStackAndSend()
    {
        uint16_t        i                   = 0;
        bool            dataAvailable       = false;
        const uint8_t   destMAC[6]          = {0x11,0x22,0x33,0x44,0x55,0x66};
        const uint8_t   srcMAC[6]           = {0x66,0x77,0x88,0x99,0xaa,0xbb};
        const uint16_t  frameType           = 0x0800;
        uint32_t        frameCheckSequence  = 0x00000000;

        //
        // Ethernet II frame header.
        //
        outbuf[0]   = destMAC[0];
        outbuf[1]   = destMAC[1];
        outbuf[2]   = destMAC[2];
        outbuf[3]   = destMAC[3];
        outbuf[4]   = destMAC[4];
        outbuf[5]   = destMAC[5];

        outbuf[6]   = srcMAC[0];
        outbuf[7]   = srcMAC[1];
        outbuf[8]   = srcMAC[2];
        outbuf[9]   = srcMAC[3];
        outbuf[10]  = srcMAC[4];
        outbuf[11]  = srcMAC[5];

        outbuf[12]  = frameType >> 8;
        outbuf[13]  = frameType & 0xff;
 
        //
        // Form the new packet.
        //
        i   = 14;
        do
        {
            outbuf[i]   = pullFrom( dataAvailable, i-14 );
            if(dataAvailable == true)
            {
                LoggerType::printf(">%d:%02x<\n", i, outbuf[i] );
                i++;
            }


        } while(dataAvailable == true);

 
        //
        // Calculate the CRC... Done in such a way that we could streamify it in future.
        //
        StartNewCRC();
        for(uint16_t j=0; j<i; j++)
        {
            AccumulateCRC( outbuf[j] );
        }
        frameCheckSequence  = CurrentCRC();

        //
        // Frame Check Sequence (FCS) in the frame trailer.
        //
        outbuf[i]  = frameCheckSequence & 0xff;
        i++;
        outbuf[i]  = (frameCheckSequence >> 8) & 0xff;
        i++;
        outbuf[i]  = (frameCheckSequence >> 16) & 0xff;
        i++;
        outbuf[i]  = (frameCheckSequence >> 24) & 0xff;
        i++;

        //
        // Write the packet to a pcap file.
        //
        {
            pcap_pkthdr         packetHeader;

            int outfd = open(outputFileName, O_RDWR|O_CREAT, S_IRWXU);
            if(outfd == -1)
            {
                perror("PCAP: dev_init: output open");
                exit(1);
            }
            else
            {
                LoggerType::printf("PCAP device handle: %d", outfd);
            }

            packetHeader.caplen         = i;
            packetHeader.len            = i;
            packetHeader.tv_sec         = 0;
            packetHeader.tv_usec        = 1;

            fileHeader.magic            = 0xa1b2c3d4;
            fileHeader.version_major    = 2;
            fileHeader.version_minor    = 4;
            fileHeader.thiszone         = 0;
            fileHeader.sigfigs          = 0;
            fileHeader.linktype         = 1; // 1==ethernet.
            fileHeader.snaplen          = sizeof(outbuf);

            //
            //
            //
            int r;
            r   = write(outfd, &fileHeader, sizeof(fileHeader));
            r   = write(outfd, &packetHeader, sizeof(packetHeader));
            r   = write(outfd, &outbuf[0], i);
            r = r;
            close(outfd);
        }

    }


private:

    uint32_t    crc;

    void StartNewCRC()
    {
        crc  = 0;
    }

    uint32_t CurrentCRC()
    {
        LoggerType::printf("%08X ", crc);

        return crc;
    }

    //
    // Originally from http://www.edaboard.com/thread120700.html
    //
    void AccumulateCRC(uint8_t value)
    {
        static const uint32_t   crcTable[] =
        {
            0x4DBDF21C, 0x500AE278, 0x76D3D2D4, 0x6B64C2B0,
            0x3B61B38C, 0x26D6A3E8, 0x000F9344, 0x1DB88320,
            0xA005713C, 0xBDB26158, 0x9B6B51F4, 0x86DC4190,
            0xD6D930AC, 0xCB6E20C8, 0xEDB71064, 0xF0000000
        };

        crc = (crc >> 4) ^ crcTable[(crc ^ (value >> 0)) & 0x0F];  // lower nibble
        crc = (crc >> 4) ^ crcTable[(crc ^ (value >> 4)) & 0x0F];  // upper nibble
    }


    /*
     * Describe at http://wiki.wireshark.org/Development/LibpcapFileFormat
     * 
     * The first record in the file contains saved values for some
     * of the flags used in the printout phases of tcpdump.
     * Many fields here are 32 bit ints so compilers won't insert unwanted
     * padding; these files need to be interchangeable across architectures.
     *
     * Do not change the layout of this structure, in any way (this includes
     * changes that only affect the length of fields in this structure).
     *
     * Also, do not change the interpretation of any of the members of this
     * structure, in any way (this includes using values other than
     * LINKTYPE_ values, as defined in "savefile.c", in the "linktype"
     * field).
     *
     * Instead:
     *
     *  introduce a new structure for the new format, if the layout
     *  of the structure changed;
     *
     *  send mail to "tcpdump-workers@tcpdump.org", requesting a new
     *  magic number for your new capture file format, and, when
     *  you get the new magic number, put it in "savefile.c";
     *
     *  use that magic number for save files with the changed file
     *  header;
     *
     *  make the code in "savefile.c" capable of reading files with
     *  the old file header as well as files with the new file header
     *  (using the magic number to determine the header format).
     *
     * Then supply the changes to "patches@tcpdump.org", so that future
     * versions of libpcap and programs that use it (such as tcpdump) will
     * be able to read your new capture file format.
     */
    #pragma pack(1)
    struct pcap_file_header 
    {
        uint32_t    magic;
        uint16_t    version_major;
        uint16_t    version_minor;
        int32_t     thiszone;       /* gmt to local correction */
        uint32_t    sigfigs;        /* accuracy of timestamps */
        uint32_t    snaplen;        /* max length saved portion of each pkt */
        uint32_t    linktype;       /* data link type (LINKTYPE_*) */
    };
    #pragma pack()

    /*
     * Each packet in the dump file is prepended with this generic header.
     * This gets around the problem of different headers for different
     * packet interfaces.
     */
    #pragma pack(1)    
    struct pcap_pkthdr 
    {
        int32_t     tv_sec;     /* Seconds.  */
        int32_t     tv_usec;    /* Microseconds.  */
        uint32_t    caplen;     /* length of portion present */
        uint32_t    len;        /* length this packet (off wire) */
    };
    #pragma pack()


    struct pcap_file_header fileHeader;

    int             dropFlag;
    int             fd;
    int             bytes_left;
    uint8_t         inbuf[2048];
    uint8_t         outbuf[2048];
    int             inptr;
    int             outptr;

    const char*     outputFileName;
};




#endif


