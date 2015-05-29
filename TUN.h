//
// Copyright (C) BlockWorks Consulting Ltd - All Rights Reserved.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Proprietary and confidential.
// Written by Steve Tickle <Steve@BlockWorks.co>, September 2014.
//




#ifndef __TUN_H__
#define __TUN_H__


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

#include <linux/if.h>
#include <linux/if_tun.h>





//
//
//
template <  typename LoggerType,
            typename StackType >
class TUN
{
    //
    // Break out the StackType helper types.
    //
    STACK_TYPES_BREAKOUT;


public:

    TUN(InternetLayerType& _internetLayer) :
        internetLayer(_internetLayer),
        dropFlag(0)
    {

        char tun_name[IFNAMSIZ];

        strcpy(tun_name, "tun0");
        fd = tun_alloc(tun_name, IFF_TUN|IFF_NO_PI);  /* tun interface, no packet information */
        if(fd == -1)
        {
            perror("tun_dev: dev_init: open");
            exit(1);
        }
        else
        {
            LoggerType::printf("TUN device handle: %d", fd);
        }


        //
        // sudo ip tuntap add dev tun0 mode tun
        // sudo ifconfig tun0 192.168.4.1 up
        //
        int r = system("ifconfig tun0 inet 192.168.0.2 192.168.0.1");

        r = system("route add -net 192.168.0.0 netmask 255.255.255.0 dev tun0");
        r++;

        bytes_left = 0;
        outptr = 0;
    }



    void Iterate()
    {
        fd_set          fdset;
        struct timeval  tv;
        int             ret;

        tv.tv_sec       = 0;
        tv.tv_usec      = 500000;
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        LoggerType::printf("Waiting for data (%d)...\n",fd);
        ret = select(fd + 1, &fdset, NULL, NULL, &tv);
        if(ret == 0)
        {
            //
            // Timeout.
            //

            //
            // Send any packets that may have been produced.
            //
            PullFromStackAndSend();

            internetLayer.Idle();
        }
        else
        {
            //
            // Data available.
            //

            bytes_left = read(fd, inbuf, sizeof(inbuf));
            if(bytes_left == -1)
            {   
                perror("tun_dev: dev_get: read\n");
            }
            else
            {
                //
                // Packet received, send it up the stack.
                //
                LoggerType::printf("<got %d bytes from tun>\n",bytes_left);
                LoggerType::printf("<");
                internetLayer.NewPacket();
                for(int i=0; i<bytes_left; i++)
                {
                    if(internetLayer.State() != Rejected)
                    {
                        internetLayer.PushInto( inbuf[i] );                        
                    }

                    LoggerType::printf("%02x ", inbuf[i]);                
                }
                LoggerType::printf(">\n");

                //
                // Send any packets that may have been produced.
                //
                PullFromStackAndSend();
            }

        }
    }


    //
    //
    //
    void PullFromStackAndSend()
    {
        uint16_t    i               = 0;
        bool        dataAvailable   = false;

        //
        // While there are still packets in the stack...
        //
        do
        {
            //
            // Form the new packet.
            //
            i   = 0;
            do
            {
                outbuf[i]   = internetLayer.PullFrom( dataAvailable, i );
                if(dataAvailable == true)
                {
                    i++;
                }

            } while(dataAvailable == true);

            //
            // Send the new packet.
            //
            if(i>0)
            {
                size_t  bytesWritten    = write(fd, outbuf, i);
                if(bytesWritten != i)
                {
                    LoggerType::printf("(TUN) not all bytes written!\n");
                }
            }

        } while(i > 0);

    }


    int tun_alloc(char *dev, int flags) {

      struct ifreq ifr;
      int fd, err;
      const char *clonedev = "/dev/net/tun";

      /* Arguments taken by the function:
       *
       * char *dev: the name of an interface (or '\0'). MUST have enough
       *   space to hold the interface name if '\0' is passed
       * int flags: interface flags (eg, IFF_TUN etc.)
       */

       /* open the clone device */
       if( (fd = open(clonedev, O_RDWR)) < 0 ) 
       {
         LoggerType::printf("opened clonedev\n");
         return fd;
       }

       /* preparation of the struct ifr, of type "struct ifreq" */
       memset(&ifr, 0, sizeof(ifr));

       ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

       if (*dev) 
       {
         LoggerType::printf("name %s supplied\n",dev);
         /* if a device name was specified, put it in the structure; otherwise,
          * the kernel will try to allocate the "next" device of the
          * specified type */
         strncpy(ifr.ifr_name, dev, IFNAMSIZ);
       }

       /* try to create the device */
       if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) 
       {
         LoggerType::printf("ioctl failed. \n");
         close(fd);
         fd = -1;
         return err;
       }
       else
       {
         LoggerType::printf("ioctl ok, fd=%d. \n",fd);        
       }

      /* if the operation was successful, write back the name of the
       * interface to the variable "dev", so the caller can know
       * it. Note that the caller MUST reserve space in *dev (see calling
       * code below) */
      strcpy(dev, ifr.ifr_name);
     LoggerType::printf("dev name = %s. \n", dev);

      /* this is the special file descriptor that the caller will use to talk
       * with the virtual interface */
      return fd;
    }




private:

    InternetLayerType&  internetLayer;

    int             dropFlag;
    int             fd;
    int             bytes_left;
    char            inbuf[2048];
    char            outbuf[2048];
    int             inptr;
    int             outptr;
};




#endif


