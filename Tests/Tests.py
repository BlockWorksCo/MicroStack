#
# Copyright (C) BlockWorks Consulting Ltd - All Rights Reserved.
# Unauthorized copying of this file, via any medium is strictly prohibited.
# Proprietary and confidential.
# Written by Steve Tickle <Steve@BlockWorks.co>, September 2014.
#


from nose import with_setup
import subprocess
import os



def Run(command):
    """
    """
    print(command)
    try:
        return subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return e.output


def BuildVMPathFromLocalPath(localPath):
    """
    """
    return '/HostRoot'+localPath



def CompareFiles(fileA, fileB):
    """
    """
    t = Run('cmp -l %s %s '%(fileA, fileB))
    return t == ''









def setup_module():
    """
    """
    out = Run('make PLATFORM=Linux clean all')
    print(out)



def teardown_module():
    """
    """
    pass










def TestChecksums():
    """
    Checks:
    - Ethernet FCS.
    - IPv4 checksum.
    - TCP checksum.
    """
    out = Run(' Output/Main Test1Input.pcap TestOutput.pcap ')
    print(out)
    assert CompareFiles('TestOutput.pcap','Checksum1CheckedOutput.pcap') == True




def TestTCPConnectionSetup():
    """
    Checks:
    - SYN receipt.
    - SYN+ACK response.
    - ACK receipt.
    """
    out = Run(' Output/Main Test1Input.pcap TestOutput.pcap ')
    print(out)
    assert CompareFiles('TestOutput.pcap','Checksum1CheckedOutput.pcap') == True







