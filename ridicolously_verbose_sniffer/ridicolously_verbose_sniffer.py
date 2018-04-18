
# Original Author: Silver Moon (m00n.silv3r@gmail.com)
# > Packet sniffer in python
#   For Linux - Sniffs all incoming and outgoing packets :)
#
# Adapted by: Michele Zini (michelegzini@gmail.com)

# Some References:

# IP HEADER:
    #   0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |Version|  IHL  |Type of Service|          Total Length         |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |         Identification        |Flags|      Fragment Offset    |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |  Time to Live |    Protocol   |         Header Checksum       |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                       Source Address                          |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                    Destination Address                        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                    Options                    |    Padding    |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

import socket # python kernel-level socket library
import sys ,os # exceptions handling and system info
 
from struct import pack,unpack # binary to meaningful data

import binascii # hex/bin conversion to string

import fcntl # socket options.. maybe? 

from time import gmtime, strftime # time


MTU = 65565 # max transmission unit
            # maybe get this from interfaces?
            # 65565 should be the max physical limit anyways (for ethernet)



#---------------------------------------------------------------------
# legacy way to get ip address, 
# caused me troble so whitched to netifaces library
#---------------------------------------------------------------------
def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                ifname[:15]))[20:24])


#---------------------------------------------------------------------
# parse system interfaces, get active mac/IP addresses 
#---------------------------------------------------------------------
def interfaces():

  # lets use colors! 
  from random import randrange
  ifmcolor = "\x1B[37m"  # light grey
  newcolor = "\x1B[36m"  # % randrange(31,38)
  defcolor = "\x1B[39m" # ? --> see Ansi Codes
  

  import netifaces
  interfaces = netifaces.interfaces()

  print 
  print "%s  Local Interfaces:%s" % (newcolor,defcolor)
  # loop trough all interfaces
  for itf in interfaces:
     
     mac_addr     = netifaces.ifaddresses(itf)[netifaces.AF_LINK]

     print "%s _________________________________________%s" % (ifmcolor,defcolor) 
     print "  %sname%s: %s%s%s" % (ifmcolor,defcolor,newcolor, itf ,defcolor)
     print "  %smac%s : %s"      % (ifmcolor,defcolor, mac_addr[0]['addr'])


     # not all interfaces have assigned IP addresses. 
     # if so skip to next one  
     try: 
       ip_addresses = netifaces.ifaddresses(itf)[netifaces.AF_INET]
     except KeyError,e:
       continue

     # interface might have more that one ip address allocated
     # if so loop trough them with index i
     for i in range(len(ip_addresses)):

         print "    * %sIPv4%s: %s " % (ifmcolor,defcolor, ip_addresses[i]['addr']   )
         print "      %sMask%s: %s " % (ifmcolor,defcolor, ip_addresses[i]['netmask'])

         # broadcast is not always available. 
         # if so skip to next interface. 
         try:
           print "      %sBrdc%s: %s " % (ifmcolor,defcolor, ip_addresses[i]['broadcast'])
         except KeyError,e:
           break

  print

#---------------------------------------------------------------------
def neve():

  # get active interfaces info
  interfaces()

  
  black     = "\x1B[1;30m"   # red
  red       = "\x1B[1;31m"   # red 
  green     = "\x1B[1;32m"   # red 
  yellow    = "\x1B[1;33m"   # yellow
  blue      = "\x1B[1;34m"   # red 
  purple    = "\x1B[1;35m"   # red 
  lblue     = "\x1B[1;36m"   # red 
  white     = "\x1B[1;37m"   # red 
  defcolor  = "\x1B[0;39m"   # to system theme

  # ask for permissi0n:
  print "%s  Intercepting network traffic is a violation of privacy " % yellow
  print "        and might be illegal in you location.."  
  print "  "
  print "    * seek consent from everyone on your network *%s " % defcolor 
  print
  consent = raw_input('                %sStart capture?(y/N):%s '%(red,defcolor)) 


  if consent not in ['y','Y','yes','ok',"let's gooo!",'yeaaahhh']:
     print "wise!"
     sys.exit(0)



  # create kernel level socket
  # arguments:
  #  - AF_PACKET     -> data link (ethernet) layer socket
  #                     {use AF_INET/AF_INET6 if only interested in IPv4/IPv6}
  # 
  #  - SOCK_RAW      -> access everything going trough interfaces.
  #
  #  - ntohs(0x0003) -> '\_(?)_/'

  try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
  except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit(1)

  
  # receive all packages (promiscuos?) 
  #  - yes but ioctl WIN only
  #
  # s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  



  # receive packets in loop,
  # stop with ctrl-C (handling that would be nice)
  while True:

    # receive a MTU(Maximum Transmission Unit)-sized packet
    (packet,port) = s.recvfrom(MTU)


    # let's print a timestamp
    print strftime("+ %a, %d %b at %H:%M:%S (GMT):", gmtime())


    # parse ethernet header
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)

    # interpret ethernet header
    mac_sauce = ':'.join(binascii.hexlify(eth[0])[i:i+2] for i in range(0,12,2)) 
    mac_dest  = ':'.join(binascii.hexlify(eth[1])[i:i+2] for i in range(0,12,2))        
    eth_protocol = socket.ntohs(eth[2])

    print "  %s__ data link ________________________________________________________%s " % (green,defcolor) 
    print " /  from  %s  -->  to  %s    PROTO %4i  \     " % (mac_sauce,mac_dest,eth_protocol)


    # --------------------------------------------------------------------
    # IP Protocol
    # --------------------------------------------------------------------
    if eth_protocol == 8 :

        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

         

        # --------------------------------------------------------------------
        # TCP protocol
        # --------------------------------------------------------------------
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            
            pld_type = 'unknown'

            # common protocol?
            secure   = {443:'https',22:'ssh'}
            insecure = {80:'http',23:'telnet'}

            srccolor = defcolor
            dstcolor = defcolor
            pldcolor = purple

            if source_port in secure:
                srccolor = yellow
                pldcolor = yellow
                pld_type = secure[source_port]

            if dest_port   in secure:
                dstcolor = yellow
                pldcolor = yellow
                pld_type = secure[dest_port]

            if source_port in insecure: 
                srccolor = red
                pldcolor = red
                pld_type = insecure[source_port]

            if dest_port   in insecure:
                dstcolor = red
                pldcolor = red
                pld_type = insecure[dest_port]

            #get data from the packet
            data = packet[h_size:]

            print_from = s_addr + ' : ' + srccolor + str(source_port) + defcolor 
            print_to   = d_addr + ' : ' + dstcolor + str(dest_port) + defcolor
            print_size = '(' + str(data_size) + ' Bytes)'

            print " |  %s_ TCP/IP ________________________________________________________%s  |"  % (lblue,defcolor)
            print " | / from %-25s  -->  to %-25s          \ |" %  (print_from,print_to)
            print " | | type %s%-6s%s %-13s                                       | |" % (pldcolor,pld_type,defcolor,print_size)
            
            # print data if any
            if len(data) > 0:
                print " | |  %s_ payload ___________________________________________________%s  | |"  %  (pldcolor,defcolor)
                print " | | /               hex                           ascii           \ | |" 
	        n = 18
	        for i in xrange(0,len(data),n):
                   hexline = binascii.hexlify(data[i:i+n])
                   asciiline = ""

	           for j in xrange(0,len(hexline),2):
	              char = hexline[j:j+2].decode('hex')

	              if ord(char) >= 32 and ord(char) <= 126:
	                  asciiline += char
	              else:
	                  asciiline += '.'

          	   print " | | |  %-36s   %-18s  | | |" % (hexline, asciiline)

                print " | | \%s=============================================================%s/ | |"  %  (pldcolor,defcolor)

            print " | \%s_________________________________________________________________%s/ |"  % (lblue,defcolor)



        # --------------------------------------------------------------------
        # ICMP Packets
        # --------------------------------------------------------------------
        elif protocol == 1 :
            #continue
            # skip icmp packets if we implement traceroute
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            icmp_desc = {8:'echo request: ping', 0:'echo reply: host is alive', 3:'echo reply: host is dead'}

            print " |  %s_ ICMP __________________________________________________________%s  |"  % (white,defcolor)
            print " | / from %-15s   to %-15s                       \ |" % (s_addr,d_addr)
            print " | | type %i %s%-30s%s                           | |" % (icmp_type,white,icmp_desc[icmp_type],defcolor)


            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            # print data if any
            if len(data) > 0:
		   n = 20 # byte per line                                                      .
		   print " | | _________________ hex __________________   _______ ascii ______ | |" 
		   
	    	   for i in xrange(0,len(data),n):
		      hexline = binascii.hexlify(data[i:i+n])
		      asciiline = ""

		      for j in xrange(0,len(hexline),2):
		         char = hexline[j:j+2].decode('hex')

		         if ord(char) >= 32 and ord(char) <= 126:
		            asciiline += char
		         else:
		            asciiline += '.'

		      print " | | %-40s   %-20s | |" % (hexline,asciiline)
		                 
            print " | \%s=================================================================%s/ |"  % (white,defcolor)



        # --------------------------------------------------------------------
        #UDP packets
        # --------------------------------------------------------------------
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port   = udph[1]
            length      = udph[2]
            checksum    = udph[3]

            print " |  %s_ UDP/IP ________________________________________________________%s  |"  % (lblue,defcolor)
            print " | / from %15s  port %5i                                \ |" % (s_addr,source_port)
            print " | | to   %15s  port %5i                                | |" % (d_addr,dest_port)
            

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            # print data if any
            if len(data) > 0:
		   n = 20 # byte per line                                                      .
		   print " | | _________________ hex __________________   _______ ascii ______ | |" 
		   
	    	   for i in xrange(0,len(data),n):
		      hexline = binascii.hexlify(data[i:i+n])
		      asciiline = ""

		      for j in xrange(0,len(hexline),2):
		         char = hexline[j:j+2].decode('hex')

		         if ord(char) >= 32 and ord(char) <= 126:
		            asciiline += char
		         else:
		            asciiline += '.'

		      print " | | %-40s   %-20s | |" % (hexline,asciiline)

            print " | \%s_________________________________________________________________%s/ |"  % (lblue,defcolor)

        # --------------------------------------------------------------------
        #some other IP packet like IGMP
        # --------------------------------------------------------------------
        else :
            #print 'Protocol other than TCP/UDP/ICMP'
            pass


    # --------------------------------------------------------------------
    # Unknown internet-layer protocol
    # --------------------------------------------------------------------
    else:
        print " |  %s_ unknown _______________________________________________________%s  |" % (purple,defcolor)
        print " | / payload size: %5i                                             \ |" % len(packet[eth_length:])

        
        data = packet[eth_length:]

        # print data if any
        if len(data) > 0:
           n = 20 # byte per line                                                      .
           print " | | _________________ hex __________________   _______ ascii ______ | |" 
           
    	   for i in xrange(0,len(data),n):
              hexline = binascii.hexlify(data[i:i+n])
              asciiline = ""

              for j in xrange(0,len(hexline),2):
                 char = hexline[j:j+2].decode('hex')

                 if ord(char) >= 32 and ord(char) <= 126:
                    asciiline += char
                 else:
                    asciiline += '.'

	      print " | | %-40s   %-20s | |" % (hexline,asciiline)

        print " | \%s=================================================================%s/ |" % (purple,defcolor)
       
    print " \%s_____________________________________________________________________%s/" % (green,defcolor)
    print 

# ========= BOILERPLATE ===========================
if __name__ == '__main__':
   neve()


