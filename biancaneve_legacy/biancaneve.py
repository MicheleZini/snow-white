#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)
 
import socket, sys ,os
from struct import *


 
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

#---------------------------------------------------------------------
if os.name != "nt":
    import fcntl
    import struct

    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                ifname[:15]))[20:24])

#---------------------------------------------------------------------
def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip

#--------------------------------------------------
def interfaces():

  import netifaces
  interfaces = netifaces.interfaces()

  me_ip = [] # list of all interface IP addresses

  for itf in interfaces:     
     mac_addr     = netifaces.ifaddresses(itf)[netifaces.AF_LINK]

     # not all interfaces have assigned IP addresses. 
     # if so skip to next one  
     try: 
       ip_addresses = netifaces.ifaddresses(itf)[netifaces.AF_INET]
     except KeyError,e:
       continue

     # interface might have more that one ip address allocated
     # if so loop trough them with index i
     for i in range(len(ip_addresses)):
       me_ip.append(ip_addresses[i]['addr']) 

  return me_ip


#---------------------------------------------------------------------
def neve():
  try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
  except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

  #me=get_lan_ip() NO!
  me = interfaces()
  print me
  
  nodes=[]
  
  # receive a packet
  while True:
    (packet,port) = s.recvfrom(65565)
     
    #packet string from tuple
    #packet = packet[0]
     
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    if eth_addr(packet[0:6])=='00:00:00:00:00:00' and eth_addr(packet[6:12]) =='00:00:00:00:00:00':
        continue
 
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
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
        
        #TCP protocol
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
            #text_out.text += ' [TCP]'+ str(s_addr)+':'+str(source_port)+' ---> '+str(d_addr)+':'+str(dest_port)+'\n'

            
            if s_addr in me:
                 
                 print ' [TCP]'+ str(s_addr)+':'+str(source_port)+' ---> '+str(d_addr)+':'+str(dest_port)
            elif d_addr in me:
                 
                 print ' [TCP]'+str(d_addr)+':'+str(dest_port)+ ' <--- '+str(s_addr)+':'+str(source_port)
            else:
                 continue
            
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
             
            #print 'Data : ' + data
 
        #ICMP Packets
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
            if s_addr in me:
                 if icmp_type==0:
                     print ' [icmp] reply to ping coming from '+str(d_addr)
                 if icmp_type==8:
                     print ' [icmp] pinging  '+str(d_addr)
            elif d_addr in me:
                 if icmp_type==0:
                     print ' [icmp] host is alive '+str(s_addr)
                 if icmp_type==3:
                     print ' [icmp] host is dead '+str(s_addr)
                 if icmp_type==8:
                     print ' [icmp] ping coming from  '+str(s_addr)
            else:
                 continue
         
            #print '[icmp] Type: '+ str(icmp_type) 
            #print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
             
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
             
            #print 'Data : ' + data
 
        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            
            if s_addr in me:
                 print ' [UDP]'+ str(s_addr)+':'+str(source_port)+' ---> '+str(d_addr)+':'+str(dest_port)
            elif d_addr in me:
                 print ' [UDP]'+str(d_addr)+':'+str(dest_port)+ ' <--- '+str(s_addr)+':'+str(source_port)
            else:
                 continue
            
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
             
            #print 'Data : ' + data
 
        #some other IP packet like IGMP
        else :
            #print 'Protocol other than TCP/UDP/ICMP'
            print '[other] ...'

#-------------------------------------------------------
def fiocco(s):
    # process a single packet
    packet = s.recvfrom(65565)
     
    # packet string from tuple
    packet = packet[0]

    # size of packet
    size = len(packet)

    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    if eth_addr(packet[0:6])=='00:00:00:00:00:00' and eth_addr(packet[6:12]) =='00:00:00:00:00:00':
        return
 
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
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
        me=interfaces()

        #TCP protocol
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
            
            if s_addr in me: 
                      
                 return ('TCP',d_addr,dest_port,size) 

            elif d_addr in me:                
                 return  ('TCP',s_addr,source_port,size)
            else:
                 return 
            
 
        #ICMP Packets
        elif protocol == 1 :
            return
            # skip icmp packets if we implement traceroute
            # TODO size must be passed from icmp too..

            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]
 
            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            if s_addr in me:
                 if icmp_type==0:
                     return  ('icmp',d_addr,0) 
                 if icmp_type==8:
                     return  ('icmp',d_addr,0) 
            elif d_addr in me:
                 if icmp_type==0:
                     return  ('icmp',s_addr,0) 
                 if icmp_type==3:
                     return  ('icmp',s_addr,0) 
                 if icmp_type==8:
                     return  ('icmp',d_addr,0) 
            else:
                return 
 
        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            
            if s_addr in me:
                 return  ('UDP',d_addr,dest_port,size) 
            elif d_addr in me:
                 return  ('UDP',s_addr,source_port,size) 
            else:
                return 
        #some other IP packet like IGMP
        else :
            #print 'Protocol other than TCP/UDP/ICMP'
            return ('other',d_addr,'',0) 

if __name__ == '__main__':
  neve()
