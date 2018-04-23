#!/usr/bin/kivy
import kivy
kivy.require("1.9.0")

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.config import Config
Config.set('graphics', 'resizable', '0')
Config.set('graphics', 'width', '1050')
Config.set('graphics', 'height', '664')
from  kivy.graphics import *
import socket, sys,os
from struct import *
import threading
import time
#---------------------------
import biancaneve
import trace
#---------------------------
from functools import partial
from location import * #locate
from urllib2 import urlopen


class node():
    def __init__(self,ip,longitude,latitude,citta,stato,act,dat,l,x,y):
        self.ip_addr=ip
        self.lon=longitude
        self.lat=latitude
        self.activity=act
        self.data=dat
        self.log=l
        self.city=citta
        self.country=stato

        self.center_x = x
        self.center_y = y

        self.expanded = False

        self.traced = 0 # 0 = not traced
                        # 1 = traced
                        # 2 = tracing
        self.hops = []
        self.whoisd = False


def format_data(d):
            if d // 1000000000 > 0:
              data = d / float(1000000000)
              unit = 'GB'
            elif d // 1000000 > 0:
              data = d / float(1000000)
              unit = 'MB'
            elif d // 1000 > 0:
              data = d / float(1000)
              unit = 'KB'
            else:
              data = d
              unit = 'Bytes'

            if unit == 'Bytes':
              return '%.0f %s' % (data,unit)
            else:
              return '%.1f %s' % (data,unit)

from kivy.uix.image import Image
from kivy.uix.widget import Widget
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Rectangle, Color
import math
from random import randrange

#===============================================================================================
class MapWidget(Widget):
    def __init__(self, **kwargs):
        super(MapWidget, self).__init__(**kwargs)
        with self.canvas:
            self.node_buttons = []
            self.rect = Rectangle(source='./img/mercatore_black.jpeg', pos=self.center)
        self.bind(pos=self.update_rect, size=self.update_rect)
        

    def update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size

    def mercatore(self,(lat,lon),*args): 
        if lat == '-' :
            lat,lon = (55.9410456,-3.2755948) # hard-coded Scotland location
        
        #much thanks to Michel Feldheim for Mercator Map projecion
        x = self.pos[0] + ((self.size[0]/360.0) * (180 + lon)) - 23 # hard-coded adjustment to the map
        lat_rad = lat*3.14/180
        mercN = math.log(math.tan((3.14/4)+(lat_rad/2)))
        y = self.pos[1] + (self.size[0]/3) + (self.size[1]*mercN/(1.75*3.14)) + 6 # hard-coded adjustment to the map
        return (x,y)

    def draw_node(self,new_node,me_lat,me_lon, *args):
        x,y = self.mercatore((new_node.lat,new_node.lon))
        mx,my = self.mercatore((me_lat,me_lon))
        # x,y of nodes on the map 
        # from longitue,latitude using mercatore projection equation
        
        self.canvas.add(Color(0,0,0))
        if abs(x-mx)>abs(y-my):
            self.canvas.add(Line(group='traffic',points=[x,y-1,mx,my-1], width=1))
        else:
            self.canvas.add(Line(group='traffic',points=[x-1,y,mx-1,my], width=1))

        self.canvas.add(Color(1,0.65,0))
        self.canvas.add(Line(group='traffic',points=[x,y,mx,my], width=1))

        self.canvas.add(Rectangle(group='nodes',pos=(x-2,y-2),size=(4,4)))
        self.canvas.add(Rectangle(group='nodes',pos=(mx-3,my-3),size=(6,6)))


    def draw_hop(self,new_lat,new_lon,last_lat,last_lon, *args):
        x,y = self.mercatore((new_lat,new_lon))
        mx,my = self.mercatore((last_lat,last_lon))
        # x,y of nodes on the map 
        # from longitue,latitude using mercatore projection equation
        
        self.canvas.add(Color(0,0,0))
        if abs(x-mx)>abs(y-my):
            self.canvas.add(Line(group='routes',points=[x,y-1,mx,my-1], width=1))
        else:
            self.canvas.add(Line(group='routes',points=[x-1,y,mx-1,my], width=1))

        self.canvas.add(Color(0.3,1,0))
        self.canvas.add(Line(group='routes',points=[x,y,mx,my], width=1))

        self.canvas.add(Rectangle(group='hops',pos=(x-2,y-2),size=(4,4)))
        


#===============================================================================================
from kivy.uix.scrollview import ScrollView
from kivy.properties import StringProperty


class Scrollable(ScrollView):

    pass

#===============================================================================================
class biancaBoxLayout(BoxLayout):  

    def start(self,args):
        
        self.nodes = {}
        self.me = [] #urlopen('http://ip.42.pl/raw').read() 
                     # much external, such secure, wow
        for ip in biancaneve.interfaces():
          self.me.append('[b]'+ip+'[/b]') 
        self.me_coord = (55.9410456,-3.2755948)#locate(self.me)
        self.me_data = 0
        (x,y) = self.ids.map.mercatore(self.me_coord)
        ip = '127.0.0.1'
        n = node(ip,self.me_coord[1],self.me_coord[0],city(ip),country(ip),0,0,'hi',x,y)
        #self.nodes.append(n)
        #self.ids.map.draw_node(n,self.me_coord[0],self.me_coord[1])
        try:
            self.s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
            self.update_event = Clock.schedule_interval(partial(self.update_all), 1 / 30.)
            #Clock.schedule_once(partial(self.test_all()), 1)
        except socket.error , msg:
            self.ids.text_out.text += 'Socket could not be created.\n Error Code : ' + str(msg[0]) + '\n Message ' + msg[1]+'\n'
            return

        # switch scan start/stop buttons enabled status
        self.ids.btn_start.disabled = True
        self.ids.btn_start.opacity = .98
        self.ids.btn_stop.disabled = False
        self.ids.btn_stop.opacity = 1

        self.ids.text_out.text +='Socket created...\n'

    def warning(self):
        cont_lay = BoxLayout(orientation='vertical')
        butt_lay = BoxLayout(orientation='horizontal', size_hint=(1,.2))

        btn1 = Button(text='I understand, proceed')
        btn2 = Button(text='mmm, take me back')

        butt_lay.add_widget(btn1)
        butt_lay.add_widget(btn2)
        cont_lay.add_widget(Label(text='This program examines ALL packets in the network interface.\n\nBefore starting a capture session, be sure to obtain informated consensus\nfrom all users in the network. Unhautorized capture may be considered\nillegal under your legislation, and is performed under the user responsibility', halign= 'center'))
        cont_lay.add_widget(butt_lay)
        popup = Popup(size_hint=(.6,.5),
                      title=' Warning',
                      content=cont_lay,
                      auto_dismiss=False)

        btn1.bind(on_press=popup.dismiss)
        btn1.bind(on_press=self.start)
        btn2.bind(on_press=popup.dismiss)

        popup.open()
          
    def stop(self):
        self.update_event.cancel()
        self.s.close()

        # switch scan start/stop buttons enabled status
        self.ids.btn_stop.disabled = True
        self.ids.btn_stop.opacity = .98
        self.ids.btn_start.disabled = False
        self.ids.btn_start.opacity = 1

        self.ids.text_out.text +='Socket closed...\n'


    def update_all(self, args):
        fiocco=biancaneve.fiocco(self.s)
        if fiocco:
            new_node=True
            
            for ip,n in self.nodes.iteritems():
                if fiocco[1]==n.ip_addr: 
                    n.activity+=1
                    n.data+=fiocco[3]
                    self.me_data+=fiocco[3]
                    n.log+= fiocco[0] +'\n'
                    new_node=False
                    if n.lat != '-':
                       self.ids.map.draw_node(n,self.me_coord[0],self.me_coord[1])
                    break
            if new_node:
                ip=fiocco[1]
                coord=locate(ip)
                x,y = self.ids.map.mercatore(coord)
                n = node(ip,coord[1],coord[0],city(ip),country(ip),1,fiocco[3],fiocco[0]+'\n',x,y)
                self.me_data+=fiocco[3]
                self.nodes[ip] = n
                if coord[0] != '-':
                    self.ids.map.draw_node(n,self.me_coord[0],self.me_coord[1])


            Clock.schedule_once(partial(self.update_text), 0)
            Clock.schedule_once(partial(self.remove_traff), 1)


    def remove_traff(self, args):
        self.ids.map.canvas.remove_group('traffic')

    def remove_routes(self):
        self.ids.map.canvas.remove_group('routes')
        self.ids.map.canvas.remove_group('hops')


    def update_text(self, args):
        text=''
        text+='=== [color=FF9900]ME[/color] =====================\n'
        for ip in self.me:
          text+=' Local IPv4: '+ip+'\n'
        text+=' Data: [b]'+format_data(self.me_data)+'[/b]\n'
        text+=' \n'
        for ip,n in self.nodes.iteritems():
            if n.expanded:
              exp='info -'
            else:
              exp='info +'
            text+='--- [color=FF9900]NODE[/color] -------------------  [b][ref=exp_'+n.ip_addr+'][ '+exp+' ][/ref][/b]\n'
            text+=' IPv4: [b]'+n.ip_addr+'[/b]\n'
            text+=' Activity: [b]'+str(n.activity)+'[/b] packets\n'
            text+=' Data: '+format_data(n.data)+'\n'
            text+='\n'
            
            if n.expanded:

              if n.lat != '-':
                text+=' Coordinates: [size=11]'+str(n.lat)+' N ,'+str(n.lon)+' E [/size]\n'
                if str(n.country) != '-':
                  text+='+ City: [i]'+str(n.city)+'[/i]\n'
                  text+='+ Country: [i]'+str(n.country)+'[/i]\n'
              
                if n.traced == 1:
                   text+='\n'
                   for hop in n.hops:
                      text+=' Hop '+str(hop[0][0])+' - <[b]'+str(hop[0][1])+'[/b]>\n'
                      if hop[1][1] != '-': # if able to locate hop print, else blank
                        text+='   [i]'+str(hop[1][0])+' , '+str(hop[1][1])+'[/i] \n'
                   text+=' [b][color=66ff33]Route Traced[/color][/b]\n'
                elif n.traced == 0:
                   text+=' [b][ref=trace_'+n.ip_addr+'][color=ff0000]Trace Route[/color][/ref][/b]\n'
                else:
                   text+=' [b]Tracing..[/b]\n'

              else:
                text+='   [i]location unavailable[/i]\n'

              text+='\n' # space btw nodes
           
        
        self.ids.text_out.text = text 


    
    # action on node initiated..
    def host_action(self,value):        
        action = value.split('_')

        node = self.nodes[action[1]] # [node->global_node_hops] points to node that initiated action   


        # action is traceroute
        if action[0] == 'trace':

          node.traced = 2 # set tracing in progress status
          Clock.schedule_once(partial(self.update_text), 0) # try to update the status, failing miserably.. TODO!
          hops = trace.trc(action[1])

          if (hops != '-'):
            node.traced = 1 # set trace completed status
            # YAAAY 

            # now draw the trace
            last_lat = self.me_coord[0]
            last_lon = self.me_coord[1]
            found_hops = []

            for hop in hops:
             
               (new_lat,new_lon) = locate(hop[1])
               found_hops.append((hop,(city(hop[1]),country(hop[1]))))

               if new_lat != '-':
                  self.ids.map.draw_hop(new_lat,new_lon,last_lat,last_lon)
                  last_lat = new_lat
                  last_lon = new_lon

            node.hops = found_hops

            # force to draw connection to last hop
            (new_lat,new_lon) = locate(action[1]) # ndr: action[1] = remote host IP
                                                #      action[0] = action (tracert,whois)
            self.ids.map.draw_hop(new_lat,new_lon,last_lat,last_lon)
          else:
            node.traced = 0  # set trace failed status
            # NOPE

        # action is expand info
        if action[0] == 'exp':
          # switch
          if node.expanded:
            node.expanded=False
          else:
            node.expanded=True

        Clock.schedule_once(partial(self.update_text), 0)

#----------------------------------------------------------------------------------------------- 
class biancApp(App): 

    icon = './img/bn_icon.png'
    title = 'Biancaneve'

    def build(self):
        self.load_kv('run_gui.kv')
        return biancaBoxLayout()

if __name__ == '__main__': 
    bianca = biancApp()
    bianca.run()
