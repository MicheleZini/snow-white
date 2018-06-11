# biancaneve
*Network traffic geolocation tool using Python(2.7)/Kivy*  

biancaneve is a lulz-driven project born out of curiosity and desire to experiment/teach myself python, databases, networking and overall keep me busy while i wait for a company to hire me as ~~helpdesk support~~ pentester. please note that this is a (somewhat) working **prototype** and cannot be considered a reliable tool. 

i do have further and better versions of this project under development, but i rethought the entire system to be scalable, reliable and overall better. so do not hold your breath for that. as for now, this is pretty much as far as u can push python as a GUI environment. I want to clarify that *do not recommend taking this path* for your project, but hey take a look and maybe be inspired

This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.

## usage:
to run the main GUI and fancy graphics:

```sudo run_guy.py```

If you wish to take a peak at the sniffer output in the terminal, biancaneve.py can be run as a standalone script by simply:

```sudo biancaneve.py```
 
## requires:
**kivy framework:**

```sudo add-apt-repository ppa:kivy-team/kivy & sudo apt-get update & sudo apt-get install python-kivy```
 
**pip -> geoIP2:**

```sudo apt-get install python-pip & pip install geoip2```

## extras:
**traceroute:**

*One feature available is tracing the path to a remote host, this is accomplished by launching the traceroute command in bash. If you do try this please note that the sniffer will be "frozen" until the trace is complete. be patient.*

```sudo apt-get install traceroute```

