import sys,subprocess
import re


def trc(host):
  # run traceroute command
  trace = subprocess.check_output(['traceroute', host])

  # parse output
  #print trace
  hops = re.findall("\s(\d\d?)\s.*\((.+)\).*\n",trace)
  for hop in hops:
     print hop
  if len(hops) > 0:
    return hops
  else:
    return '-'


def main():   
  # Check args
  if len(sys.argv) != 2:
    print '[-] Usage: trace <host>'
    return '-'
  
  trc(sys.argv[1])



if __name__ == '__main__':
	main()
