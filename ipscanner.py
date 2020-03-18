from netaddr import IPSet, IPRange, iter_iprange
import socket
import os
import re
import argparse
import signal
import sys
import nmap
import pandas as pd
import time
import slack
import yaml
# import texttable
ps = nmap.PortScanner()
# Color Output
col_green = "\033[0;32m"
col_red = "\033[1;31m"
col_norm = "\033[0m"

# Pasring the Arguments
group = argparse.ArgumentParser(description='Subnet Scanner')
parser = group.add_mutually_exclusive_group(required=True)
parser.add_argument('-d', '--hostname', help='e.g. google.com')
parser.add_argument('-n', '--network', help='e.g. 192.168.1.1 or'
                                                          ' 192.168.10.0/24')
parser.add_argument('-i', '--iprange', help='e.g. 192.168.1.1 - 192.168.1.10')
args = vars(group.parse_args())
hostname = str(args['hostname'])
network = str(args['network'])
iprange = str(args['iprange'])
#print(args)

# Catch SIGIN CTRL+C
def signal_handler(sig, frame):
    print('Scan stopped.')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


class IPSCANNER:

    def __init__(self):
        # self.args = args
        self.network = None
        self.ips = None

    def inputarg(self,args):

        if args['hostname'] is not None:
            host = args['hostname']
            self.network = socket.gethostbyname(host)
            self.ipscan()
        elif args['network'] is not None:
            self.network = args['network']
            self.ipscan()
        elif args['iprange'] is not None \
                and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",args['iprange']):
            iprange = args['iprange']
            a = iprange.split('-')
            sip = a[0]
            eip = a[1]
            self.ips = list(iter_iprange(sip,eip,step=1))
            self.ipscan()
        else:
            print("Host is unreachable or Invalid input")
            sys.exit(0)

    # Portscan
    def checkPort(self,ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect((ip, port))
            s.shutdown(1)
            return True
        except:
            return False

    # Reverse Lookup
    def lookup(self,addr):
        try:
            data = socket.gethostbyaddr(str(addr))
            host = repr(data[0])
            host = str(host)
            host = host.strip("'")
            return host
        except:
            return "NA"
    # NMAP Ping Check
    def nmap_check(self,ip):
        nm_response = ps.scan(hosts=str(ip), arguments="-sn -PE")
        nm_res = nm_response['nmap']['scanstats']['uphosts']
        return nm_res


    # Loop through Subnet and try to ping and portscan host
    def ipscan(self):
        masterlist = [["IP ADDRESS","HOSTNAME", "STATUS", "SSH", "TELNET", "HTTP", "HTTPS"]]
        if self.network is not None:
            for ip in IPSet([self.network]):
                nm_response = self.nmap_check(str(ip))
                if nm_response == '1':
                    ports = {'ssh': 22,
                             'telnet': 23,
                             'http': 80,
                             'https': 443}
                    port_check = {}
                    for protocol, port in ports.items():
                        skcheck= self.checkPort(str(ip), port)
                        port_check[protocol]=skcheck
                    host_name = self.lookup(str(ip))
                    slavelist = [str(ip),"ONLINE", host_name, port_check['ssh'], port_check['telnet'],
                                  port_check['http'], port_check['https']]
                    masterlist.append(slavelist)
                else:
                    slavelist = [str(ip), "OFFLINE", "Unknown", False, False,False,False]
                    masterlist.append(slavelist)
        elif self.ips is not None:
            for ip in self.ips:
                nm_response = self.nmap_check(str(ip))
                if nm_response == '1':
                    ports = {'ssh': 22,
                             'telnet': 23,
                             'http': 80,
                             'https': 443}
                    port_check = {}
                    for protocol, port in ports.items():
                        skcheck= self.checkPort(str(ip), port)
                        port_check[protocol]=skcheck
                    host_name = self.lookup(str(ip))
                    slavelist = [str(ip),"ONLINE", host_name, port_check['ssh'], port_check['telnet'],
                                  port_check['http'], port_check['https']]
                    masterlist.append(slavelist)
                else:
                    slavelist = [str(ip), "OFFLINE", "Unknown", False, False,False,False]
                    masterlist.append(slavelist)

        # table = texttable.Texttable()
        # table.add_rows(masterlist,header=True)
        # print(table.draw())
        print(masterlist)
        self.export_csv(masterlist)
        self.slackapi()
        self.hostyaml(masterlist)

    # Export to CSV
    def export_csv(self,masterlist):
        a = time.strftime("%Y%m%d")
        df = pd.DataFrame(masterlist)
        df.to_csv('Inventory{}.csv'.format(a), index=False, header=False)

    def slackapi(self):
        a = time.strftime("%Y%m%d")
        client = os.environ['SLACK_TOKEN']
        sc = slack.WebClient(client)
        response = sc.files_upload(
            channels='#random',
            file='Inventory{}.csv'.format(a))
    # Export to YAML
    def hostyaml(self,masterlist):
        hosts = []
        for i in masterlist:
            hosts.append(i[0])
        fp = os.path.abspath("/home/nirav/PycharmProjects/Lab_setup/site.yaml")
        with open(fp, 'w') as file:
            documents = yaml.dump(hosts, file)




obj1 = IPSCANNER()
obj1.inputarg(args)