#!/usr/bin/env python
# Author: Chris Duffy
# Email: Chris.Duffy@Knowledgecg.com
# Date: May 14, 2014
# Purpose: An script that can process and parse SCAP XMLs
# Returnable Data: A dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name]
# Name: scap_parser.py
# Disclaimer: This script is intended for professionals and not malicious activity

import sys
import xml.etree.ElementTree as etree
import argparse

class Scap_parser:
    def __init__(self, scap_xml, verbose=0):
        try:
            self.hosts = self.scap_parser(verbose, scap_xml)
        except Exception as e:
            print(e) 

    def scap_parser(self, verbose, scap_xml):
        # Parse the SCAP xml file and extract hosts and place them in a dictionary
        # Input: SCAP XML file and verbose flag
        # Return: Dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name]
        if not scap_xml:
            sys.exit("[!] Cannot open SCAP XML file: %s \n[-] Ensure that your are passing the correct file and format" % (scap_xml))       
        try:
            tree = etree.parse(scap_xml)
        except:
            sys.exit("[!] Cannot open SCAP XML file: %s \n[-] Ensure that your are passing the correct file and format" % (scap_xml))       
        hosts={}
        services=[]
        root = tree.getroot()
        hostname_node = None
        if verbose >1:
            print ("[*] Parsing the SCAP XML file: %s") %(scap_xml)
        for host in root.iter('nodes'):
            hostname = "Unknown"
            service ="Unknown"  
            address = host.find('node').get('address')
            for name in host.iter('names'):
                try:        
                    hostname = name.find('name').text
                except:
                    if verbose>2:
                        print ("[-] No hostname found")
            for item in host.iter('endpoints'):
                for openport in item.iter('endpoint'):
                    state = openport.get('status')
                    if state.lower() == 'open':
                        protocol = openport.get('protocol')
                        port = openport.get('port')
                        service = openport.find('services').find('service').get('name')
                        service = service.lower()
                    services.append([hostname,address,protocol,port,service])
        for i in range(0, len(services)):
            service = services[i]
            hostname=service[0]
            address=service[1]
            protocol=service[2]
            port=service[3]
            serv_name=service[4]
            hosts[i]=[service[0],service[1],service[2],service[3],service[4]]
            if verbose >0:
                print ("[+] Adding %s with an IP of %s:%s with the service %s to the potential target pool") % (hostname,address,port,serv_name)
        if hosts:
            if verbose > 3:      
                print ("[*] Results from SCAP XML import: %s") % (hosts)
            return hosts
            if verbose > 0:
                print ("[+] Parsed and imported %s unique ports") % (str(i))
        else:
            if verbose > 0:
                print ("[-] No ports were discovered in the SCAP XML file")

    def hostsReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
            return self.hosts
        except Exception as e:
            print(e)

if __name__ == '__main__': 
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-x reports.xml] -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-x", "--xml", type=str, help="Generate a dictionary of data based on a SCAP XML import, more than one file may be passed, separated by a comma", action="store", dest="xml")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.42b')
    args = parser.parse_args()

    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    # Set Constructors
    xml = args.xml                   # nmap XML
    verbose = args.verbose           # Verbosity level
    xml_list=[]                         # List to hold XMLs

    # Set return holder
    hosts=[]                            # List to hold instances
    hosts_temp={}                       # Temporary dictionary, which holds returned data from specific instances
    hosts_dict={}                       # Dictionary, which holds the combined returned dictionaries
    processed_hosts={}                  # The dictionary, which holds the unique values from all processed XMLs

    # Instantiation for proof of concept
    if "," in xml:
        xml_list = xml.split(',')
    else:
        xml_list.append(xml)
    for x in xml_list:
        try:
            tree_temp = etree.parse(x)
        except:
            sys.exit("[!] Cannot open XML file: %s \n[-] Ensure that your are passing the correct file and format" % (x))       
        try:
            root = tree_temp.getroot()
            name=root.get("scanner")
            if name is not None and "nmap" in name:
                sys.exit("[!] File being processed is a NMAP XML")            
            else:
                hosts.append(Scap_parser(x, verbose))
        except:
            sys.exit("[!] File being processed is not a SCAP XML") 


    # Processing of each instance returned to create a composite dictionary
    for inst in hosts:
        hosts_temp = inst.hostsReturn()
        hosts_dict = dict(hosts_temp.items() + hosts_dict.items())

    # Identify unique dictionary values
    temp = [(k, hosts_dict[k]) for k in hosts_dict]
    temp.sort()
    for k, v in temp:
        if v in processed_hosts.values():
            continue
        processed_hosts[k] = v

    # Printout of dictionary values
    if verbose>0:
        for target in processed_hosts.values():
            print "[*] Hostname: %s IP: %s Protocol: %s Port: %s Service: %s" % (target[0],target[1],target[2],target[3],target[4])

