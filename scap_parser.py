#!/usr/bin/env python
# Author: Chris Duffy
# Email: Chris.Duffy@Knowledgecg.com
# Date: May 14, 2014
# Purpose: An script that can process and parse SCAP XMLs
# Returnable Data: A dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name, MAC Address]
# Returnable Data: A dictionary of Vulnerabilities [vuln_id] = [Vulnerability Title, Vulnerability Severity, Vulnerability PCI Severity, Vulnerability CVSS Score, Vulnerability CVSS Vector, Vulnerability Published, Vulnerability Added Date, Vulnerability Modified Date, Vulnerability Description, References, Solutions, Solutions links]
# Returnable Data: A dictionary of Vulnerabilities mapped to hosts [Vulnerability IDs] = [IPs, hostnames]
# Returnable Data: A dictionary of hosts mapped to details [IPs]=[MAC Addresses, Hostnames, Vulnerability IDs]
# Name: scap_parser.py
# Disclaimer: This script is intended for professionals and not malicious activity

import sys
import xml.etree.ElementTree as etree
import argparse
import xlsxwriter

class Scap_parser:
    def __init__(self, scap_xml, verbose=0):
        try:
            self.hosts, self.vulnerabilities, self.host_vulns, self.vuln_hosts = self.scap_parser(verbose, scap_xml)
        except Exception as e:
            print(e) 

    def uniq_list(self, import_list):
        # Uniques and sorts any list passed to it
        # Input: list
        # Returned: unique and sorted list
        set_list = set(import_list)
        returnable_list = list(set_list)
        returnable_list.sort()
        return (returnable_list)

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
        vulnerabilities={}
        problems=[]
        services=[]
        ref_dict = {}
        solutions=[]
        host_vuln_ids=[]
        host_vulns={}
        host_vulns_temp={}
        hostnames=[]
        vuln_ids=[]
        affected_hosts=[]
        vuln_hosts={}
        hostname = "Unknown hostname"
        root = tree.getroot()
        hostname_node = None
        if verbose >1:
            print ("[*] Parsing the SCAP XML file: %s") %(scap_xml)
        for host in root.iter('nodes'):
            service ="Unknown"
            for node in host.iter('node'):  
                hostnames=[]
                hostname = "Unknown hostname"
                address = node.get('address')
                hwaddress = node.get('hardware-address')
                if hwaddress == None:
                    hwaddress = "Undiscovered MAC"
                for names in node.iter('names'):
                    for name in names.iter('name'):
                        try:
                            hostname = name.text
                            if hostname:
                                hostnames.append(hostname)
                            else:
                                hostname="Unknown hostname"
                                hostnames.append(hostname)
                        except:
                            if verbose>2:
                                print ("[-] No hostname found")
                            hostname = "Unknown hostname"
                            hostnames.append(hostname)
                for tests in host.iter('tests'):
                    for test in tests.iter('test'):
                        vuln_status = test.get('status')
                        if "vulnerable" in vuln_status:
                            temp = test.get('id')
                            host_vuln_ids.append(temp)
                            vuln_ids.append(temp)
                host_vulns_temp[address]=[hwaddress,hostnames,host_vuln_ids]
                host_vulns = dict(host_vulns_temp.items() + host_vulns.items())
                for item in host.iter('endpoints'):
                    for openport in item.iter('endpoint'):
                        state = openport.get('status')
                        if state.lower() == 'open':
                            protocol = openport.get('protocol')
                            port = openport.get('port')
                            service = openport.find('services').find('service').get('name')
                            service = service.lower()
                        if not hostnames:
                            hostnames.append(hostname)
                        services.append([hostnames,address,protocol,port,service,hwaddress])
        for vulns in root.iter('VulnerabilityDefinitions'):
            for vuln in vulns.iter('vulnerability'):
                vuln_id = vuln.get('id')
                vuln_id=vuln_id.lower()
                vuln_title = vuln.get('title')
                vuln_severity = vuln.get('severity')
                vuln_pciseverity = vuln.get('pciSeverity')
                vuln_cvssscore = vuln.get('cvssScore')
                vuln_cvssvector = vuln.get('cvssVector')
                vuln_published = vuln.get('published')
                vuln_added = vuln.get('added')
                vuln_modified = vuln.get('modified')
                try:
                    vuln_description = vuln.find('description').find('ContainerBlockElement').find('Paragraph').text
                except:
                    if verbose > 4:
                        print ("No Vulnerability Description was found")
                for references in vuln.iter('references'):
                    for reference in references.iter('reference'):
                        source = None
                        locator = None
                        source = reference.get('source')
                        try:
                            locator = reference.text
                        except:
                            if verbose > 4:
                                print ("No Vulnerability Description was found")
                        ref_dict[source]=locator
                for solution in vuln.iter('solution'):
                    for container in solution.iter('ContainerBlockElement'):
                        for paragraph in container.iter('Paragraph'):
                            solutions.append(paragraph.text)
                        for links in container.iter('URLLink'):
                            solution_link = links.get('LinkURL')
                problems.append([vuln_id,vuln_title,vuln_severity,vuln_pciseverity,vuln_cvssscore,vuln_cvssvector,vuln_published, vuln_added, vuln_modified, vuln_description, ref_dict, solutions, solution_link])
        # Generate Host data Dictionary
        for i in range(0, len(services)):
            #Host information
            service = services[i]
            hostnames=service[0]
            address=service[1]
            protocol=service[2]
            port=service[3]
            serv_name=service[4]
            hwaddress=service[5]
            hosts[i]=[hostnames,address,protocol,port,serv_name,hwaddress]                          
            if verbose >2:
                print ("[+] Adding %s with an IP of %s:%s with the service %s and MAC address of %s to the target pool") % (hostnames,address,port,serv_name,hwaddress)
        # Generate Vulnerability Dictionary
        for i in range(0, len(problems)):
            #Vulnerability information
            problem = problems[i]
            vuln_id = problem[0]
            vuln_title = problem[1]
            vuln_severity = problem[2]
            vuln_pciseverity = problem[3]
            vuln_cvssscore = problem[4]
            vuln_cvssvector = problem[5]
            vuln_published = problem[6]
            vuln_added = problem[7]
            vuln_modified = problem[8]
            vuln_description = problem[9]
            ref_dict = problem[10]
            solutions = problem[11]
            solution_link = problem[12]
            vulnerabilities[vuln_id] = [vuln_title,vuln_severity,vuln_pciseverity,vuln_cvssscore,vuln_cvssvector,vuln_published, vuln_added, vuln_modified, vuln_description, ref_dict, solutions, solution_link]
            statement = '''[+] Vulnerability ID: %s
[+] Vulnerability Title: %s''' % (vuln_id,vuln_title)
            if verbose > 3:
                print(statement)
        # Generate Affected Hosts Dictionary
        for ids in vuln_ids:
            for key, value in host_vulns.items():
                for i in value[2]:
                    if ids == i:
                        temporary = "%s:%s" % (key,value[1])
                        affected_hosts.append(temporary)
            affected_hosts=self.uniq_list(affected_hosts)
            vuln_hosts[ids]=affected_hosts
            affected_hosts=[]
        if hosts or vulnerabilities or host_vulns or vuln_hosts:
            if verbose > 4:      
                print ("[*] Results from SCAP XML import: %s") % (hosts)
            if verbose > 0:
                print ("[+] Parsed and identified %s unique ports") % (str(len(services)))
            if vulnerabilities:
                if verbose > 0:
                    print ("[+] Parsed and identified %s vulnerable hosts") % (str(len(host_vulns)))
            else:
                if verbose > 0:
                    print ("[+] Parsed and identified %s hosts") % (str(len(host_vulns)))
            if verbose > 0:
                print ("[+] Parsed and identified %s vulnerabilities") % (str(len(problems)))
        return (hosts, vulnerabilities, host_vulns, vuln_hosts)

    def allReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
            return (self.hosts, self.vulnerabilities, self.host_vulns, self.vuln_hosts)
        except Exception as e:
            print(e)

    def hostsReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
            return (self.hosts)
        except Exception as e:
            print(e)

    def hostsVulnsReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
            return (self.host_vulns)
        except Exception as e:
            print(e)

    def vulnHostsReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
            return (self.vuln_hosts)
        except Exception as e:
            print(e)

    def vulnsReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
            return (self.vulnerabilities)
        except Exception as e:
            print(e)

def combDict(verbose, dictionary_temp, dictionary):
    dictionary = dict(dictionary_temp.items() + dictionary.items())
    return (dictionary)

def uniqDict(verbose, dictionary):
    # Identify unique dictionary values
    processed={}
    temp = [(k, dictionary[k]) for k in dictionary]
    temp.sort()
    for k, v in temp:
        if v in processed.values():
            continue
        processed[k] = v
    return (processed)

def uniqDictKey(verbose, dictionary):
    # Identify unique dictionary values
    processed={}
    temp = [(k, dictionary[k]) for k in dictionary]
    temp.sort()
    for k, v in temp:
        if k in processed.keys():
            continue
        processed[k] = v
    return (processed)

def generateXSLX(verbose, xml, filename, vulnerabilities, vuln_hosts, host_vulns, hosts):
    references=[]
    if not filename:
        filename = "%s.xlsx" % (xml)
    else:
        filename = "%s.xlsx" % (filename)
    workbook = xlsxwriter.Workbook(filename)
    format1 = workbook.add_format({'bold': True})
    format1.set_bg_color('#538DD5')
    format2 = workbook.add_format({'text_wrap': True})
    format2.set_align('left')
    format2.set_align('top')
    format2.set_border(1)
    format3 = workbook.add_format({'text_wrap': True})
    format3.set_align('left')
    format3.set_align('top')
    format3.set_bg_color('#C5D9F1')
    format3.set_border(1)
    worksheet = workbook.add_worksheet()
    worksheet.set_column(0, 0, 20)
    worksheet.set_column(1, 3, 12)
    worksheet.set_column(4, 5, 30)
    worksheet.set_column(6, 8, 19)
    worksheet.set_column(9, 9, 30)
    worksheet.set_column(10, 10, 13)
    worksheet.set_column(11, 12, 24)
    row = 1
    col = 0
    if verbose > 0:
        print ("[*] Creating Workbook: %s") % (filename)
    worksheet.write('A1', "Vulnerability Title", format1)
    worksheet.write('B1', "Severity", format1)
    worksheet.write('C1', "PCI Severity", format1)
    worksheet.write('D1', "CVSS Score", format1)
    worksheet.write('E1', "CVSS Vector", format1)
    worksheet.write('F1', "Affected Hosts", format1)
    worksheet.write('G1', "Published Date", format1)
    worksheet.write('H1', "Added Date", format1)
    worksheet.write('I1', "Modified Date", format1)
    worksheet.write('J1', "Description", format1)
    worksheet.write('K1', "References", format1)
    worksheet.write('L1', "Solutions", format1)
    worksheet.write('M1', "Solution Link", format1)
    worksheet.autofilter('A1:M1')
    for key, value in vuln_hosts.items():        
        #print "Key: %s Value: %s" %(key,value)
        try:
            temp=vulnerabilities[key]
            vuln_title=temp[0]
            vuln_severity=temp[1]
            vuln_pciseverity=temp[2]
            vuln_cvssscore=temp[3]
            vuln_cvssvector=temp[4]
            vuln_published=temp[5]
            vuln_added=temp[6]
            vuln_modified=temp[7]
            vuln_description=temp[8]
            ref_dict=temp[9]
            solutions=temp[10]
            solution_link=temp[11]
        except:
            if verbose > 3:
                print "[!] An error occurred parsing vulnerbility ID: %s" %(key)
        hosts_temp = ",".join(vuln_hosts.get(key))
        hosts_temp = hosts_temp.split(':')
        hostnames_temp = str(hosts_temp[1]).strip('[]')
        hosts = "%s:(%s)"% (hosts_temp[0],hostnames_temp)
        print hosts
        for k, v in ref_dict.items():
            temps="%s:%s" % (k,v)
            references.append(temps)
        ref = ", ".join(references)
        solutions = "".join(solutions)
        try:
            if row % 2 != 0:
                temp_format = format2
            else:
                temp_format = format3
            worksheet.write(row, col,     vuln_title, temp_format)
            worksheet.write(row, col + 1, vuln_severity, temp_format)
            worksheet.write(row, col + 2, vuln_pciseverity, temp_format)
            worksheet.write(row, col + 3, vuln_cvssscore, temp_format)
            worksheet.write(row, col + 4, vuln_cvssvector, temp_format)
            worksheet.write(row, col + 5, hosts, temp_format)
            worksheet.write(row, col + 6, vuln_published, temp_format)
            worksheet.write(row, col + 7, vuln_added, temp_format)
            worksheet.write(row, col + 8, vuln_modified, temp_format)
            worksheet.write(row, col + 9, vuln_description, temp_format)
            worksheet.write(row, col + 10, ref, temp_format)
            worksheet.write(row, col + 11, solutions, temp_format)
            worksheet.write(row, col + 12, solution_link, temp_format)
            row += 1
        except:
            if verbose > 3:
                print "[!] An error occurred writing data for %s" % (vuln_title)
    workbook.close()

if __name__ == '__main__': 
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-x reports.xml] -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-x", "--xml", type=str, help="Generate a dictionary of data based on a SCAP XML import, more than one file may be passed, separated by a comma", action="store", dest="xml")
    parser.add_argument("-f", "--filename", type=str, help="Filename for output of exports", action="store", dest="filename")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.43b')
    args = parser.parse_args()

    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    # Set Constructors
    xml = args.xml                   # nmap XML
    verbose = args.verbose           # Verbosity level
    filename = args.filename         # Filename for Exports
    xml_list=[]                      # List to hold XMLs

    # Set return holder
    hosts=[]                            # List to hold instances
    hosts_temp={}                       # Temporary dictionary, which holds returned data from specific instances
    hosts_dict={}                       # Dictionary, which holds the combined returned dictionaries
    processed_hosts={}                  # The dictionary, which holds the unique values from all processed XMLs
    vulnerabilities_dict={}
    host_vulns_dict={}
    vuln_hosts_dict={}
    processed_vuln_hosts={}
    processed_host_vulns={}
    processed_vulnerabilities={}
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
            sys.exit("[!] File: %s is not a SCAP XML" % (x))

    # Processing of each instance returned to create a composite dictionary
    for inst in hosts:
        hosts_temp = inst.hostsReturn()
        vulnerabilities_temp = inst.vulnsReturn()
        host_vulns_temp = inst.hostsVulnsReturn()
        vuln_hosts_temp = inst.vulnHostsReturn()
        hosts_dict=combDict(verbose, hosts_temp, hosts_dict)
        vulnerabilities_dict=combDict(verbose, vulnerabilities_temp, vulnerabilities_dict)
        host_vulns_dict=combDict(verbose, host_vulns_temp, host_vulns_dict)
        vuln_hosts_dict=combDict(verbose, vuln_hosts_temp, vuln_hosts_dict)

    processed_hosts=uniqDict(verbose, hosts_dict)
    processed_vulnerabilities=uniqDict(verbose, vulnerabilities_dict)
    processed_host_vulns=uniqDict(verbose, host_vulns_dict)
    processed_vuln_hosts=uniqDictKey(verbose, vuln_hosts_dict)

    generateXSLX(verbose, xml, filename, processed_vulnerabilities, processed_vuln_hosts, processed_host_vulns, processed_hosts)

    # Printout of dictionary values
    if verbose>0:
        for target in processed_hosts.values():
            print "[*] Hostname: %s IP: %s Protocol: %s Port: %s Service: %s MAC Address: %s" % (target[0],target[1],target[2],target[3],target[4],target[5])

