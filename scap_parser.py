#!/usr/bin/env python
# Author: Chris Duffy
# Email: Chris.Duffy@Knowledgecg.com
# Date: May 14, 2014
# Purpose: An script that can process and parse SCAP XMLs
# Returnable Data: A dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name, MAC Address]
# Returnable Data: A dictionary of Vulnerabilities [vuln_id] = [Vulnerability Title, Vulnerability Severity, Vulnerability PCI Severity, Vulnerability CVSS Score, Vulnerability CVSS Vector, Vulnerability Published, Vulnerability Added Date, Vulnerability Modified Date, Vulnerability Description, References, Solutions, Solutions links]
# Returnable Data: A dictionary of Vulnerabilities mapped to hosts [Vulnerability IDs] = [IPs, hostnames]
# Returnable Data: A dictionary of hosts mapped to details [IPs]=[MAC Addresses, Hostnames, Vulnerability IDs]
#A dictionary of hosts mapped to details [IPs]=[MAC Addresses, Hostnames, Ports, Services, Port:Protocol, Port:Protocol:Service, Vulnerability IDs, os_vendor, os_product, os_version]
#A dictionary of services mapped to hosts [service]=[IPs, hostnames, ip:(hostnames)]
# Name: scap_parser.py
# Disclaimer: This script is intended for professionals and not malicious activity

import sys
import xml.etree.ElementTree as etree
import argparse
import urllib
from StringIO import StringIO    
try:
    import xlsxwriter
except:
    sys.exit("[!] Install the xlsx writer library as root or through sudo: pip install xlsxwriter")
try:
    import pycurl
except:
    sys.exit("[!] Install the pycurl library as root or through sudo: pip install pycurl")

class Scap_parser:
    def __init__(self, scap_xml, verbose=0):
        try:
            self.hosts, self.vulnerabilities, self.host_vulns, self.vuln_hosts, self.host_details, self.service_list, self.vuln_dict = self.scap_parser(verbose, scap_xml)
        except Exception as e:
            print(e) 

    def uniqDict(self, verbose, dictionary):
        # Identify unique dictionary values
        processed={}
        temp = [(k, dictionary[k]) for k in dictionary]
        temp.sort()
        for k, v in temp:
            if v in processed.values():
                continue
            processed[k] = v
        return (processed)

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
        status_id_list=[]
        host_vulns={}
        host_vulns_temp={}
        hostnames=[]
        vuln_ids=[]
        affected_hosts=[]
        exploits=[]
        vuln_hosts={}
        host_details={}
        vuln_dict={}
        temp_ref_dict={}
        solution_link=None
        hostname = "Unknown hostname"
        root = tree.getroot()
        hostname_node = None
        high_cert = None
        if verbose >0:
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
                # Identify most likely fingerprint
                for fingerprints in node.iter('fingerprints'):
                    for oss in fingerprints.iter('os'):
                        temp_cert = oss.get('certainty')
                        if high_cert is None or temp_cert > high_cert:
                            high_cert = temp_cert
                    for oss in fingerprints.iter('os'):
                        temp_cert = oss.get('certainty')
                        if temp_cert == high_cert:
                            os_vendor = oss.get('vendor')
                            os_product = oss.get('family')
                            os_version = oss.get('version')
                for tests in node.iter('tests'): # WAS host.iter check to make sure it still works
                    for test in tests.iter('test'):
                        vuln_status = test.get('status')
                        if "not-vulnerable" not in vuln_status:
                            temp = test.get('id')
                            temp=temp.lower()
                            status_id="%s:%s" % (temp, vuln_status)
                            vuln_dict[temp]=[vuln_status]
                            host_vuln_ids.append(temp)
                            vuln_ids.append(temp)
                            status_id_list.append(status_id)
                        elif "skipped" in vuln_status or "error" in vuln_status:
                            temp = test.get('id')
                            temp=temp.lower()
                            status_id="%s:%s" % (temp, vuln_status)
                            vuln_dict[temp]=[vuln_status]
                            host_vuln_ids.append(temp)
                            vuln_ids.append(temp)
                            status_id_list.append(status_id)
                        else:
                            if verbose > 4:
                                temp = test.get('id')
                                temp=temp.lower()
                                print ("Host %s:%s was not vulnerable to: %s") % (address, hostname, temp)
                           
                #HOST VULNS DICT
                host_vulns_temp[address]=[hwaddress, hostnames, host_vuln_ids, status_id_list]
                host_vulns = dict(host_vulns_temp.items() + host_vulns.items())
                for item in host.iter('endpoints'):
                    service_list=[]
                    port_list=[]
                    port_protocol_list=[]
                    port_protocol_service_list=[]
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
                        port_protocol="%s:%s" % (port,protocol)
                        port_protocol_service="%s:%s:%s" % (port,protocol,service)
                        service_list.append(service)
                        port_list.append(port)
                        port_protocol_list.append(port_protocol)
                        port_protocol_service_list.append(port_protocol_service)
                # Complete host details
                host_details[address]=[hwaddress, hostnames, port_list, service_list, port_protocol_list, port_protocol_service_list, len(host_vuln_ids),os_vendor, os_product, os_version]
        service_list = self.uniq_list(service_list)
        for vulns in root.iter('VulnerabilityDefinitions'):
            for vuln in vulns.iter('vulnerability'):
                ref_dict.clear()
                solutions=[]
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
                temp_ref_dict[vuln_id]=dict(ref_dict)
                ref_dict.clear
                for solution in vuln.iter('solution'):
                    for container in solution.iter('ContainerBlockElement'):
                        for paragraph in container.iter('Paragraph'):
                            solutions.append(paragraph.text)
                        for links in container.iter('URLLink'):
                            solution_link = links.get('LinkURL')
                            if solution_link is None:
                                solution_link = links.get('LinkTitle')                              
                problems.append([vuln_id,vuln_title,vuln_severity,vuln_pciseverity,vuln_cvssscore,vuln_cvssvector,vuln_published, vuln_added, vuln_modified, vuln_description, solutions, solution_link])
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
            if verbose >4:
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
            solutions = problem[10]
            solution_link = problem[11]
            ref_dict2 = temp_ref_dict.get(vuln_id)
            temp_status = vuln_dict.get(vuln_id)            
            vulnerabilities[vuln_id] = [vuln_title,vuln_severity,vuln_pciseverity,vuln_cvssscore,vuln_cvssvector,vuln_published, vuln_added, vuln_modified, vuln_description, ref_dict2, solutions, solution_link, temp_status]
            statement = '''[+] Vulnerability ID: %s
[+] Vulnerability Title: %s''' % (vuln_id,vuln_title)
            if verbose > 4:
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
        return (hosts, vulnerabilities, host_vulns, vuln_hosts, host_details, service_list, vuln_dict)

    def allReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
            return (self.hosts, self.vulnerabilities, self.host_vulns, self.vuln_hosts, self.host_details, self.service_list, self.vuln_dict)
        except Exception as e:
            print(e)

    def vulnDictReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The vulnerability ids matched to statuses
        try:
            return (self.vuln_dict)
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
        # Returned: The processed hosts to vulnerabilities
        try:
            return (self.host_vulns)
        except Exception as e:
            print(e)

    def vulnHostsReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed vulnerabilities to hosts
        try:
            return (self.vuln_hosts)
        except Exception as e:
            print(e)

    def vulnsReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed vulnerabilities
        try:
            return (self.vulnerabilities)
        except Exception as e:
            print(e)

    def hostDetailsReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
            return (self.host_details)
        except Exception as e:
            print(e)

    def serviceListReturn(self):
        # A controlled return method
        # Input: None
        # Returned: The processed services
        try:
            return (self.service_list)
        except Exception as e:
            print(e)

# Local Funcs
def serviceDict(verbose, service_list, host_details):
    # Create a dictionary services matched to lists of hosts
    # Input: Service List and Processed host details
    # Returned: service[service]=[IP:(hostnames)]
    service_dict={}
    for ser in service_list:
        valid=[]
        for key, value in host_details.items():
            ip=key
            hostnames=", ".join(value[1])
            services=value[3]
            host="%s:(%s)" % (ip, hostnames)
            if ser in services:
                valid.append(host)
        service_dict[ser]=[valid]
    return (service_dict)

def uniqList(verbose, import_list):
    # Uniques and sorts any list passed to it
    # Input: list
    # Returned: unique and sorted list
    set_list = set(import_list)
    returnable_list = list(set_list)
    returnable_list.sort()
    return (returnable_list)

def combDictService(verbose, dictionary_temp, dictionary):
    key_list=[]
    for k, v in dictionary_temp.items():
        key_list.append(k)
        for key in keylist:
            temp_value.extend(dictionary_temp.get(k))
            value
            
    else:
        for k, v in dictionary_temp.items():
            dictionary = dict(dictionary_temp.items() + dictionary.items())
    return (dictionary)

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

def curlModule(verbose, refDict):
    # Curl for Metasploit modules based on a reference passed
    # Input: Verbosity and reference list
    # Returned: exploit list
    exploitList=[]
    uniqRefsList=[]
    tempRefList=[]
    for k,v in refDict.items():
        if "CVE" in k:
            temp_ref = v
            tempRefList.append(temp_ref)
        elif "BID" in k:
            temp_ref="BID %s" % (v)
            tempRefList.append(temp_ref)
        elif "OSVDB" in k:
            temp_ref="OSVDB %s" % (v)
            tempRefList.append(temp_ref)
        else:
            pass
    if tempRefList is not None:
        uniqRefsList=uniqList(verbose, tempRefList)
        for ref in uniqRefsList:
            ref_encode=urllib.urlencode({'q':ref})
            query = "http://www.rapid7.com/db/search?utf8=%E2%9C%93&"+ref_encode+"&t=m"
            storage = StringIO()
            c = pycurl.Curl()
            c.setopt(c.URL, query)
            c.setopt(c.WRITEFUNCTION, storage.write)
            c.perform()
            c.close()
            content = storage.getvalue()
            #print content #DEBUG
    else:
        exploitList.append("No Exploit Was Found")
    return (exploitList)

def generateXSLX(verbose, xml, filename, vulnerabilities, vuln_hosts, host_vulns, hosts, host_details, service_dict, vuln_dict):
    references=[]
    exploit_temp=['No Exploits Found']
    if not filename:
        filename = "%s.xlsx" % (xml)
    else:
        filename = "%s.xlsx" % (filename)
    workbook = xlsxwriter.Workbook(filename)
    # Row one formatting
    format1 = workbook.add_format({'bold': True})
    format1.set_bg_color('#538DD5')
    # Even row formatting
    format2 = workbook.add_format({'text_wrap': True})
    format2.set_align('left')
    format2.set_align('top')
    format2.set_border(1)
    # Odd row formatting
    format3 = workbook.add_format({'text_wrap': True})
    format3.set_align('left')
    format3.set_align('top')
    format3.set_bg_color('#C5D9F1')
    format3.set_border(1)
    worksheet = workbook.add_worksheet("Vulnerabilities")
    worksheet2 = workbook.add_worksheet("Hosts")
    worksheet3 = workbook.add_worksheet("Services")
    worksheet4 = workbook.add_worksheet("MiTM Targets")
    worksheet5 = workbook.add_worksheet("Exploitable Targets")
    worksheet6 = workbook.add_worksheet("Vulnerable Software Versions")
    # Column width for worksheet 1
    worksheet.set_column(0, 0, 20)
    worksheet.set_column(1, 3, 12)
    worksheet.set_column(4, 5, 30)
    worksheet.set_column(6, 8, 19)
    worksheet.set_column(9, 9, 30)
    worksheet.set_column(10, 10, 13)
    worksheet.set_column(11, 12, 24)
    # Column width for worksheet 2
    worksheet2.set_column(0, 0, 15)
    worksheet2.set_column(1, 1, 18)
    worksheet2.set_column(2, 2, 30)
    worksheet2.set_column(3, 4, 13)
    worksheet2.set_column(5, 5, 22)
    worksheet2.set_column(6, 9, 16)
    # Column width for worksheet 3
    worksheet3.set_column(0, 1, 30)
    # Column width for worksheet 4
    worksheet4.set_column(0, 0, 15)
    worksheet4.set_column(1, 1, 18)
    worksheet4.set_column(2, 2, 30)
    worksheet4.set_column(3, 3, 22)
    # Column width for worksheet 5
    worksheet5.set_column(0, 0, 30)
    worksheet5.set_column(1, 1, 25)
    worksheet5.set_column(2, 2, 30)
    worksheet5.set_column(3, 3, 19)
    worksheet5.set_column(4, 4, 20)
    # Column width for worksheet 6
    worksheet6.set_column(0, 0, 30)
    worksheet6.set_column(1, 1, 25)
    worksheet6.set_column(2, 2, 30)
    worksheet6.set_column(3, 3, 20)
    # Define starting location for Worksheet one
    row = 1
    col = 0
    # Define starting location for Worksheet two
    row2 = 1
    col2 = 0 
    # Define starting location for Worksheet three
    row3 = 1
    col3 = 0
    # Define starting location for Worksheet four
    row4 = 1
    col4 = 0
    # Define starting location for Worksheet five
    row5 = 1
    col5 = 0
    # Define starting location for Worksheet five
    row6 = 1
    col6 = 0
    if verbose > 0:
        print ("[*] Creating Workbook: %s") % (filename)
    # Generate Row 1 for worksheet one
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
    # Generate Row 1 for worksheet two
    #host_details[address]=[hwaddress, hostnames, port_list, service_list, port_protocol_list, port_protocol_service_list, len(host_vuln_ids)]
    worksheet2.write('A1', "IP", format1)
    worksheet2.write('B1', "MAC Address", format1)
    worksheet2.write('C1', "Hostnames", format1)
    worksheet2.write('D1', "Ports", format1)
    worksheet2.write('E1', "Services", format1)
    worksheet2.write('F1', "Port:Protocol:Service", format1)
    worksheet2.write('G1', "Vulnerabilities", format1)
    worksheet2.write('H1', "Vendor", format1)
    worksheet2.write('I1', "Product", format1)
    worksheet2.write('J1', "Version", format1)
    worksheet2.autofilter('A1:J1')
    # Generate Row 1 for worksheet three
    worksheet3.write('A1', "Service", format1)
    worksheet3.write('B1', "Hosts", format1)
    worksheet3.autofilter('A1:B1')
    # Generate Row 1 for worksheet four
    worksheet4.write('A1', "IP", format1)
    worksheet4.write('B1', "MAC Address", format1)
    worksheet4.write('C1', "Hostnames", format1)
    worksheet4.write('D1', "Port:Protocol:Service", format1)
    worksheet4.autofilter('A1:D1')
    # Generate Row 1 for worksheet five
    worksheet5.write('A1', "Vulnerability Title", format1)
    worksheet5.write('B1', "Affected Hosts", format1)
    worksheet5.write('C1', "Description", format1)
    worksheet5.write('D1', "Exploit", format1)
    worksheet5.write('E1', "References", format1)
    worksheet5.autofilter('A1:E1')
    # Generate Row 1 for worksheet six
    worksheet6.write('A1', "Vulnerability Title", format1)
    worksheet6.write('B1', "Affected Hosts", format1)
    worksheet6.write('C1', "Description", format1)
    worksheet6.write('D1', "References", format1)
    worksheet6.autofilter('A1:D1')
    # Generate workseet 5
    for key, value in vuln_hosts.items():
        temp = str(vuln_dict.get(key)).strip('[]')
        if "vulnerable-version" in temp:
            try:
                temp=vulnerabilities[key]
                vuln_title=temp[0]
                vuln_description=temp[8]
                ref_dict_temp=temp[9]
            except:
                if verbose > 3:
                    print "[!] An error occurred parsing vulnerbility ID: %s" %(key)
            hosts_temp = ",".join(vuln_hosts.get(key))
            hosts_temp = hosts_temp.split(':')
            hostnames_temp = str(hosts_temp[1]).strip('[]')
            hosts = "%s:(%s)"% (hosts_temp[0],hostnames_temp)
            for k, v in ref_dict_temp.items():
                temps="%s:%s" % (k,v)
                references.append(temps)
            ref = ", ".join(references)
            if ref is None:
                ref="No References Supplied"
            try:
                if row6 % 2 != 0:
                    temp_format = format2
                else:
                    temp_format = format3
                worksheet6.write(row6, col6,     vuln_title, temp_format)
                worksheet6.write(row6, col6 + 1, hosts, temp_format)
                worksheet6.write(row6, col6 + 2, vuln_description, temp_format)
                worksheet6.write(row6, col6 + 3, ref, temp_format)
                row6 += 1
                references=[]
            except:
                if verbose > 3:
                    print "[!] An error occurred writing data for %s in Worksheet 6" % (vuln_title)

    # Generate workseet 5
    for key, value in vuln_hosts.items():
        temp = str(vuln_dict.get(key)).strip('[]')
        if "exploit" in temp:
            try:
                temp=vulnerabilities[key]
                vuln_title=temp[0]
                vuln_description=temp[8]
                ref_dict_temp=temp[9]
            except:
                if verbose > 3:
                    print "[!] An error occurred parsing vulnerbility ID: %s" %(key)
            hosts_temp = ",".join(vuln_hosts.get(key))
            hosts_temp = hosts_temp.split(':')
            hostnames_temp = str(hosts_temp[1]).strip('[]')
            hosts = "%s:(%s)"% (hosts_temp[0],hostnames_temp)
            #exploit_temp = curlModule(verbose, ref_dict_temp)
            exploits = ", ".join(exploit_temp)
            for k, v in ref_dict_temp.items():
                temps="%s:%s" % (k,v)
                references.append(temps)
            ref = ", ".join(references)
            if ref is None or ref == "":
                ref="No References Supplied"
            try:
                if row5 % 2 != 0:
                    temp_format = format2
                else:
                    temp_format = format3
                worksheet5.write(row5, col5,     vuln_title, temp_format)
                worksheet5.write(row5, col5 + 1, hosts, temp_format)
                worksheet5.write(row5, col5 + 2, vuln_description, temp_format)
                worksheet5.write(row5, col5 + 3, exploits, temp_format)
                worksheet5.write(row5, col5 + 4, ref, temp_format)
                row5 += 1
                references=[]
            except:
                if verbose > 3:
                    print "[!] An error occurred writing data for %s in Worksheet 5" % (vuln_title)
    # Generate workseet 4
    for key, value in host_details.items():
        ip=key
        hwaddress=value[0]
        hostnames=", ".join(value[1])
        port_protocol_service_list=", ".join(value[5])
        if "Undiscovered" not in hwaddress:
            try:
                if row4 % 2 != 0:
                    temp_format = format2
                else:
                    temp_format = format3
                worksheet4.write(row4, col4    , ip, temp_format)
                worksheet4.write(row4, col4 + 1, hwaddress, temp_format)
                worksheet4.write(row4, col4 + 2, hostnames, temp_format)
                worksheet4.write(row4, col4 + 3, port_protocol_service_list, temp_format)
            except:
                if verbose > 3:
                    print "[!] An error occurred writing data for %s in Worksheet 2" % (ip)
            row4 += 1
    # Generate worksheet 2
    for key, value in host_details.items():
        ip=key
        hwaddress=value[0]
        hostnames=", ".join(value[1])
        port_list=", ".join(value[2])
        service_list=", ".join(value[3])
        port_protocol_service_list=", ".join(value[5])
        num_vulns=value[6]
        os_vendor=value[7]
        os_product=value[8]
        os_version=value[9]
        try:
            if row2 % 2 != 0:
                temp_format = format2
            else:
                temp_format = format3
            worksheet2.write(row2, col2    , ip, temp_format)
            worksheet2.write(row2, col2 + 1, hwaddress, temp_format)
            worksheet2.write(row2, col2 + 2, hostnames, temp_format)
            worksheet2.write(row2, col2 + 3, port_list, temp_format)
            worksheet2.write(row2, col2 + 4, service_list, temp_format)
            worksheet2.write(row2, col2 + 5, port_protocol_service_list, temp_format)
            worksheet2.write(row2, col2 + 6, int(num_vulns), temp_format)
            worksheet2.write(row2, col2 + 7, os_vendor, temp_format)
            worksheet2.write(row2, col2 + 8, os_product, temp_format)
            worksheet2.write(row2, col2 + 9, float(os_version), temp_format)
        except:
            if verbose > 3:
                print "[!] An error occurred writing data for %s in Worksheet 2" % (ip)
        row2 += 1
    # Write worksheet 3
    for key, value in service_dict.items():
        service=key   
        host = ", ".join(value[0])
        try:
            if row3 % 2 != 0:
                temp_format = format2
            else:
                temp_format = format3
            worksheet3.write(row3, col3,     service, temp_format)
            worksheet3.write(row3, col3 + 1, host, temp_format)
        except:
            if verbose > 3:
                print "[!] An error occurred writing data for %s in Worksheet 3" % (service)
        row3 += 1
    # Generate Worksheet 1
    for key, value in vuln_hosts.items():        
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
            ref_dict_temp_ws1=temp[9]
            solutions=temp[10]
            solution_link=temp[11]
        except:
            if verbose > 3:
                print "[!] An error occurred parsing vulnerbility ID: %s" %(key)
        hosts_temp = ",".join(vuln_hosts.get(key))
        hosts_temp = hosts_temp.split(':')
        hostnames_temp = str(hosts_temp[1]).strip('[]')
        hosts = "%s:(%s)"% (hosts_temp[0],hostnames_temp)
        for k, v in ref_dict_temp_ws1.items():
            temps="%s:%s" % (k,v)
            references.append(temps)
        ref = ", ".join(references)
        solutions = "".join(solutions)
        try:
            if row % 2 != 0:
                temp_format = format2
            else:
                temp_format = format3
            if ref is None or ref == "":
                ref="No References Supplied"
            worksheet.write(row, col,     vuln_title, temp_format)
            worksheet.write(row, col + 1, int(vuln_severity), temp_format)
            worksheet.write(row, col + 2, int(vuln_pciseverity), temp_format)
            worksheet.write(row, col + 3, float(vuln_cvssscore), temp_format)
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
            references=[]
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
    parser.add_argument('--version', action='version', version='%(prog)s 0.45b')
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
    service_list=[]                     # A List to hold services
    hosts_temp={}                       # Temporary dictionary, which holds returned data from specific instances
    hosts_dict={}                       # Dictionary, which holds the combined returned dictionaries
    processed_hosts={}                  # The dictionary, which holds the unique values from all processed XMLs
    vulnerabilities_dict={}
    vuln_dict={}
    host_vulns_dict={}
    vuln_hosts_dict={}
    host_details_dict={}
    processed_host_details={}
    processed_host_details={}
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
        host_details_temp = inst.hostDetailsReturn()
        service_list_temp = inst.serviceListReturn()
        vuln_dict_temp = inst.vulnDictReturn()

        # Combining Dictionaries and Lists per iteration
        hosts_dict=combDict(verbose, hosts_temp, hosts_dict)
        vulnerabilities_dict=combDict(verbose, vulnerabilities_temp, vulnerabilities_dict)
        host_vulns_dict=combDict(verbose, host_vulns_temp, host_vulns_dict)
        vuln_hosts_dict=combDict(verbose, vuln_hosts_temp, vuln_hosts_dict)
        host_details_dict=combDict(verbose, host_details_temp, host_details_dict)
        vuln_dict=combDict(verbose, vuln_dict_temp, vuln_dict)
        service_list.extend(service_list_temp)

    # Remove duplicates and create final dicitonaries
    processed_service_list=uniqList(verbose, service_list)
    processed_hosts=uniqDict(verbose, hosts_dict)
    processed_vulnerabilities=uniqDict(verbose, vulnerabilities_dict)
    processed_host_vulns=uniqDict(verbose, host_vulns_dict)
    processed_host_details=uniqDict(verbose, host_details_dict)
    processed_vuln_hosts=uniqDictKey(verbose, vuln_hosts_dict)
    processed_service_dict=serviceDict(verbose, service_list, processed_host_details)
    processed_vuln_dict=uniqDictKey(verbose, vuln_dict)

    # Generate XSLX
    generateXSLX(verbose, xml, filename, processed_vulnerabilities, processed_vuln_hosts, processed_host_vulns, processed_hosts, processed_host_details, processed_service_dict, processed_vuln_dict)

    # Printout of dictionary values
    if verbose>4:
        for target in processed_hosts.values():
            print "[*] Hostname: %s IP: %s Protocol: %s Port: %s Service: %s MAC Address: %s" % (target[0],target[1],target[2],target[3],target[4],target[5])

