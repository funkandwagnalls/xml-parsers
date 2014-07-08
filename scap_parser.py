#!/usr/bin/env python
# Author: Chris Duffy
# Email: christopher.s.duffy@gmail.com
# Date: May 14, 2014
# Purpose: An script that can process and parse SCAP XMLs
# Name: scap_parser.py
# Disclaimer: This script is intended for professionals and not malicious activity and material generated from this tool will be parsed from content out of other tools.
# Returned Data: "xml" XML file name that was passed by the parsing engine, used as a default name if no filename is passed
# Returned Data: "filename" filename that will be used to write other files
# Returned Data: "vulnerabilities" A dictionary of vulnerabilities{vulnerability id : [vulnerability title, vulnerability severity,vulnerability pciseverity, Vulnerability CVSS Score,Vulnerability CVSS Vector, Vulnerability Published Date, Vulnerability Modified Date, Vulnerability Updated Date, Vulnerability Description, References{Ref Type:Reference}, Solutions, Solution link, Vulnerability Status based on how it was identified]}
# Returned Data: "vuln_hosts" A dictionary of Vulnerabilities mapped to hosts vuln_hosts{Vulnerability IDs = [IPs, [hostname1, hostname2]]}
# Returned Data: "host_vulns" A dictionary of hosts mapped to details host_vulns{IPs=[MAC Addresses, [Hostnames], [Vulnerability IDs]]}
# Returned Data: "hosts" A dictionary of hosts{iterated number = [[Hostnames], IP address, protocol, port, service name, MAC Address]}
# Returned Data: "host_details" A dictionary of hosts mapped to details host_details{IPs=[MAC Addresses, [Hostnames], [Ports], [Services], [Port:Protocol], [Port:Protocol:Service], [Vulnerability IDs], Operating System Vendor, Operating System Product, Operating System Product]}
# Returned Data: "service_dict" A dictionary of services mapped to hosts service_dict{service=[IPs, [hostnames], ip:(hostname1, hostname2)]}
# Returned Data: "vuln_dict" A dictionary of vulnerability IDs mapped to vulnerability statuses vuln_dict{Vulnerability ID=Vulnerability Status} 
# Returned Data: "docVar" The type of office product that should be generated.


import sys
import xml.etree.ElementTree as etree
import argparse
import urllib
try:
    import docGenerator as gen
except:
    sys.exit("[!] Please download the docGenerator.py script from https://code.google.com/p/xml-parsers/")
from StringIO import StringIO    


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
        os_vendor = ""
        os_product = ""
        os_version = ""
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
                            os_version = oss.get('version')
                            if (isinstance(os_version, basestring)):
                                os_version_string=True
                            if os_version_string:
                                os_version = str(os_version)
                                os_product = oss.get('product')
                            else:
                                os_version = float(os_version)
                                os_product = oss.get('family')
                            os_vendor = oss.get('vendor')
                            if os_vendor is None:
                                os_vendor == "Unknown Vendor"
                            if os_product is None:
                                os_product == "Unknown Product"                           
                for tests in node.iter('tests'):
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
                            temp = test.get('id')
                            temp=temp.lower()
                            status_id="%s:%s" % (temp, vuln_status)
                            vuln_dict[temp]=[vuln_status]
                            host_vuln_ids.append(temp)
                            vuln_ids.append(temp)
                            status_id_list.append(status_id)
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
                    s = vuln.find('description').find('ContainerBlockElement').find('Paragraph').text
                    s = s.replace("\n","")
                    s = s.replace("\r","")
                    s = s.replace("\t","")
                    s = s.replace("    "," ")
                    s = s.replace("  "," ")
                    s = s.replace(". ",".  ")
                    s = s.replace(".   ",".  ")
                    s = s.replace("from:","from the link below.")
                    vuln_description=s

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
                            s = paragraph.text
                            s = s.replace("\n","")
                            s = s.replace("\r","")
                            s = s.replace("\t","")
                            s = s.replace("    "," ")
                            s = s.replace("  "," ")
                            s = s.replace(". ",".  ")
                            s = s.replace(".   ",".  ")
                            s = s.replace("from:","from the link below.")
                            solutions.append(s)
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


if __name__ == '__main__': 
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-x reports.xml] [-f filename (extensions added automatically)] --xlsx --docx --all -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-x", "--xml", type=str, help="Generate a dictionary of data based on a SCAP XML import, more than one file may be passed, separated by a comma", action="store", dest="xml")
    parser.add_argument("-f", "--filename", type=str, help="Filename for output of exports", action="store", dest="filename")
    parser.add_argument("--xlsx", action="store_true", dest="xlsx_var", help="Output data into an xlsx file")
    parser.add_argument("--docx", action="store_true", dest="docx_var", help="Output data into an docx file")
    parser.add_argument("--all", action="store_true", default=True, dest="all_var", help="Output data into both a docx and xlsx file, which is the default")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.48b')
    args = parser.parse_args()

    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    # Set Constructors
    xml = args.xml                   # nmap XML
    verbose = args.verbose           # Verbosity level
    filename = args.filename         # Filename for Exports
    all_var = args.all_var           # The boolean holder for all output files
    xlsx_var = args.xlsx_var         # The boolean holder for the xlsx output file
    docx_var = args.docx_var         # The boolean holder for the docx output file

    # Normalizers and basic constructors
    if xlsx_var or docx_var:
        all_var = False
    if xlsx_var and docx_var:
        all_var = True
    xml_list=[]                      # List to hold XMLs
    docVar=""

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

    # Remove duplicates and create final dictionaries
    processed_service_list=uniqList(verbose, service_list)
    processed_hosts=uniqDict(verbose, hosts_dict)
    processed_vulnerabilities=uniqDict(verbose, vulnerabilities_dict)
    processed_host_vulns=uniqDict(verbose, host_vulns_dict)
    processed_host_details=uniqDict(verbose, host_details_dict)
    processed_vuln_hosts=uniqDictKey(verbose, vuln_hosts_dict)
    processed_service_dict=serviceDict(verbose, service_list, processed_host_details)
    processed_vuln_dict=uniqDictKey(verbose, vuln_dict)

    if all_var:
        docVar = "all"
    elif xlsx_var:
        docVar = "xlsx"
    elif docx_var:
        docVar = "docx"
    else:
        sys.exit("[!] An error occured when attempting to process the output file")

    gen.docGenerator(verbose, xml, filename, processed_vulnerabilities, processed_vuln_hosts, processed_host_vulns, processed_hosts, processed_host_details, processed_service_dict, processed_vuln_dict, docVar)

