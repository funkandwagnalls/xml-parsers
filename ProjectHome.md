This project contains Python scripts that can be used to parse and process XMLs output from a variety of scan engines and tools.  Examples include NMAP, and Nexpose or Nessus with a SCAP XML output.  These scripts can be instantiated, imported, or run directly from the CLI.

The tool can output data into either a concise xlsx or docx from combined SCAP XML files after extracting unique content.  The xlsx currently has the worksheets listed below, which are created based on the content extracted from the XML files.

**Vulnerabilities = The vulnerabilities extracted from all scans and the affected hosts.**

**Hosts = A detailed list of each host.**

**Services = Creates an output of services per host, with matching protocol and port**

**MitM Targets = Shows hosts that may be susceptible to MitM attacks, based on scan engine location.**

**Exploitable Targets = Provides potentially exploitable targets based on information from scans.**

**Vulnerable Software Versions = Shows vulnerabilities based outdated services and software**

**IP to Vulnerability Matrix = Single lines with a one to one match of IP address to each vulnerability.**

**Not Vulnerable or False Positives = Items the scan engine tried to identify as a vulnerability, but found it was not actually present.**

**IP to Services Itemization = Itemization of IP to service per row, which allows for simple sorting.**

The docx generates one finding per page in a report format.

Disclaimer: These tools are not designed for malicious purposes, please use them responsibly.