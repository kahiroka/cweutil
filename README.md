# CWE/CAPEC Utility

This is a simple utility to search CWE/CAPEC items by ID or keyword.

# Preparation

CWE: Download https://cwe.mitre.org/data/xml/cwec_latest.xml.zip, then extract it as cwec.xml in the same directory.
CAPEC: Download https://capec.mitre.org/data/xml/capec_latest.xml, then place it as capec.xml in the same directory.

# Usage

Show parents hierarchy of CWE ID:

    $ python3 ./cweutil.py -p 312
    312, Cleartext Storage of Sensitive Information
     311, Missing Encryption of Sensitive Data
      693, Protection Mechanism Failure
     922, Insecure Storage of Sensitive Information
      664, Improper Control of a Resource Through its Lifetime

Show children of CWE ID:

    $ python3 ./cweutil.py -c 312
    312, Cleartext Storage of Sensitive Information
     313, Cleartext Storage in a File or on Disk
     314, Cleartext Storage in the Registry
     315, Cleartext Storage of Sensitive Information in a Cookie
     316, Cleartext Storage of Sensitive Information in Memory
     317, Cleartext Storage of Sensitive Information in GUI
     318, Cleartext Storage of Sensitive Information in Executable

Search CWE by keyword:

    $ python3 ./cweutil.py -k cleartext
    312, Cleartext Storage of Sensitive Information
    313, Cleartext Storage in a File or on Disk
    314, Cleartext Storage in the Registry
    315, Cleartext Storage of Sensitive Information in a Cookie
    316, Cleartext Storage of Sensitive Information in Memory
    317, Cleartext Storage of Sensitive Information in GUI
    318, Cleartext Storage of Sensitive Information in Executable
    319, Cleartext Transmission of Sensitive Information

Show children of CAPEC ID:

    $ python3 ./cweutil.py -a -c 66
    66, SQL Injection
     108, Command Line Execution through SQL Injection
     109, Object Relational Mapping Injection
     110, SQL Injection through SOAP Parameter Tampering
     470, Expanding Control over the Operating System from the Database
     7, Blind SQL Injection
