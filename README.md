# CWE Utility

This is a simple utility to search CWE items by number or keyword.

# Preparation

Download https://cwe.mitre.org/data/xml/cwec_latest.xml.zip, then extract it as cwec.xml in the same directory. 

# Usage

By number:

    $ python3 ./cweutil.py -c 312
    312, Cleartext Storage of Sensitive Information
     311, Missing Encryption of Sensitive Data
      693, Protection Mechanism Failure
     922, Insecure Storage of Sensitive Information
      664, Improper Control of a Resource Through its Lifetime

By keyword:

    $ python3 ./cweutil.py -k cleartext
    312, Cleartext Storage of Sensitive Information
    313, Cleartext Storage in a File or on Disk
    314, Cleartext Storage in the Registry
    315, Cleartext Storage of Sensitive Information in a Cookie
    316, Cleartext Storage of Sensitive Information in Memory
    317, Cleartext Storage of Sensitive Information in GUI
    318, Cleartext Storage of Sensitive Information in Executable
    319, Cleartext Transmission of Sensitive Information