import xml.etree.ElementTree as ET
from argparse import ArgumentParser
import re
import os
import sys

# https://cwe.mitre.org/data/definitions/635.html
nvdview = ['16', '20', '22', '59', '78', '79', '89', '94', '119', '134', '189', '200', '255', '264', '287', '310', '352', '362', '399']
cwedic = {}

def printcwe(cwe, space=''):
	if cwe in nvdview:
		print(space + cwe + ', [NVD]' + cwedic[cwe]['name'])
	else:
		print(space + cwe + ', ' + cwedic[cwe]['name'])

def grepi(str):
	p = re.compile(".*" + str + ".*", re.IGNORECASE)
	for cwe in cwedic:
		name = cwedic[cwe]['name']
		if p.match(name) != None:
			printcwe(cwe)

def search(cwe, space=''):
	if cwe in cwedic:
		printcwe(cwe, space)
		for parent in cwedic[cwe]['childof']:
			search(parent, space + ' ')

def getArgs():
	usage = 'python3 {} options'.format(__file__)
	argparser = ArgumentParser(usage=usage)
	argparser.add_argument('-c', '--cwe', nargs='?', type=str, dest='cwe', help='search by #CWE')
	argparser.add_argument('-k', '--keyword', nargs='?', type=str, dest='kw', help='search by keyword')
	return argparser.parse_args()

def main():
	args = getArgs()

	cwe_path = os.path.dirname(os.path.abspath(__file__)) + '/cwec.xml'
	if not os.path.isfile(cwe_path):
		print('Download https://cwe.mitre.org/data/xml/cwec_latest.xml.zip, then extract it as ' + cwe_path)
		sys.exit()
	tree = ET.parse(cwe_path)
	root = tree.getroot()
	ns = {'xmlns':'http://cwe.mitre.org/cwe-6'}

	for weakness in root[0]:
		id = weakness.attrib['ID']
		name = weakness.attrib['Name']
		pcwelist = []
		for pcwe in weakness.findall('./' + 'xmlns:Related_Weaknesses/' + "xmlns:Related_Weakness[@Nature='ChildOf']", ns):
			if pcwe.attrib['CWE_ID'] not in pcwelist:
				pcwelist.append(pcwe.attrib['CWE_ID'])
		cwedic[id] = {'name':name, 'childof':pcwelist }

	if args.cwe != None:
		search(args.cwe)
	elif args.kw != None:
		grepi(args.kw)

if __name__ == "__main__":
	main()
