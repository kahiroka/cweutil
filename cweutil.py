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

def parents(cwe, space=''):
	if cwe in cwedic:
		printcwe(cwe, space)
		for parent in cwedic[cwe]['childof']:
			parents(parent, space + ' ')

def children(cwe, space=''):
	if cwe in cwedic:
		printcwe(cwe, space)
		for child in cwedic[cwe]['parentof']:
			printcwe(child, space + ' ')

def getArgs():
	usage = 'python3 {} options'.format(__file__)
	argparser = ArgumentParser(usage=usage)
	argparser.add_argument('-p', '--parents', nargs='?', type=str, dest='parents', help='show parents hierarchey of the CWE ID')
	argparser.add_argument('-c', '--children', nargs='?', type=str, dest='children', help='show children of the CWE ID')
	argparser.add_argument('-k', '--keyword', nargs='?', type=str, dest='keyword', help='search by the keyword')
	argparser.add_argument('-a', '--capec', action='store_true', dest='capec', help='use capec mode')
	return argparser.parse_args()

def main():
	args = getArgs()

	cwe_path = os.path.dirname(os.path.abspath(__file__)) + '/cwec.xml'
	if args.capec:
		cwe_path = os.path.dirname(os.path.abspath(__file__)) + '/capec.xml'
	if not os.path.isfile(cwe_path):
		print('CWE: Download https://cwe.mitre.org/data/xml/cwec_latest.xml.zip, then extract it as cwec.xml.')
		print('CAPEC: Download https://capec.mitre.org/data/xml/capec_latest.xml, then place it as capec.xml.')
		sys.exit()
	tree = ET.parse(cwe_path)
	root = tree.getroot()
	ns = {'xmlns':'http://cwe.mitre.org/cwe-6'}
	if args.capec:
		ns = {'xmlns':'http://capec.mitre.org/capec-3'}
		global nvdview
		nvdview = []

	for weakness in root[0]:
		id = weakness.attrib['ID']
		name = weakness.attrib['Name']
		pcwelist = []
		node = 'xmlns:Related_Weaknesses/'
		leaf = 'xmlns:Related_Weakness'
		id_type = 'CWE_ID'
		if args.capec:
			node = 'xmlns:Related_Attack_Patterns/'
			leaf = 'xmlns:Related_Attack_Pattern'
			id_type = 'CAPEC_ID'

		for pcwe in weakness.findall('./' + node + leaf + "[@Nature='ChildOf']", ns):
			if pcwe.attrib[id_type] not in pcwelist:
				pcwelist.append(pcwe.attrib[id_type])

		if id not in cwedic:
			cwedic[id] = {'name':name, 'childof':pcwelist, 'parentof':[] }
		else:
			cwedic[id]['name'] = name
			cwedic[id]['childof'] = pcwelist

		for chid in pcwelist:
			if chid not in cwedic:
				cwedic[chid] = {'name':'', 'childof':[], 'parentof':[id]}
			else:
				cwedic[chid]['parentof'].append(id)

	if args.parents != None:
		parents(args.parents)
	elif args.children != None:
		children(args.children)
	elif args.keyword != None:
		grepi(args.keyword)

if __name__ == "__main__":
	main()
