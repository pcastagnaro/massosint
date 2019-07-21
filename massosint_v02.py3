#!/usr/bin/python3

import subprocess,sys, getopt



#python ~/tools/Sublist3r/sublist3r.py -b -d <DOMAIN> -o <DOMAIN>.sublister

def execCommand(command):
	print('Executing command: ' + ' '.join(command))

	proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	o, e = proc.communicate()
	return o.decode('ascii') # Output

def usage():
	print("\nUsage:")
	print("----------------")
	#print ('   ' + sys.argv[0] + ' -d <DOMAIN> -o <OUT PATH> -t <TOOLS BASE PATH> -shodan <SHODAN API> -censys <CENSYS API>')
	print ('   ' + sys.argv[0] + ' <DOMAIN> <OUT PATH> <TOOLS BASE PATH> <SHODAN API> <CENSYS API>')
	print("\n")

def addFinalSlash(path):
	if path[(len(path) -1):len(path)] != "/":
		path = path + "/"
	return path


def main(argv):
	domains = ['domain.com']
	outPath = ""
	toolsBasePath = ""
	shodanAPI = ''
	censysAPI = '' #API ID:Secret

	if len(sys.argv) < 6:
		print("\nThere is no total of expected arguments. Please see the usage\n")
		usage()
		exit()
	else:
		try:
			domains[0]=sys.argv[1]
			outPath=sys.argv[2]
			toolsBasePath=sys.argv[3]
			shodanAPI=sys.argv[4]
			censysAPI=sys.argv[5]
		except:
			print("\nThere is an error with arguments. Please see the usage", sys.exc_info()[0])
			usage()
			exit()
		
		outPath = addFinalSlash(outPath)
		toolsBasePath = addFinalSlash(toolsBasePath)

		#print(outPath)
		#print(toolsBasePath)


	#for eachArg in sys.argv:   
		#print(eachArg)

	#tools = {'sublister': 'Sublist3r/sublist3r.py', 'altdns': 'altdns/altdns.py', 'subfinder': ''}

	for domain in domains:
		
		# #Sublist3r OK
		tempOutPath = outPath + domain + '.sublister'
		toolPath = toolsBasePath + 'Sublist3r/'
		command = ['python', toolPath + 'sublist3r.py', '-d', domain , '-o', tempOutPath]
		result = execCommand(command)
		print(result)

		#blacksheepwall OK
		tempOutPath = outPath + domain + '.blacksheepwall'
		command = [toolsBasePath + './blacksheepwall_linux_amd64', '-censys', censysAPI, '-reverse', '-exfiltrated', '-clean', '-fcrdns', '-shodan', shodanAPI, '-crtsh', '-vt', '-srv', '-csv', '-axfr', '-headers', '-tls', '-domain', domain]
		result = execCommand(command)
		f = open(tempOutPath, '+w')
		f.write(result)
		f.close()
		print(result)

		#subfinder OK
		tempOutPath = outPath + domain + '.subfinder'
		command = ['subfinder', '-d', domain, '-b', '-w', '/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt', '-v', '-o', tempOutPath]
		result = execCommand(command)
		print(result)

		altdns
		tempOutPath = outPath + domain + '.altdns'
		toolPath = toolsBasePath + 'altdns/'
		command = ['python', toolPath + 'altdns.py', '-i', toolPath + 'words.txt', '-o', domain + '.data.altdns', '-w', toolPath + 'words.txt', '-r', '-s', domain + '.results.altdns']
		result = execCommand(command)
		print(result)

	exit()



if __name__ == "__main__":
	main(sys.argv)