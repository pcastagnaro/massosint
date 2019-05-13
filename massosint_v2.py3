#!/usr/bin/python3

import subprocess



#python ~/tools/Sublist3r/sublist3r.py -b -d <DOMAIN> -o <DOMAIN>.sublister

def execCommand(command):
	print('Executing command: ' + ' '.join(command))

	proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	o, e = proc.communicate()
	return o.decode('ascii') # Output

if __name__ == "__main__":
	domains = ['consumeraffairs.com', 'my.consumeraffairs.com', 'matchingtool.consumeraffairs.com', 'retirementliving.com', 'mythreecents.com', 'reviews.10news.com', 'reviews.3newsnow.com', 'reviews.abc15.com', 'reviews.abcactionnews.com', 'reviews.fox47news.com', 'reviews.fox4now.com', 'reviews.kgun9.com', 'reviews.kivitv.com', 'reviews.kshb.com', 'reviews.ktnv.com', 'reviews.kxxv.com', 'reviews.nbc26.com', 'reviews.news5cleveland.com', 'reviews.news9.com', 'reviews.newschannel5.com', 'reviews.newson6.com', 'reviews.thedenverchannel.com', 'reviews.theindychannel.com', 'reviews.tmj4.com', 'reviews.turnto23.com', 'reviews.wcpo.com', 'reviews.wkbw.com', 'reviews.wmar2news.com', 'reviews.wptv.com', 'reviews.wtxl.com', 'reviews.wxyz.com', 'registry.consumeraffairs.com', 'sentry.consumeraffairs.com', 'qa-leads.consumeraffairs.com', 'leads.consumeraffairs.com', 'staging-leads.consumeraffairs.com', 'my.consumeraffairs.com', 'qa.consumeraffairs.com', 'staging.consumeraffairs.com', 'git-conaff.consumeraffairs.com', 'media.consumeraffairs.com', 'matillion.consumeraffairs.com', 'matchingtool.consumeraffairs.com', 'staging-matchingtool.consumeraffairs.com', 'qa-matchingtool.consumeraffairs.com', 'matchingtool-cdn.consumeraffairs.com', 'staging-my.consumeraffairs.com']
	outPath = "/home/pcastagnaro/bounty/Cobalt/pt1480_consumeraffair/"
	toolsBasePath = "/home/pcastagnaro/tools/"
	shodanAPI = 'Z1q2RpmJnzdtrarh6PzaMMpC1A3rwtgE'
	censysAPI = 'fce44397-591d-4606-af29-dd88b81c6a92:HjblOaMynlbQQkeBVckyBox0Y2PiKTII' #API ID:Secret

	tools = {'sublister': 'Sublist3r/sublist3r.py', 'altdns': 'altdns/altdns.py'}

	for domain in domains:
		
		#Sublist3r
		tempOutPath = outPath + domain + '.sublister'
		toolPath = toolsBasePath + 'Sublist3r/'
		command = ['python', toolPath + 'sublist3r.py', '-d', domain , '-o', tempOutPath]
		result = execCommand(command)
		print(result)

		#blacksheepwall
		tempOutPath = outPath + domain + '.blacksheepwall'
		command = ['./blacksheepwall_linux_amd64', '-censys', censysAPI, '-reverse', '-exfiltrated', '-clean', '-fcrdns', '-shodan', shodanAPI, '-crtsh', '-vt', '-srv', '-axfr', '-headers', '-tls', '-domain', domain]
		result = execCommand(command)
		print(result)

		#subfinder
		tempOutPath = outPath + domain + '.subfinder'
		command = ['subfinder', '-d', domain, '-o', tempOutPath, '-recursive']
		result = execCommand(command)
		print(result)

		#altdns
		# tempOutPath = outPath + domain + '.altdns'
		# toolPath = toolsBasePath + 'altdns/'
		# command = ['python', toolPath + 'altdns.py', '-i', toolPath + 'words.txt', '-o', domain + '.data.altdns', '-w', toolPath + 'words.txt', '-r', '-s', domain + '.results.altdns']
		# result = execCommand(command)
		# print(result)

	exit()






#print('Error: '  + e.decode('ascii'))
#print('code: ' + str(proc.returncode))

#result = subprocess.run(['python', command], stdout=subprocess.PIPE)
#result = subprocess.run(['python ' + toolsBasePath + 'Sublist3r/sublist3r.py', '-b', '-d', domain], stdout=subprocess.PIPE)
#result.stdout.decode('utf-8')