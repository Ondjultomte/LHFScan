# Script : LHF Scan - Lowest Hanging Fruit Scan
# Author : Dave Addison
#
# A script to identify the lowest hanging fruit on a network 
# without having to sift through NMAP outputs.
# This script collates all known 
#      + web services,
#      + SMB shares, 
#      + FTP, 
#      + SSH, 
#      + Telnet, 
#      + SMTP 
#      + and dangerous hosts including XP and 2003
# Includes rudimentary fixing of TCPwrapper issues.
#
# Future versions to include scans for various known issues such as GPO passwords and PII on shared areas.

import socket,os,sys,nmap,getopt

def main(argv):
	iprange=""
	try:
		opts, args = getopt.getopt(argv,"h:i:",["help","iprange="])
	except getopt.GetoptError:
		print('.... you want to read the help menu i think')
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h' or opt == '--help':
			print('ANMAP')
			print('Author : Dave Addison')
			print('URL : https://simpleinfosec.com')
			print('Usage: anmap.py -i <iprange>')
			sys.exit()
		elif opt in ("-i", "--iprange"):
			iprange=arg
		elif opt in ("-o", "--output"):
			filepath = arg
	if iprange == '':
		print('You need to provide an IP or an IP range in the format of 10.10.10.10/24 or 10.10.10.1-100')
		print('i.e. ANMAP.py -i 192.168.1.0/24')
		sys.exit(2)
		
	nm = nmap.PortScanner()
	nm2 = nmap.PortScanner()
	danger=[]
	services=[]
	domains=[]

	print("[+] Starting discovery scan")
		
	nm.scan(hosts=iprange, arguments='-sP')

	print("[+] Discovery finished")
	print("[+] "+str(len(nm.all_hosts()))+" hosts discovered")
	i=1

	for hosts in nm.all_hosts():
		print("[+] Scanning services on "+str(i)+"/"+str(len(nm.all_hosts()))+" - "+str(hosts)+" ("+str(nm[hosts].hostname())+")")
		i+=1
		nm2.scan(hosts=hosts, arguments="-sV -O")
		for host in nm2.all_hosts():	
			try:
				if nm2[host]['osmatch'][0]['name'][:29]=='Microsoft Windows Server 2003':danger.append("win2k3-Maybe:"+str(host))
				if 'XP' in nm2[host]['osmatch'][0]['name']:danger.append("XP-Maybe:"+str(host))
			except IndexError:
				continue
			for proto in nm2[host].all_protocols():
				lport = nm2[host][proto].keys()
				sorted(lport)
				for port in lport:
					if str(port)=='389' and nm2[host][proto][port]['product']=='Microsoft Windows Active Directory LDAP':
						services.append("_DC:"+host)
						domains.append(nm2[host][proto][port]['extrainfo'])
					services.append(nm2[host][proto][port]['name']+":"+str(host)+":"+str(port))

	print("[+] Scan finished")
	print("[+] Now checking for TCPWrapped data")

	for item in sorted(services):
		if 'tcpwrapped' in item:
			splitup=item.split(":")
			print("[+] "+str(splitup[1])+":"+str(splitup[2])+" showing as TCPWrapped. Enumerating a different way...")
			nm3=nmap.PortScanner()
			nm3.scan(hosts=str(splitup[1]),arguments='-sV -sT -p '+str(splitup[2]))
			for host in nm3.all_hosts():
				for proto in nm3[host].all_protocols():
					lport=nm3[host][proto].keys()
					sorted(lport)
					for port in lport:
						print("[+] Came back as "+nm3[host][proto][port]['name'])
						services.remove(item)
						services.append(nm3[host][proto][port]['name']+":"+str(host)+":"+str(port))
						
	
	print("[+] Scan finished\n\n")
	
	print("#########################")
	print("# W E B   S E R V E R S #")
	print("#########################")
	
	for item in sorted(services):
		if 'http' in item:
			splitup=item.split(":")
			print(splitup[1]+":"+splitup[2])
			
	print("\n################")
	print("# T E L N E T  #")
	print("################")
	
	for item in sorted(services):
		if 'telnet' in item:
			splitup=item.split(":")
			print(str(splitup[1])+":"+str(splitup[2])+"\nBanner : "+str(grab_banner(str(splitup[1]),str(splitup[2]))))
			
		
	print("\n##########")
	print("# S S H  #")
	print("##########")
	
	for item in sorted(services):
		if 'ssh' in item:
			splitup=item.split(":")
			print(splitup[1]+":"+splitup[2])
	
	print("\n############")
	print("# S M T P  #")
	print("############")
	
	for item in sorted(services):
		if 'smtp' in item:
			splitup=item.split(":")
			print(splitup[1]+":"+splitup[2])
			
	print("\n##########")
	print("# F T P  #")
	print("##########")
	
	for item in sorted(services):
		if 'ftp' in item:
			splitup=item.split(":")
			print(splitup[1]+":"+splitup[2])


	print("\n##########")
	print("# S M B  #")
	print("##########")
	
	for item in sorted(services):
		splitup=item.split(":")
		if ('137' in splitup[2]) or ('139' in splitup[2]):
			print(splitup[1])
			
			
	print("\n#################################")
	print("# D A N G E R O U S   H O S T S #")
	print("#################################")
	
	for item in sorted(danger):
		print(item)
		
		
def grab_banner(ip,port):  
	try:  
		s=socket.socket()  
		s.connect(str(ip),str(port))  
		banner = s.recv(1024)  
		print(str(banner))  
	except:
		print("Unable to obtain banner")
		
if __name__ == "__main__":
	main(sys.argv[1:])
	