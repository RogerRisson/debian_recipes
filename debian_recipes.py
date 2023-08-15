#!/usr/bin/env python3

# apt install virtualbox-7.0 qemu-utils genisoimage wget python3

# A dependencia do virtualbox deve ser tipo: virtualbox | virtualbox-6.1 | virtualbox-7.0
# Isso vai permitir que qualquer versão do virtualbox disponível em distros modernas atenda
# a necessidade do script!

# Architecture: all

version_number = '0.1'

import os, argparse, hashlib, re, sys, shutil, crypt, datetime, time

class vbox:
	def __init__(self, binary_path='/usr/bin/vboxmanage'):
		self.binary_path = binary_path
		self.command = []

	def __getattr__(self, name):
		self.command.append(name.replace('_', '-'))
		return self

	def __getitem__(self, name):
		self.command.append(name)
		return self

	def __call__(self, **args):
		import subprocess
		
		for k in args.keys():
			if(args[k] is True):
				self.command.append("--{}".format(k.replace('_','-')))
			else:
				self.command.append("--{}".format(k.replace('_','-')))
				if isinstance(args[k],list):
					self.command += args[k]
				else:
					self.command.append(str(args[k]))
		
		res = subprocess.run([self.binary_path] + self.command, capture_output=True)
		if res.returncode == 0:
			self.command = []
			return res.stdout.decode('utf-8').rstrip()
		else:
			e = Exception("There is a problem with the requested API! [{}]".format(' '.join([self.binary_path] + self.command)))
			self.command = []
			raise e

vbox = vbox()

def file_get_contents(file_path):
	with open(file_path) as f:
		return f.read()

def file_put_contents(file_path, data):
	with open(file_path, 'w+') as f:
		f.write(data + "\n")

def exec(command, capture=True):
	import subprocess
	result = subprocess.run(command, shell=True, capture_output=capture)
	if capture == True:
		result.stdout = result.stdout.decode('utf-8').rstrip()
	return result

def user_data(hostname, password, script=None):
	import yaml
	base = {
		'hostname': 'debian', 
		'ssh_pwauth': True, 
		'disable_root': False,
		'chpasswd': {
			'expire': False,
			'users': [{
				'name': 'root',
				'password': 'teste'
			}]
		},
		'updates': {
			'network': {
				'when': ['boot', 'boot-legacy']
			}
		}
	}
	base['hostname'] = hostname
	base['chpasswd']['users'][0]['password']=crypt.crypt(password)
	if script != None:
		ret  = 'Content-Type: multipart/mixed; boundary="//"\nMIME-Version: 1.0\n\n--//\n'
		ret += 'Content-Type: text/cloud-config; charset="us-ascii"\nMIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\nContent-Disposition: attachment; filename="cloud-config.txt"\n\n'
		ret += "#cloud-config\n" + yaml.dump(base)
		ret += '\n--//\nContent-Type: text/x-shellscript; charset="us-ascii"\nMIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\nContent-Disposition: attachment; filename="userdata.txt"\n\n'
		ret += file_get_contents(script)
		ret += '\n\n--//--'
		return ret
	else:
		return "#cloud-config\n" + yaml.dump(base)

def is_valid_ip(ip):
	import ipaddress
	if '/' in ip:
		return False
	try:
		addr = ipaddress.ip_address(ip)
		if str(addr).split('.')[3] == '0':
			return False
	except ValueError:
		return False
	return True

def is_valid_cidr(cidr):
	import ipaddress
	if '/' in cidr:
		try:
			ip = ipaddress.ip_interface(cidr)
			if str(ip.ip) == str(ip.network).split('/')[0]:
				raise ValueError
		except ValueError:
			return False
	else:
		return False

	return True

def network_config(mac, ip=None, gateway=None, dns=None):
	import yaml
	mac = mac.lower()
	if ip == None:
		return ''
	else:
		base = {
			'network': {
				'version': 2,
				'ethernets': {
					'id0': {
						'match': {'macaddress': mac},
						'addresses': [ip],
					}
				}
			}
		}
		if gateway != None:
			base['network']['ethernets']['id0']['gateway4'] = gateway
		if dns != None:
			base['network']['ethernets']['id0']['nameservers'] = {'addresses': [dns]}
		
		return yaml.dump(base)

debian_urls = {
	'bookworm': 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2',
	'bullseye': 'https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2',
	'buster': 'https://cloud.debian.org/images/cloud/buster/latest/debian-10-genericcloud-amd64.qcow2',
	'stretch': 'https://cloud.debian.org/images/cloud/stretch/daily/20200210-166/debian-9-nocloud-amd64-daily-20200210-166.qcow2'
}

debian_architectures = ['amd64', 'arm64']

debian_codenames = [name for name in debian_urls.keys()]

system_architecture = exec("dpkg --print-architecture").stdout
main_network_device = exec("ip -o -4 route show to default | awk '{print $5}'").stdout
main_network_ip     = exec("ip address show wlp0s20f3 | grep 'inet ' | xargs | awk '{print $2}' | cut -d '/' -f 1").stdout

if not system_architecture in debian_architectures:
	sys.exit("Your system architecture is not suported, chose 'amd64' or 'arm64' using --architecture option!")

parser = argparse.ArgumentParser(
	description='A tool to implement server recypes for the Debian Operating System.',
	add_help=False,
	usage="%(prog)s <recype> [options]",
	epilog="This is free software; see the source for copying conditions.  There is NO WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
	)

parser.add_argument('recype', nargs=1, help='A bash script used for the recype')
parser.add_argument('--debian-version', metavar='', default='bookworm', help='The debian version to use. (Default value: \'bookworm\')', choices=debian_codenames)
parser.add_argument('--architecture', metavar='', default=system_architecture, help='The chosen architecture. (Default value: \'{}\')'.format(system_architecture), choices=debian_architectures)
parser.add_argument('--memory', metavar='', type=int, default=1024, help='The amount of RAM in MegaBytes for the virtual machine. (Default value: \'1024\')')
parser.add_argument('--vcpu', metavar='', type=int, default=1, help='The amount of CPU cores for the virtual machine. (Default value: \'1\')')
parser.add_argument('--network-device', metavar='', default=main_network_device, help='The network device to attach the virtual machine. (Default value: \'{}\')'.format(main_network_device))
parser.add_argument('--interface', metavar='', default='gui', help='Select the type of the interface GUI or SERIAL. (Default value: \'gui\')', choices=['gui', 'serial'])
parser.add_argument('--keep', default=False, help='Keep the Virtual Machine after the process is finished. (Default value: \'false\')', action='store_true')
parser.add_argument('--list-versions', help='Shows the available Debian versions and exit.', action='store_true')
parser.add_argument('--vm-hostname', metavar='', help='Config the VM hostname. (Default value: \'debian\')', default='debian')
parser.add_argument('--vm-password', metavar='', help='Config the VM root password. (Default value: \'toor\')', default='toor')
parser.add_argument('--vm-ip', metavar='', help='Config the VM IP address in the format \'1.2.3.4/24\'. (Default value: \'dhcp\')', default=None)
parser.add_argument('--vm-gateway', metavar='', help='Config the VM Gateway address. (Default value: \'dhcp\')', default=None)
parser.add_argument('--vm-dns', metavar='', help='Config the VM DNS address, only one address is allowed. (Default value: \'dhcp\')', default=None)
parser.add_argument('--version', help='Shows the version number and exit', action='version', default=argparse.SUPPRESS, version=f"%(prog)s {version_number}")
parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.')

args = parser.parse_args()

if args.vm_ip is not None and not is_valid_cidr(args.vm_ip):
	sys.exit("ERROR: The value of --vm-ip argument needs to be a valid IP/MASK in CIDR format (eg: 192.168.0.10/24)")

if args.vm_gateway is not None and not is_valid_ip(args.vm_gateway):
	sys.exit("ERROR: The value of --vm-gateway argument needs to be a valid IP address (eg: 192.168.0.1)")

if args.vm_dns is not None and not is_valid_ip(args.vm_dns):
	sys.exit("ERROR: The value of --vm-dns argument needs to be a valid IP address (eg: 8.8.8.8)")

if not os.path.exists(args.recype[0]):
	sys.exit("ERROR: The recype needs to be an existing file, and a valid shell script")

if args.list_versions:
	for name in debian_codenames:
		print(name)
	quit()

url = debian_urls[args.debian_version]
image_file = url.split(sep='/')[-1]

print("Implementing Recype.: {}".format(args.recype[0]))
print("Debian Version......: {}".format(args.debian_version))
print("Debian Architecture.: {}".format(args.architecture))
print("RAM Memory..........: {}".format(args.memory))
print("VCPU................: {}".format(args.vcpu))
print("Main network device.: {}".format(args.network_device))
print("VM IP address.......: {}".format('DHCP' if args.vm_ip is None else args.vm_ip))
print("VM Gateway address..: {}".format('DHCP' if args.vm_gateway is None else args.vm_gateway))
print("VM DNS address......: {}".format('DHCP' if args.vm_dns is None else args.vm_dns))
print("VM Hostname.........: {}".format(args.vm_hostname))
print("VM root password....: {}".format(args.vm_password))
print()

print("Downloading base image file... ")
if not os.path.exists(image_file):
	if exec("wget -q --show-progress {}".format(url), capture=False).returncode != 0:
		print("DOWNLOAD FAIL!")
		quit()
	else:
		print("DOWNLOAD SUCCESS!")
else:
	print("USING PRE-EXISTING IMAGE FILE!\n")

print("Creating virtual machine... ", end='')
try:
	vm_name = hashlib.md5(str(datetime.datetime.now().microsecond).encode('utf-8')).hexdigest()[0:10]
	vm_uuid = vbox.createvm(name=vm_name, basefolder=os.getcwd(), ostype="Debian_64", register=True).split("\n")[1].split(': ')[1]

	if exec(f"qemu-img convert -f qcow2 {image_file} -O vdi '{vm_name}/disk.vdi'").returncode != 0:
		raise Exception("Impossible to generate the VM disk!")

	vbox.modifyvm[vm_uuid](boot1='disk', memory=args.memory, cpus=args.vcpu, nic1='bridged', nic_type1='virtio', bridge_adapter1=args.network_device)
	vbox.modifyvm[vm_uuid](uart1=['0x3F8', '4'], uart_mode1=['tcpserver', '12345'])
	vbox.storagectl[vm_uuid](add='scsi', name='SCSI', controller='buslogic')
	vbox.storageattach[vm_uuid](storagectl='SCSI', type='hdd', port=1, medium=f"{vm_name}/disk.vdi")
	
	tmp = re.search("NIC 1:[ ]*MAC: (?P<mac>[A-Z0-9]*)", vbox.showvminfo[vm_uuid]())
	if tmp is not None:
		vm_mac = ':'.join([tmp.group(1)[i:i+2] for i in range(0, len(tmp.group(1)), 2)])
	else:
		raise Exception("Unable to get the MAC Address of the VM!")

	file_put_contents(f"{vm_name}/meta-data", '')
	file_put_contents(f"{vm_name}/user-data", user_data(args.vm_hostname, args.vm_password, args.recype[0]))
	file_put_contents(f"{vm_name}/network-config", network_config(vm_mac, args.vm_ip, args.vm_gateway, args.vm_dns))

	if exec(f"genisoimage -output {vm_name}/configs.iso -volid cidata -joliet -rock {vm_name}/user-data {vm_name}/meta-data {vm_name}/network-config &> /dev/null").returncode != 0:
		raise Exception("Impossible to generate the config disk using genisoimage!")

	os.remove(f"{vm_name}/meta-data")
	os.remove(f"{vm_name}/user-data")
	os.remove(f"{vm_name}/network-config")

	vbox.storageattach[vm_uuid](storagectl='SCSI', type='dvddrive', port=0, medium=f"{vm_name}/configs.iso")

except Exception as e:
	shutil.rmtree(vm_name, ignore_errors=True)
	vbox.unregistervm[vm_name](delete_all=True)
	sys.exit(f"FAIL!\n{e}")

print("OK!")

print("Starting Virtual Machine... ", end='')
try:
	if args.interface == 'gui':
		vbox.startvm[vm_uuid]()

	elif args.interface == 'serial':
		vbox.startvm[vm_uuid](type='headless')
		exec("telnet localhost 12345", capture=False)
		try:
			vbox.controlvm[vm_uuid].poweroff()
		except:
			pass

except Exception as e:
	sys.exit(f"FAIL!\n{e}")
print("OK!")

print("Waiting the Virtual Machine to close... ", end='', flush=True)
pid = exec(f"cat {vm_name}/Logs/VBox.log  | grep 'Process ID:' | tail | awk '{{print $4}}'").stdout
while exec(f"ps -p {pid} | grep -c {pid}").stdout != '0':
	time.sleep(1)
print("OK!") 

if args.keep == False:
	print("Destroying the Virtual Machine...", end='')
	try:
		vbox.unregistervm[vm_uuid](delete_all=True)
		shutil.rmtree(vm_name, ignore_errors=True)
	except Exception as e:
		sys.exit(f"FAIL!\n{e}")
	print("OK!")
