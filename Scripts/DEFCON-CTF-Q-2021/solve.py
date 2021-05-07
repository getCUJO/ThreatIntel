from pwn import *   
import hashlib
from Crypto.Cipher import AES          

banner = '\033[34m\
     _____ _    _      _  ____             _____ \n\
    / ____| |  | |    | |/ __ \\      /\\   |_   _|\n\
   | |    | |  | |    | | |  | |    /  \\    | |  \n\
   | |    | |  | |_   | | |  | |   / /\\ \\   | |  \n\
   | |____| |__| | |__| | |__| |  / ____ \\ _| |_ \n\
    \\_____|\\____/ \\____/ \\____/  /_/    \\_\\_____|\n\
                                                 \n\
\033[0m'

print(banner)

# generate key from array of integers (provided by OOO)
def key_array_to_key_string(key_list):
    key_string_binary = b''.join([bytes([x]) for x in key_list])
    return hashlib.md5(key_string_binary).digest()

# handle each round
def send_data(p, first, second):
	competitor = 0
	me = 0
	result = ''
	p.sendline(first)
	p.recvuntil(b'rotate right\n')
	p.sendline(second)
	line2 = p.recvuntil(b'!').decode('utf-8').split(',')
	if 'bets on 0' in line2[0]:
		competitor = 0
	else:
		competitor = 1
	if '0' in line2[1]:
		me = 0
	else:
		me = 1
	if 'Win' in line2[1]:
		result = 'WIN'
	else:
		result = "LOSE"
	return competitor, me, result

"""
Chose between challenges here.
If you want to solve back-to-qoo:
	- set correct remote() call
	- set PLAYS to 128
If you want to solve qoo-or-ooo
	- set correct remote() call
	- set PLAYS to 30
"""
while True:
	try:
		#p = remote('back-to-qoo.challenges.ooo', 5000)
		p = remote('qoo-or-ooo.challenges.ooo', 5000)

		#PLAYS = 128
		PLAYS = 30

		# array for data for every round played
		data = []

		# play the rounds and gather all data
		for i in range(PLAYS):
			node = {}
			round_string = p.recvuntil(b'qoin\n')
			zcomp = 0
			me = 0
			result = ''
			comp = 0

			if b'competitor bets on 1' in round_string:
				comp = 1
				zcomp, me, result = send_data(p, b'2', b'2')
			else:	
				zcomp, me, result = send_data(p, b'2', b'1')

			node['round'] = i
			node['me'] = me
			node['zcomp'] = zcomp
			node['mycomp'] = comp 
			node['result'] = result

			#calculate z like
			if result == 'WIN':
				node['z'] = (comp * zcomp) ^ me
			else:
				node['z'] = (comp * zcomp) ^ me
				#negate the original
				if node['z'] == 1:
					node['z'] = 0
				else:
					node['z'] = 1
			data.append(node)

		# if this does not throw error, we won
		p.recvuntil(b'let him know.\n')
		# no error means we won, exiting loop
		break
	except:
		# restart the game 
		print("[\033[93m!\033[0m] Did't manage to win the game, trying again..")
		p.close()
		pass

# parse Zardus leaks
for i in range(PLAYS):
	line = p.recvline()
	data[i]['adam'] = line.decode('utf-8')[-2]

# parse nonce and ciphertext from Zardus
nonce = p.recvline().decode('utf-8').split('-1:')[1].strip('\n')
ciphertext = p.recvline().decode('utf-8').split('-2:')[1].strip('\n')

p.close()

key_bits = []

# determine which bits we need for the key
for item in data:
	if int(item['adam']) == int(item['zcomp']):
		key_bits.append(int(item['z']))


# decrypt the flag
key = key_array_to_key_string(key_bits)
nonce = bytes.fromhex(nonce)
ciphertext = bytes.fromhex(ciphertext)
cipher = AES.new(key, AES.MODE_EAX,nonce=nonce)
plaintext = cipher.decrypt(ciphertext)

print('[\033[92m+\033[0m] FLAG: ' + str(plaintext.decode('utf-8').strip('\n')))