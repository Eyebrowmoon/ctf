import socket
import struct
import time

def to_int(t):
	return struct.unpack("<l", t)[0]

url = 'liberty_thisbusinessisbinaryyoureaoneorazeroaliveordead.quals.shallweplayaga.me'
port = 11445
my_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_sock.bind(('localhost', 11445))
my_sock.listen(1)

binary_cnt = 0

while True:
	connection, client_address = my_sock.accept()
	try:
		sock = socket.create_connection((url, port))
		while binary_cnt < 14:
			data_len = sock.recv(4)
			data = ""
			while len(data) < to_int(data_len):
				temp = sock.recv(to_int(data_len) - len(data))
				data += temp
	
			print("Recv Length: " + str(to_int(data_len)))
			#print(data)
			connection.send(data_len)
			connection.send(data)

			with open('liberty_binary/binary_' + str(binary_cnt), 'wb') as f:
				f.write(data)
				binary_cnt += 1

			time.sleep(0.1)
	
			recv_data_len = connection.recv(4)
			recv_data = ""
			while len(recv_data) < to_int(recv_data_len):
				temp = connection.recv(to_int(recv_data_len) - len(recv_data))
				recv_data += temp
	
			print("Send Length: " + str(to_int(recv_data_len)))
			print(recv_data.encode('hex'))
			sock.send(recv_data_len)
			sock.send(recv_data)
	finally:
                time.sleep(1000)
		sock.close()
		connection.close()
