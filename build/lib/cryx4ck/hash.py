#importimg base64 for more encode
import base64
import hashlib
'''
Encrypt Function
'''
#creating a class
class data:
#making __init__ function
	def __init__(self,data):
#basic encoding
		self.data = data
		self.re=self.data[::-1]
		self.b64=base64.b64encode(self.re.encode())
		self.b6=self.b64.decode()
#returning result
	def result(self):
		self.reencode=hashlib.md5(self.b6[::-1].encode()).hexdigest()
		self.b32=base64.b32encode(self.reencode.encode())
		self.b3=self.b32.decode()
		return self.b3.replace('=','')