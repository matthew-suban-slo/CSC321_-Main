import bcrypt
from sys import *
import datetime

class User:
	def __init__(self, name, saltedhash):
		self.name = name
		self.saltedhash = saltedhash
		self.password = ""
		self.guessCount = 0
		self.duration = datetime.datetime.now()

	def __eq__(self, other):
		return (self.name == other.name and
				self.saltedhash == other.saltedhash)

	def __repr__(self):
		return 'User: %s\nSaltedHash: %s\nPassword: %s\ngCount: %d\nDuration: %.10s\n' % (
			self.name, self.saltedhash, self.password, self.guessCount, self.duration)


def parseShadow(filename):
	lines = filename.readlines()
	user_list = []
	for line in lines:
		temp = line.split(":")
		temp_user = User(temp[0], temp[1].strip())
		user_list.append(temp_user)
	return user_list

def parseWordFile(filename):
	lines = filename.readlines()
	words = []
	for line in lines:
		words.append(line.strip().encode())
	return words

def checkPass(user_list, word_list):
	for user in user_list:
		start = datetime.datetime.now()
		for word in word_list:
			saltedhash = user.saltedhash.encode()
			user.guessCount+=1
			if bcrypt.checkpw(word, saltedhash):
				user.password = word
				user.duration = datetime.datetime.now() - start
				break

def writeOutPut(user_list):
	try:
		out = open('crackedUser.txt','w+')
	except IOError:
		print('Could not open file')
		return
	for user in user_list:
		out.write("User: %s\nWorkfactor: %s\nBroken Password: %s\nGuesses: %d\nDuration: %.10s\n" % 
			(user.name, user.saltedhash[4:6], user.password.decode('utf-8'), user.guessCount, user.duration))
	out.close()

def main(argv):
	if len(argv) < 2:
		print("[Usage]: python3 break_pass.py [SHADOW_FILE] [NLTK_WORD_FILE]")
		return 1
	else:
		shadowFile = open(argv[1], "r")
		wordFile = open(argv[2], "r")
		user_list = parseShadow(shadowFile)
		word_list = parseWordFile(wordFile)
		checkPass(user_list, word_list)
		#print(user_list[0])
		writeOutPut(user_list)
		wordFile.close()
		shadowFile.close()
		return 0


if __name__ == "__main__":
	exit(main(argv))
