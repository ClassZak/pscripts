#!/bin/python3
import sys
import bcrypt

def hash_data(data):
	"""Has the data by bcrypt"""
	# Generate salt and same password
	salt = bcrypt.gensalt(rounds=12)
	hashed = bcrypt.hashpw(data.encode('utf-8'), salt)
	return hashed.decode('utf-8')

def main():
	data = ''
	if len(sys.argv) > 1:
		data = sys.argv[1]
	else:
		data = input('Enter data for encrypt ->')
	
	print(hash_data(data))

if __name__ == '__main__':
	main()
