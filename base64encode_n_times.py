import sys
import base64


def help():
	print('''Usage: base64encode_n_times
			
''')

def main():
	times = 1
	text = ''
	if len(sys.argv) >= 2:			# For times amount
		times = int(sys.argv[1])
	else:
		times = int(input('encoding times ->'))
	if times > 50:
		raise Exception('Are you crazy?!')
	
	if len(sys.argv) >= 3:			# For encoding text
		text = sys.argv[2]
	else:
		text = input('text for encoding ->')
	
	if len(sys.argv) > 4:
		raise Exception('Error of argument parsing')
	
	encoded_text = text.encode('utf-8')
	for i in range(1, times + 1):
		encoded_text = base64.b64encode(encoded_text)
	print(encoded_text)
	
	
if __name__ == '__main__':
	main()

