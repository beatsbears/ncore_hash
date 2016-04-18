import hashlib
import os, sys, time
import multiprocessing
import itertools
import argparse

CORE_COUNT = multiprocessing.cpu_count()
MIN_LENGTH = 0
MAX_LENGTH = 1
LOWERCASE = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

UPPERCASE = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

NUMBERS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

SYMBOLS = [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', 
			',', '-', '.', '/','[', '\\', ']', '^', '_', '`',':', ';', '<', 
			'=', '>', '?', '@']

HASHTYPES = ['MD5']

def Arguments():
	parser = argparse.ArgumentParser(description='Rainbow table creation utility')

	parser.add_argument('-d', "--directory",  help="Storage Directory", type= ValidateDirectory, required=True)
	parser.add_argument('-l', "--length",  help="Length range e.g. 2-8", type= RangeGeneration, required=True)
	parser.add_argument('--hash', help="Hash function to use {}".format(str(HASHTYPES)), required=False)

	parser.add_argument("--lowercase", help="Use lowercase character set", action="store_true", default=False)
	parser.add_argument("--uppercase", help="Use uppercase character set", action="store_true", default=False)
	parser.add_argument("--num", help="Use numeric character set", action="store_true", default=False)
	parser.add_argument("--symbols", help="Use symbols", action="store_true", default=False)
	parser.add_argument("--full_ascii", help="Use full ascii character set", action="store_true", default=False)

	parser.add_argument("-s", "--salt", help="[Optional] Salt Value", type=str)


	gl_args = parser.parse_args()

	return gl_args

##------------------------------------------------------------------------------------------
def ValidateDirectory(dir):
	if not os.path.isdir(dir):
		raise argparse.ArgumentTypeError('[!] Directory: {} does not exist!'.format(dir))

	if os.access(dir, os.W_OK):
		return dir
	else:
		raise argparse.ArgumentTypeError('[!] Access to {} was denied!'.format(dir))	

##------------------------------------------------------------------------------------------

def RangeGeneration(ran):
	try:
		ran_vals = ran.split('-')
		if int(ran_vals[0]) > 0 and int(ran_vals[1]) > int(ran_vals[0]):
			new_tuple = tuple(range(int(ran_vals[0]),int(ran_vals[1])+1))
			if int(ran_vals[1]) > 5:
				print '[!] WARNING: This could take awhile and tie up system resources in the meantime.'
				user_ok = input("Please press [1] to continue or [0] to abort: ")
				if user_ok:
					return new_tuple
				else:
					print '[!] Exiting program...'
					exit(0)
			else:
				return new_tuple
		else:
			raise argparse.ArgumentTypeError('[!] Range was not in the correct format')	
	except:
		raise argparse.ArgumentTypeError('[!] Range was not in the correct format')

##------------------------------------------------------------------------------------------

def PasswordGen(size):
	cnt = 0

	list_to_use = []
	if ascii_bool:
		list_to_use = UPPERCASE + LOWERCASE + NUMBERS + SYMBOLS
	else:
		if lower_bool:
			list_to_use.extend(LOWERCASE)
		if upper_bool:
			list_to_use.extend(UPPERCASE)
		if num_bool:
			list_to_use.extend(NUMBERS)
		if sym_bool:
			list_to_use.extend(SYMBOLS)

	try:
		with open(output_directory + 'RB{}.csv'.format(size),'w') as f:
			time_start = time.time()
			for i in range(size, size+1):
				for s in itertools.product(list_to_use, repeat=i):
					pword=''.join(s)

					gen_hash = hashlib.md5()

					if salt_value != None:
						gen_hash.update(salt_value+pword)
					else:
						gen_hash.update(pword)

					hash_digest = gen_hash.hexdigest()

					f.write("{},{}\n".format(pword,hash_digest))
					cnt += 1

					del gen_hash
		time_diff = time.time() - time_start
		print '[+] RB{}.csv generation complete'.format(size)
		print '[+] {} hashes generated in {} seconds'.format(str(cnt), str(time_diff))
		return cnt
	except Exception, e:
		print "[!] Error generating or writing hashes"
		print str(e)
		exit(0)

##------------------------------------------------------------------------------------------
def CreatePool(ran):
	cpu_pool = multiprocessing.Pool(processes=CORE_COUNT)
	print '[+] {} CPU cores available for processing'.format(CORE_COUNT)
	print '[+] Starting hash generation...'
	results = cpu_pool.map(PasswordGen,(ran))
	return results



if __name__ == "__main__":
	args = Arguments()
	output_directory = args.directory
	ascii_bool = args.full_ascii
	lower_bool = args.lowercase
	upper_bool = args.uppercase
	num_bool = args.num
	sym_bool = args.symbols
	salt_value = args.salt
	length_range = args.length

	start_time = time.time()
	counts = CreatePool(length_range)
	stop_time = time.time() - start_time
	print '[+] Total processing time: {} seconds'.format(str(stop_time))











