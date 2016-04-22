#!/usr/bin/env python

'''
Author: Andrew Scott
Date: 4/20/2016  ;)
'''



import hashlib
import os, sys, time
import multiprocessing
from random import shuffle
import itertools
import argparse

# Constants
##------------------------------------------------------------------------------------------
CORE_COUNT = multiprocessing.cpu_count()
LOWERCASE = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

UPPERCASE = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

NUMBERS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

SYMBOLS = [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', 
			',', '-', '.', '/','[', '\\', ']', '^', '_', '`',':', ';', '<', 
			'=', '>', '?', '@']

HASHTYPES = ['MD5','SHA1','SHA224','SHA256','SHA384','SHA512']


# Parse command line arguments
##------------------------------------------------------------------------------------------
def Arguments():
	parser = argparse.ArgumentParser(description='Rainbow table creation utility')

	parser.add_argument('-d', "--directory",  help="Storage Directory", type= ValidateDirectory, required=True)
	parser.add_argument('-l', "--length",  help="Length range e.g. 2-8", type= RangeGeneration, required=True)
	parser.add_argument('--hash', help="Hash function to use {}".format(str(HASHTYPES)), type= GetHashFunction, required=False)

	parser.add_argument("--lowercase", help="Use lowercase character set", action="store_true", default=False)
	parser.add_argument("--uppercase", help="Use uppercase character set", action="store_true", default=False)
	parser.add_argument("--num", help="Use numeric character set", action="store_true", default=False)
	parser.add_argument("--symbols", help="Use symbols", action="store_true", default=False)
	parser.add_argument("--full_ascii", help="Use full ascii character set", action="store_true", default=False)

	parser.add_argument("-s", "--salt", help="[Optional] Salt Value", type=str)

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("--single",help="Single core operation", action="store_true", default=False)
	group.add_argument("--multi",help="Multi core operation", action="store_true", default=False)
	group.add_argument("--even",help="Multi core operation distributed evenly", action="store_true", default=False)

	gl_args = parser.parse_args()

	return gl_args

# Validates that the directory provided exists and is writeable
##------------------------------------------------------------------------------------------
def ValidateDirectory(dir):
	if not os.path.isdir(dir):
		raise argparse.ArgumentTypeError('[!] Directory: {} does not exist!'.format(dir))

	if os.access(dir, os.W_OK):
		return dir
	else:
		raise argparse.ArgumentTypeError('[!] Access to {} was denied!'.format(dir))	


# Converts the range string provided by the user into a tuple and does input validation
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

# Returns the supported hash generation function
##------------------------------------------------------------------------------------------
def GetHashFunction(hashfunc):
	if hashfunc not in HASHTYPES:
		raise argparse.ArgumentTypeError('[!] Hash function was not found or was not in the correct format')	
	if hashfunc == HASHTYPES[0]: ## MD5
		return hashlib.md5()
	elif hashfunc == HASHTYPES[1]: ## SHA1
		return hashlib.sha1()
	elif hashfunc == HASHTYPES[2]: ## SHA224
		return hashlib.sha224()
	elif hashfunc == HASHTYPES[3]: ## SHA256
		return hashlib.sha256()
	elif hashfunc == HASHTYPES[4]: ## SHA384
		return hashlib.sha384()
	elif hashfunc == HASHTYPES[5]: ## SHA512
		return hashlib.sha512()


# Determine the character set to use for brute password generation
##------------------------------------------------------------------------------------------
def GetCharacterList():
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
	return list_to_use


# Single
##------------------------------------------------------------------------------------------
def HashGenSingle(ran):

	print '\n[+] Single core hash generation mode'
	print '[+] Starting hash generation...'
	cnt = 0

	list_to_use = GetCharacterList()

	try:
		with open(output_directory + 'RB_Single.csv','w') as f:
			time_start = time.time()
			for i in range(ran[0], ran[-1]+1):
				for s in itertools.product(list_to_use, repeat=i):
					pword=''.join(s)

					gen_hash = hash_type

					if salt_value != None:
						pword = salt_value + pword
						gen_hash.update(pword)
					else:
						gen_hash.update(pword)

					hash_digest = gen_hash.hexdigest()

					f.write("{},{}\n".format(pword,hash_digest))
					cnt += 1

					del gen_hash
		time_diff = time.time() - time_start
		print '[+] RB_Single.csv generation complete'
		print '[+] {} hashes generated in {} seconds'.format(str(cnt), str(time_diff))
		return cnt
	except Exception, e:
		print "[!] Error generating or writing hashes"
		print str(e)
		exit(0)	





# Multi core method 1
##------------------------------------------------------------------------------------------
def PasswordGen_1(size):
	cnt = 0

	list_to_use = GetCharacterList()

	try:
		with open(output_directory + 'RB{}.csv'.format(size),'w') as f:
			time_start = time.time()
			for i in range(size, size+1):
				for s in itertools.product(list_to_use, repeat=i):
					pword=''.join(s)

					gen_hash = hash_type

					if salt_value != None:
						pword = salt_value + pword
						gen_hash.update(pword)
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

# spawn multiple threads to do the password generation and hashing
##------------------------------------------------------------------------------------------
def CreatePool_1(ran):
	cpu_pool = multiprocessing.Pool(processes=CORE_COUNT)
	print '\n[+] {} CPU cores available for processing'.format(CORE_COUNT)
	print '[+] Starting hash generation...'
	results = cpu_pool.map(PasswordGen_1,(ran))
	return results








# Multi core method 2  -- evenly split work among cores... other than the list generation
##------------------------------------------------------------------------------------------

# Generates a password list to be split among cores
##------------------------------------------------------------------------------------------
def PasswordGen_2(ran):
	pword_list = []
	list_to_use = GetCharacterList()

	for i in range(ran[0], ran[-1]+1):
		for s in itertools.product(list_to_use, repeat=i):
			pword=''.join(s)
			pword_list.append(pword)

	return pword_list


# Do the hashing of a password list
##------------------------------------------------------------------------------------------
def HashList(alist):
	cnt = 0
	try:
		with open(output_directory + 'RB{}.csv'.format(alist[0]),'w') as f:
			time_start = time.time()
			for pword in alist:
				gen_hash = hash_type

				if salt_value != None:
					pword = salt_value + pword
					gen_hash.update(pword)
				else:
					gen_hash.update(pword)

				hash_digest = gen_hash.hexdigest()

				f.write("{},{}\n".format(pword,hash_digest))
				cnt += 1

				del gen_hash
		time_diff = time.time() - time_start
		print '[+] RB{}.csv generation complete'.format(alist[0])
		print '[+] {} hashes generated in {} seconds'.format(str(cnt), str(time_diff))
		return cnt
	except Exception, e:
		print "[!] Error generating or writing hashes"
		print str(e)
		exit(0)


# spawn multiple threads to do the password generation and hashing
##------------------------------------------------------------------------------------------
def CreatePool_2(ran):
	cpu_pool = multiprocessing.Pool(processes=CORE_COUNT)
	print '\n[+] {} CPU cores available for processing'.format(CORE_COUNT)
	print '[+] Starting hash generation...'

	# Create password list and break into mostly even chunks for processing
	pwords = PasswordGen_2(ran)
	leng = len(pwords)/CORE_COUNT
	chunks=tuple(pwords[x:x+leng] for x in range(0, len(pwords), leng))

	results = cpu_pool.map(HashList,(chunks))
	return results




##------------------------------------------------------------------------------------------
##------------------------------------------------------------------------------------------
if __name__ == "__main__":
	args = Arguments()
	output_directory = args.directory
	ascii_bool = args.full_ascii
	lower_bool = args.lowercase
	upper_bool = args.uppercase
	num_bool = args.num
	sym_bool = args.symbols

	# if the user didn't use one or more character sets, exit
	if (ascii_bool == False) and (lower_bool == False) and (upper_bool == False) and (num_bool == False) and (sym_bool == False):
		print '[!] No chracter set selected... Exiting'
		exit(0)

	salt_value = args.salt
	length_range = args.length
	hash_type = args.hash

	start_time = time.time()
	if args.single:
		counts = HashGenSingle(length_range)
	elif args.multi:
		counts = CreatePool_1(length_range)
	elif args.even:
		counts = CreatePool_2(length_range)

	stop_time = time.time() - start_time
	print '[+] Total processing time: {} seconds'.format(str(stop_time))











