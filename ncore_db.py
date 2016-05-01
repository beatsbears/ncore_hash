#!/usr/bin/env python

'''
Author: Andrew Scott
Date: 4/30/2016  
'''


import sqlite3
import csv
import argparse
import os
import string


# Parse command line arguments
##------------------------------------------------------------------------------------------
def Arguments():
	parser = argparse.ArgumentParser(description='Hash table aggregation and search tool')

	parser.add_argument('-dir', "--directory",  help="Read Directory", type= ValidateDirectory, required=False)
	parser.add_argument('-db', "--database",  help="DB to search for hash", type= ValidateFile, required=False)
	parser.add_argument('-i', "--input", help="Hash to search for", type=str, required=False)
	parser.add_argument('-s', "--strict", help="Only include .csv files of the same hash type", action="store_true", default=False, required=False)
	parser.add_argument('-n', "--new", help="Create a new hash database", action="store_true", default=False, required=False)
	parser.add_argument('-d', "--existingDatabase", help="Use an existing database", type= ValidateDatabase, required=False)


	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("--search",help="Search for hash in ", action="store_true", default=False)
	group.add_argument("--agg", help="Aggregate csv files into sqlite DB", action="store_true", default=False)

	gl_args = parser.parse_args()

	return gl_args

# Print a silly header
##------------------------------------------------------------------------------------------
def PrintHeader():
	print """\033[0;33m
 __    _  _______  _______  ______    _______ 
|  |  | ||       ||       ||    _ |  |       |
|   |_| ||       ||   _   ||   | ||  |    ___|
|       ||       ||  | |  ||   |_||_ |   |___ 
|  _    ||      _||  |_|  ||    __  ||    ___|
| | |   ||     |_ |       ||   |  | ||   |___ 
|_|  |__||_______||_______||___|  |_||_______|  v0.1\n\n\033[0m"""


# Validates that the directory provided exists and is writeable/readable
##------------------------------------------------------------------------------------------
def ValidateDirectory(direct):
	if not os.path.isdir(direct):
		raise argparse.ArgumentTypeError('[!] Directory: {} does not exist!'.format(direct))

	if os.access(direct, os.W_OK) and os.access(direct, os.R_OK):
		return direct
	else:
		raise argparse.ArgumentTypeError('[!] Access to {} was denied!'.format(direct))	

# Validates that the file provided exists and is readable
##------------------------------------------------------------------------------------------
def ValidateFile(theFile):
	if not os.path.exists(theFile):
		raise argparse.ArgumentTypeError('[!] File: {} does not exist!'.format(theFile))

	if os.access(theFile, os.R_OK):
		return theFile
	else:
		raise argparse.ArgumentTypeError('[!] Access to {} was denied!'.format(theFile))


# Validates that the database provided exists and is readable
##------------------------------------------------------------------------------------------
def ValidateDatabase(db):
	if not os.path.exists(db):
		raise argparse.ArgumentTypeError('[!] Database: {} does not exist!'.format(db))

	if os.access(db, os.R_OK) and db.split(".")[-1] == "sqlite3":
		return db
	else:
		raise argparse.ArgumentTypeError('[!] Access to {} was denied!'.format(db))


# Aggregate a new db from all the csv files in the target directory
##------------------------------------------------------------------------------------------
def CreateNewDB(direct,new,existing):
	db_to_use = ""
	existing_db = CheckExistingDB(direct)

	if existing:
		db_to_use = existing
		return db_to_use

	elif new and len(existing_db) < 1:
		db_to_use = direct + "nC_1.sqlite3"

	elif new and len(existing_db) >= 1:
		top_db = 0
		# dude... gross
		for file in existing_db:
			if int((file.split('.')[0])[-1]) > top_db:
				top_db = int((file.split('.')[0])[-1])
		db_to_use = direct + "nC_{}.sqlite3".format(str(top_db+1))

	elif len(existing_db) == 1:
		db_to_use = existing_db[0]
		return db_to_use

	elif len(existing_db) > 1:
		user_selected_db = str(raw_input("Which existing Database would you like to use: \n{}\n".format("\n".join(existing_db))))
		if user_selected_db not in existing_db:
			print "[!] Selected DB is not available or does not exist: {}".format(user_selected_db)
			exit(0)
		db_to_use = direct + user_selected_db
		return db_to_use
	else:
		if len(existing_db) < 1:
			db_to_use = direct + "nC_1.sqlite3"
		else:
			print "[!] Selected DB is not available or does not exist: {}".format(user_selected_db)
			exit(0)

	try:
		# Connecting to the database file if one does not exist yet
		conn = sqlite3.connect(db_to_use)
		c = conn.cursor()

		# Create new table
		c.execute('CREATE TABLE nC_Hashes \
			(plain TEXT PRIMARY KEY,\
			salt TEXT NULL,\
			hash TEXT NOT NULL,\
			algorithm TEXT NOT NULL)')

		# commit and close	
		conn.commit()
		conn.close()
	except Exception, e:
		print '[!] Error creating or accessing Database: {}'.format(db_to_use)
		print str(e)
		exit(0)

	# finally return this new db
	print '[+] Successfully created new Database: {}'.format(db_to_use)
	return db_to_use	


# Return any existing databases
##------------------------------------------------------------------------------------------
def PopulateOrAddToDB(db,files):
	conn = sqlite3.connect(db)
	c = conn.cursor()
	try:
		for file in files:
			ht = ((file.split('/')[-1]).split('.')[0]).split('_')[-1]
			reader = csv.reader(open(file, 'r'), delimiter=',')
			for row in reader:
				to_db = [unicode(row[0], "utf8"), unicode(row[1], "utf8"), unicode(row[2], "utf8"), unicode(ht, "utf8")]
				c.executemany("INSERT INTO nC_Hashes (plain, salt, hash, algorithm) VALUES (?, ?, ?, ?);", [to_db])
			conn.commit()
			print '[+] Successfully imported {}'.format(file)
		conn.close()
	except Exception, e:
		print '[!] Error writing to Database!'
		print str(e)
		exit(0)

# Return any existing databases
##------------------------------------------------------------------------------------------
def CheckExistingDB(direct):
	existing_db = []
	for file in os.listdir(direct):
		if file.split('.')[-1] == "sqlite3" and file[:2] == 'nC':
			existing_db.append(direct+file)

	return existing_db


# Return a dictionary of all eligable csv files along with hash type
##------------------------------------------------------------------------------------------
def ReturnFiles(direct):
	valid_files = {}

	for file in os.listdir(direct):
	    if file.split('.')[-1] == 'csv' and file[:2] == 'nC':
	    	hash_type = (file.split('_')[-1])[:-4]
	    	file_path = direct + file
	    	valid_files[file_path] = hash_type

	return valid_files


# Search for a hash in the target database
##------------------------------------------------------------------------------------------
def SearchDB(dbname,hash_to_find):
	try:
		conn = sqlite3.connect(dbname)
		c = conn.execute("SELECT * FROM nC_Hashes WHERE hash = '{}' LIMIT 1;".format(hash_to_find))
		for row in c:
			if row[0] != None:
				return row
		return '.'
	except:
		print "[!] No result found or error during search"
	finally:
		conn.close()

# Pretty print db row result
##------------------------------------------------------------------------------------------
def PrintResults(foundtuple):
	if foundtuple == '.':
		print "[-] Hash not found in table"
	else:
		if foundtuple[1] != "None":
			print "[+] Salted Password: {}".format(foundtuple[0])
			print "[+] Salt: {}".format(foundtuple[1])
			print "[+] Password: {}".format(remove_all(foundtuple[1],foundtuple[0]))
		else:
			print "[+] No Salt"
			print "[+] Password: {}".format(foundtuple[0])
		print "[+] Hash: {}".format(foundtuple[2])
		print "[+] Hash Algorithm: {}".format(foundtuple[3])


def remove_all(substr, st):
    index = 0
    length = len(substr)
    while string.find(st, substr) != -1:
        index = string.find(st, substr)
        st = st[0:index] + st[index+length:]
    return st


##------------------------------------------------------------------------------------------
##------------------------------------------------------------------------------------------
if __name__ == "__main__":
	PrintHeader()
	args = Arguments()
	# parse arguements
	directory = args.directory
	database = args.database
	hash_to_find = args.input
	same_hash = args.strict
	new_db = args.new
	existing_db = args.existingDatabase
	agg_mode = args.agg
	search_mode = args.search

	if agg_mode:
		# gather all csv files and get their hash type
		csv_to_process = ReturnFiles(directory)
		current_db = CreateNewDB(directory,new_db,existing_db)
		PopulateOrAddToDB(current_db,csv_to_process)
	elif search_mode:
		res = SearchDB(database,hash_to_find)
		PrintResults(res)






