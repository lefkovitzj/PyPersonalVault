"""
	Author: AaronTook (https://AaronTook.github.io)
	Version: 1.0.0
	Version Launch Date: 12/5/2023
	File Last Modified: 12/5/2023
	Project Name: PyPersonalVault
	File Name: utils.py
"""

""" Python Standard Library imports. """
from tkinter import *
from tkinter import filedialog
import os, requests

""" Pycryptodome imports for encryption, decryption, key generation, and hashing. """
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_256

# Create and return the hash of a passed string argument .
def hash_sha3_256(str_data):
	h_obj = SHA3_256.new()
	h_obj.update(bytes(str_data, 'utf-8'))
	return str(h_obj.hexdigest())

# Create RSA keys and save them to a file with a password, then return the file name.
def create_keys(document_code, file_name):
	secret_code = (document_code)
	key = RSA.generate(2048)
	encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
								protection="scryptAndAES128-CBC")
	
	# Output the keys to a file.
	file_out = open(file_name, "wb")
	file_out.write(encrypted_key)
	file_out.close()
	return file_name

# Run RSA encryption using the passed arguments.
def encrypt_with(input_data, output_file_location, key_file_location, pass_phrase):
	try:
		data = input_data
		file_out = open(output_file_location, "wb")
		
		recipient_key = RSA.import_key(open(key_file_location).read(), passphrase=(pass_phrase)).publickey()
		session_key = get_random_bytes(16)
		
		# Encrypt the session key with the public RSA key.
		cipher_rsa = PKCS1_OAEP.new(recipient_key)
		enc_session_key = cipher_rsa.encrypt(session_key)
		
		# Encrypt the data with the AES session key.
		cipher_aes = AES.new(session_key, AES.MODE_EAX)
		ciphertext, tag = cipher_aes.encrypt_and_digest(data)
		[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
		file_out.close()
		return True
	except ValueError:
		return False

# Run RSA decryption using the passed arguments.
def decrypt_with(data_file_location, output_file_location, key_file_location, pass_phrase):
	file_in = open(data_file_location, "rb")
	file_out = open(output_file_location, "wb")
	private_key = RSA.import_key(open(key_file_location).read(), passphrase=(pass_phrase))
	
	enc_session_key, nonce, tag, ciphertext = \
		[ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
	file_in.close()
	
	# Decrypt the session key with the private RSA key.
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(enc_session_key)
	
	# Decrypt the data with the AES session key.
	cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
	data = cipher_aes.decrypt_and_verify(ciphertext, tag)
	file_out.write(data)

# Detirmine if the application has available or necessary updates if online return a boolean and a string representing status and description.
def needs_update(current_data):
	try:
		data_url = current_data["app_source_url"]
		data = requests.get(data_url).json()
		newest_version = data["version"]
		current_version = current_data["version"]
		
		# The application version is not up-to-date.
		if current_version != newest_version:
			# Get the Encryption System, Application Version, and Patch numbers.
			newest_version_digits = newest_version.split(".")
			current_version_digits = current_version.split(".")
			
			# The Encryption System is up-to-date.
			if newest_version_digits[0] == current_version_digits[0]:
				# The Application is on the most recent version.
				if newest_version_digits[1] == current_version_digits[1]:
					# The Application is not on the most recent patch.
					if newest_version_digits[2] != current_version_digits[2]:
						return True, "A bugfix or patch is available for PyPersonalVault. \n\nChanges should be minor and should not effect encrypted files in your vault(s). If an unexpected issue arises, you can downgrade versions later to recover the files as necessary."
				
				# The Application is not on the most recent Version.
				else:
					return True, "A new PyPersonalVault version is available. \n\nThis version should be either new features or user interraction changes, and any changes made should not effect encrypted files in your vault(s). If an issue arises, you can downgrade versions later to recover the files as necessary."
			
			# The Encryption System is not up-to-date.
			else:
				return True, "PyPersonalVault desperately needs updated! \n\nThis new version may make changes to the core encryption process, and as a result, you will need to decrypt all of the files in your vault(s) before updating or the encrypted files will be lost. You can always downgrade your system if necessary to recover the files, but they will be inaccessible in the new version."
		
		# The Application is on the most recent patch.
		else:
			return False, "You're good to go!"
	
	# The user is offline and the system cannot check for updates.
	except requests.exceptions.ConnectionError:
		return False, "You're offline. PyPersonalVault cannot check for updates at this time."

# Open a file selection app using tkinter and return the users selection as a full filepath and partial filename.
def gui_get_file(initial_directory="", limit_filetypes=[]):
	# Open file explorer (using tkinter) to select a file. 
	root = Tk()
	root.withdraw()
	complete_file_path = filedialog.askopenfilename(title="PyPersonalVault - File Select", initialdir = os.getcwd() + "/" + initial_directory, filetypes = limit_filetypes)
	root.destroy()
	# Extract the path and filename and return those strings.
	file_path, file_name = os.path.split(complete_file_path)
	return complete_file_path, file_name
