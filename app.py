"""
	Author: AaronTook (https://AaronTook.github.io)
	Version: 1.0.0
	Version Launch Date: 12/1/2023
	File Last Modified: 12/1/2023
	Project Name: PyPersonalVault
	File Name: app.py
"""

""" Python Standard Library imports. """
import os, sys, json, requests, webbrowser

""" Third-party imports. """
import customtkinter

""" Application file imports. """
import utils

""" Set the customtkinter appearance mode and theme. """
customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

""" Create a class to represent a PyPersonalVault, with information storage and any minor utility methods. """
class VaultManagerObject():
	# Initialize the object.
	def __init__(self, vault_name, key_file_location, vault_file_paths_list):	
		self.name = vault_name
		self.key_file = key_file_location
		self.vault_files = vault_file_paths_list
	# Save the data about the vault to a PersonalVaultData (.pvd) file using the JSON format.
	def save_vault_data(self):
		# Format the vault data.
		vault_data = {
			"Name": self.name,
			"Key File Location": self.key_file,
			"Vault File List": self.vault_files
		}
		# Save the vault data.
		with open(f"PyPersonalVault - {self.name}.pvd", "w") as vault_data_file:
			json.dump(vault_data, vault_data_file, indent =4)
			vault_data_file.close()

""" Create a class to contain the Application with its functionality and GUI. """
class App(customtkinter.CTk):
	# Initialize the object.
	def __init__(self):
		# Define the GUI window and lock its dimensions.
		super().__init__()
		self.resizable(width=False, height=False)
		
		# Initialize the current vault data, which will eventually be filled with a VaultManagerObject.
		self.current_vault = None
		
		# GUI Data to represent different GUIs that have been opened.
		self.guis_open = []
		self.create_gui_launcher()
	
	""" Create the four main GUI stages of the application (launcher, update checker, license agreement, pypersonalvault). """
	# Create the main Application Launcher GUI.
	def create_gui_launcher(self):
		# Get the project directory.
		path = os.getcwd()
		has_encrypted_dir = False
		has_decrypted_dir = False
		has_license_file = False
		has_app_data_file = False
		
		# Ensure that license.txt and application_data.json exist in the project directory.
		for dir_obj in os.scandir(path):
			if dir_obj.is_file():
				if dir_obj.name.lower() == "license.txt":
					has_license_file = True
				elif dir_obj.name.lower() == "application_data.json":
					has_app_data_file = True
			elif dir_obj.is_dir():
				if  dir_obj.name == "encrypted":
					has_encrypted_dir = True
				elif dir_obj.name == "decrypted":
					has_decrypted_dir = True
		
		# If the required directories are missing, simply create them.
		if has_decrypted_dir!= True:
			os.mkdir("decrypted")
		if has_encrypted_dir!= True:
			os.mkdir("encrypted")
		
		# Detirmine if any necessary files are missing or corrupted.
		initialization_errors = []
		required_resources_list = {"license.txt": has_license_file, "application_data.json": has_app_data_file}
		for required_resource, resource_exists in required_resources_list.items():
			if not resource_exists:
				initilalization_errors.append(f"Missing file: {required_resource}")
		
		# Get update-related information using the data file.
		try:
			with open("application_data.json", "r") as app_data_file:
				self.app_data_from_file = json.load(app_data_file)
			self.app_source_url = self.app_data_from_file["app_source_url"]
			self.license_accepted = self.app_data_from_file["license_accepted"]
			self.update_status, self.update_message = utils.needs_update(self.app_data_from_file)
		except (json.decoder.JSONDecodeError, KeyError):
			initialization_errors.append("Invalid file contents: application_data.json")
		
		# If there are no missing or corrupt files, launch the update GUI.
		if initialization_errors == []:
			self.create_gui_update()
		# Some file(s) have been deleted or corrupted. Display which files, and offer to open a source for downloading new versions of the files.
		else:
			# There is no need to add this GUI to a list of opened GUIs, as the only way to leave this GUI will be by closing it or clicking a button that automatically closes it.
			self.title("PyPersonalVault Launcher")    
			self.geometry("450x300") # Dimensions of the window will be 450x300.
			self.grid_rowconfigure(0, weight=0)  # Configure grid system.
			self.grid_columnconfigure(0, weight=1)
			self.grid_rowconfigure(1, weight=1)
			self.grid_rowconfigure(2, weight=0)
			
			# Create a CTkFrame with a label to describe the purpose of the window.
			self.label_frame = customtkinter.CTkFrame(self, width=430, height=40)
			self.label_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=(10,0))
			self.label_launcher = customtkinter.CTkLabel(self.label_frame, text=f"PyPersonalVault App Launcher", height=20, width=410)
			self.label_launcher.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

			# Set the launcher's textbox message to be a list of any errors encountered at launch.
			launcher_message = "\n".join(initialization_errors)
			
			# Create the textbox to contain the update message.
			self.textbox_launcher = customtkinter.CTkTextbox(self, width=400, corner_radius=10, wrap="word")
			self.textbox_launcher.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=10, padx=10)
			self.textbox_launcher.insert("0.0", launcher_message+"\n")
			
			# Create the button to launch the app and open the update in the browser.
			self.button_open_for_download = customtkinter.CTkButton(self, text="Get needed files", command=self.launcher_open_for_download, width = 200)
			self.button_open_for_download.grid(row=2, column=1, sticky="ns", pady=10, padx=10)
	
	# Create the main Update Checker GUI.
	def create_gui_update(self):
		# Detirmine if an update is needed based on the return from utils.needs_update.
		if self.update_status == False: # An update is needed or available.
			self.create_license_agreement_gui()
			return
		else:
			# Add update to list of opened GUIs
			self.forget_any_guis()
			self.guis_open.append("update")
			
			self.title("PyPersonalVault Update Information")    
			self.geometry("450x300") # Dimensions of the window will be 450x300.
			self.grid_rowconfigure(0, weight=0)  # Configure grid system.
			self.grid_columnconfigure(0, weight=1)
			self.grid_rowconfigure(1, weight=1)
			self.grid_rowconfigure(2, weight=0)
			
			# Create a CTkFrame with a label to describe the purpose of the window.
			self.label_frame = customtkinter.CTkFrame(self, width=430, height=40)
			self.label_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=(10,0))
			self.label_update = customtkinter.CTkLabel(self.label_frame, text=f"PyPersonalVault Update Tool", height=20, width=410)
			self.label_update.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
			
			# Set the update checker's textbox message to be the description returned by utils.needs_update.
			update_message = f"{self.update_message}"
			
			# Create the textbox to contain the update message.
			self.textbox_update = customtkinter.CTkTextbox(self, width=400, corner_radius=10, wrap="word")
			self.textbox_update.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=10, padx=10)
			self.textbox_update.insert("0.0", self.update_message+"\n")
			
			# Create the button to launch the app without updating.
			self.button_open_no_update = customtkinter.CTkButton(self, text="Launch Without Updating", command=self.update_gui_button_event_open, width = 200)
			self.button_open_no_update.grid(row=2, column=0, sticky="ns", pady=10, padx=10)
			
			# Create the button to launch the app and open the update in the browser.
			self.button_open_update = customtkinter.CTkButton(self, text="Open Update & Launch", command=self.update_gui_button_event_update_and_open, width = 200)
			self.button_open_update.grid(row=2, column=1, sticky="ns", pady=10, padx=10)
	
	# Create the main License Agreement GUI.
	def create_license_agreement_gui(self):
		# Detirmine if the license has been accepted.
		if self.license_accepted == True:
			# Skip this GUI and launch the main application GUI.
			self.create_pypersonalvault_gui()
		# Display the license acceptance GUI.
		else:
			# Forget the grid items from the last GUI.
			self.forget_any_guis()
			
			# Add license to list of opened GUIs.
			self.guis_open.append("license")
			
			self.title("PyPersonalVault License Agreement")    
			self.geometry("450x400") # Dimensions of the window will be 450x400.
			self.grid_rowconfigure(0, weight=0)  # Configure grid system.
			self.grid_columnconfigure(0, weight=1)
			self.grid_rowconfigure(1, weight=1)
			self.grid_rowconfigure(2, weight=0)
			
			# Create a CTkFrame with a label to describe the purpose of the window.
			self.label_frame = customtkinter.CTkFrame(self, width=400, height=40)
			self.label_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=(10,0))
			self.label_license = customtkinter.CTkLabel(self.label_frame, text="You must agree to the PyPersonalVault license to continue.", height=20)
			self.label_license.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
			
			# Open the license file and format its contents for GUI display.
			with open("license.txt",'r') as license_file:
				license_lines = license_file.readlines()
			license_text = ""
			for line in license_lines:
				if line!="\n":
					line=line.replace("\n"," ")
				else:
					line = line.replace("\n", "\n\n")
				license_text += line
				
			# Create the textbox to contain the license message.
			self.textbox_license = customtkinter.CTkTextbox(self, width=400, corner_radius=10, wrap="word")
			self.textbox_license.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=10, padx=10)
			self.textbox_license.insert("0.0", license_text+"\n")
			
			# Create the checkbox to indicate agreement to the license.
			self.check_var = customtkinter.StringVar(value="off")
			self.checkbox_agree_license = customtkinter.CTkCheckBox(self, text="I have read and agree to the License", command=self.license_agreement_gui_checkbox_event, variable=self.check_var, onvalue="on", offvalue="off")
			self.checkbox_agree_license.grid(row=2, column=0, sticky="nsew", pady=10, padx=10)
			
			# Create the button to launch the app after agreeing to the license.
			self.button_launch_and_agree = customtkinter.CTkButton(self, text="Launch PyPersonalVault", command=self.license_agreement_gui_button_event)
			self.button_launch_and_agree.grid(row=2, column=1, sticky="nse", pady=10, padx=10)
			
			# Set default settings:
			self.button_launch_and_agree.configure(state="disabled")
			
	# Create the main Application GUI.
	def create_pypersonalvault_gui(self):
		# Forget the grid items from the last GUI.
		self.forget_any_guis()
		self.guis_open.append("main")
		
		# Configure window.
		self.title("PyPersonalVault")
		self.geometry(f"{580}x{450}")

		# Set up the grid.
		self.grid_columnconfigure(1, weight=1)
		self.grid_columnconfigure((2, 3), weight=0)
		self.grid_rowconfigure((0, 1, 2), weight=1)

		# Create sidebar frame with widgets.
		self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
		self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
		self.sidebar_frame.grid_rowconfigure(4, weight=1)
		self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="PyPersonalVault", font=customtkinter.CTkFont(size=20, weight="bold"))
		self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
		self.sidebar_button_1 = customtkinter.CTkButton(self.sidebar_frame, text="Open Vault", command=self.gui_open_vault)
		self.sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
		self.sidebar_button_2 = customtkinter.CTkButton(self.sidebar_frame, state="disabled", text="Lock Vault", command=self.gui_close_vault)
		self.sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
		self.sidebar_button_3 = customtkinter.CTkButton(self.sidebar_frame, text="New Vault", command=self.input_for_new_vault)
		self.sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)
		self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
		self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
		self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Dark", "Light", "System"],
																	   command=self.change_appearance_mode_event)
		self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))
		
		# Create images of PDF.
		self.frame_vault = customtkinter.CTkFrame(self, height = 20, width = 20)
		self.frame_vault.grid(row=0, column=1, padx=(20, 20), pady=(20, 20), sticky="nsew", rowspan=3)
		self.frame_vault.grid_columnconfigure(0, weight=1)
		
		self.label_vault = customtkinter.CTkLabel(self.frame_vault, text="Open a vault to get started!")
		self.label_vault.grid(row=0, column=0, padx=20, pady=20)

		self.label_console = customtkinter.CTkLabel(self.frame_vault, text="", width=250)
		self.label_console.grid(row=1, column=0, padx=20, pady=20)
		
		self.encrypt_button = customtkinter.CTkButton(self.frame_vault, text="Encrypt a file", width=250, height=50, command=self.gui_encrypt)
		self.encrypt_button.grid(row=2, column=0, padx=10, pady=5)
		self.decrypt_button = customtkinter.CTkButton(self.frame_vault, text="Decrypt a file", width=250, height=50, command=self.gui_decrypt)
		self.decrypt_button.grid(row=3, column=0, padx=10, pady=5)
		
		# Set default values.
		self.label_vault.cget("font").configure(size=16) # Large font for main description.
		self.encrypt_button.configure(state="disabled")
		self.decrypt_button.configure(state="disabled")
	
	""" Create the functionality for all the commands called by widgets in the GUIs. """
	# Define the functionailty of the checkbox for the license agreement GUI.
	def license_agreement_gui_checkbox_event(self):
		if self.check_var.get() == "on":
			self.button_launch_and_agree.configure(state="normal")
		else:
			self.button_launch_and_agree.configure(state="disabled")
	
	# Define the functionailty of the button for the license agreement GUI.
	def license_agreement_gui_button_event(self):
		# The application shows that the license has been agreed to.
		if self.check_var.get()=="on":
			try:
				self.app_data_from_file["license_accepted"] = True
				with open("application_data.json", "w") as app_data_file:
					json.dump(self.app_data_from_file, app_data_file, indent = 4)
				self.create_pypersonalvault_gui()
			except:
				# Something went wrong with changing the data file, ignore until next application launch.
				self.create_pypersonalvault_gui()
		else:
			# Exit the program.
			sys.exit() 
	
	# Define the functionailty of the "open update and launch" button for the update GUI.
	def update_gui_button_event_update_and_open(self):
		# Open the browser to the source code repository, then launch the license agreement GUI.
		webbrowser.open(self.app_source_url)
		self.create_license_agreement_gui()
	
	# Define the functionailty of the "launch without updating" button for the update GUI.	
	def update_gui_button_event_open(self):
		# Launch the license agreement GUI.
		self.create_license_agreement_gui()

	# Define the functionality of the button for the launcher GUI.
	def launcher_open_for_download(self):
		# Open the browser to the root source code repository, which must be a hard-coded value  since normally you would use a value that is saved to the file "application.json", but that file may be missing if this method is being called.
		webbrowser.open("https://github.com/AaronTook/PyPersonalVault/")
		# Exit the application.
		sys.exit()
	
	# Call upon each new GUI opening (except the first) to clear any widgets from previous GUI screens.
	def forget_any_guis(self):
		# Check that there is at least one (1) GUI that has been opened.
		if len(self.guis_open) != 0:
			 # Clear the widgets from the  update GUI grid.
			if self.guis_open[-1] == "update":
				self.label_frame.grid_forget()
				self.label_update.grid_forget()
				self.button_open_update.grid_forget()
				self.button_open_no_update.grid_forget()
				self.textbox_update.grid_forget()
			# Clear the widgets from the license GUI grid.
			elif self.guis_open[-1] == "license": 
				self.label_frame.grid_forget()
				self.label_license.grid_forget()
				self.button_launch_and_agree.grid_forget()
				self.checkbox_agree_license.grid_forget()
				self.textbox_license.grid_forget()
	
	# Change the theme of the GUI based on the user's selection.
	def change_appearance_mode_event(self, new_appearance_mode: str):
		# Change the appearance mode (dark, light, or system) of the application.
		customtkinter.set_appearance_mode(new_appearance_mode)
	
	# Modify the main GUI to run the vault opening sequence.
	def gui_open_vault(self):
		# Open an existing vault.
		data_file_path, data_file_name = utils.gui_get_file(limit_filetypes=[("PyPersonalVault Data Files",".pvd")])
		if data_file_path == None or data_file_path == "":
			return None
		with open(data_file_path, "r") as vault_data_file:
			vault_data_json = json.load(vault_data_file)

		# Set the current vault to a new instance of the VaultManagerObject based on the user's file selection above.
		self.current_vault = VaultManagerObject(vault_data_json["Name"], vault_data_json["Key File Location"], vault_data_json["Vault File List"])
		
		# Reconfigure the GUI.
		self.label_vault.configure(text=f"PyPersonalVault - {self.current_vault.name}")
		self.label_vault.cget("font").configure(size=16)
		self.sidebar_button_1.configure(state="disabled")
		self.sidebar_button_2.configure(state="normal")
		self.sidebar_button_3.configure(state="disabled")
		self.encrypt_button.configure(state="normal")
		self.decrypt_button.configure(state="normal")
		self.label_console.configure(text="Vault opened successfully.")
	
	# Modify the main GUI to run the encryption sequence.
	def gui_encrypt(self):
		# Encrypt a file. 
		try:
			data_file_path, data_file_name = utils.gui_get_file()
			# No file was selected.
			if data_file_path == "" or data_file_path == None:
				return False
			# The selected file was a PyPersonalVault file (.pvk, .pvd, or .pv) and cannot be encrypted.
			elif data_file_path.lower().endswith(".pvk") or data_file_path.lower().endswith(".pvd") or data_file_path.lower().endswith(".pv"):
				self.label_console.configure(text=f"Cannot encrypt file because it is a PyPersonalVault key file, a PyPersonalVault data file, or a previously encrypted file.")
				self.label_console.after(20, lambda: self.label_console.configure(wraplength=250))
				return False
			# The selected file was a Python file and cannot be encrypted.
			elif data_file_path.lower().endswith(".py"):
				self.label_console.configure(text=f"Cannot encrypt file because it is a Python file.")
				self.label_console.after(20, lambda: self.label_console.configure(wraplength=250))
				return False
			# Encrypt the file using th RSA system using a user-input password and previously-stored data.
			status = utils.encrypt_with(open(data_file_path,'rb').read(), f"encrypted/{data_file_name}.pv", self.current_vault.key_file, utils.hash_sha3_256(self.open_input_dialog_event("Password:", show_instead="*")))
			# Detirmine if the encryption was a success.
			if status == True:
				# Update vault data and the GUI to indicate success.
				self.current_vault.vault_files.append(data_file_name)
				self.current_vault.save_vault_data()
				self.label_console.configure(text="Encryption succeeded!")
				return True
			else:
				# Inform the user of encryption failure via the GUI.
				self.label_console.configure(text="Encryption failed!")
		except:
			# Inform the user of encryption failure via the GUI.
			self.label_console.configure(text="Encryption failed!")
	
	# Modify the main GUI to run the decryption sequence.
	def gui_decrypt(self):
		# Decrypt a file. 
		try:
			data_file_path, data_file_name = utils.gui_get_file("/encrypted", limit_filetypes=[("PyPersonalVault Encrypted Files",".pv")])
			# No file was selected.
			if data_file_path == "" or data_file_path == None:
				return False
			# Remove the .pv from the end of the filename.
			output_file_location = data_file_name[:-3]
			# Decrypt the file using th RSA system using a user-input password and previously-stored data.
			utils.decrypt_with(data_file_path, "decrypted/"+output_file_location, self.current_vault.key_file, utils.hash_sha3_256(self.open_input_dialog_event("Password:", show_instead="*")))
			# Update the GUI to indicate success.
			self.label_console.configure(text="Decryption succeeded!")
			return True
		except:
			# Inform the user of encryption failure via the GUI.
			self.label_console.configure(text="Decryption failed!")
	
	# Modify the main GUI to run the vault closing sequence.
	def gui_close_vault(self):
		# Close the currently open vault.
		# Ensure that there is a vault currently open.
		if self.current_vault != None:
			# Update the vault status and GUI.
			self.current_vault = None
			self.label_vault.configure(text=f"Open a vault to get started!")
			self.label_vault.cget("font").configure(size=16)
			self.sidebar_button_1.configure(state="normal")
			self.sidebar_button_2.configure(state="disabled")
			self.sidebar_button_3.configure(state="normal")
			self.encrypt_button.configure(state="disabled")
			self.decrypt_button.configure(state="disabled")
			self.label_console.configure(text="")
			
	# Take input from the new vault creation GUI and create the new vault.
	def gui_new_vault(self):
		# Create and open a new vault.
		# Get the user's input from the form.
		new_name = self.input_name.get()
		new_password = self.input_password.get()
		new_password_confirm = self.input_password_confirm.get()
		
		# Ensure that the new name is not missing.
		if new_name!="":
			# Ensure that the new name does not have spaces.
			if " " not in new_name:
				self.input_name_label.configure(text="New Vault Name:")
				
				# Ensure that the passwords match.
				if  new_password == new_password_confirm:
					self.input_password_confirm_label.configure(text="Confirm Password:")
					
					# Ensure that the passwords are not missing.
					if new_password!="":
						# Update the GUI and create the vault key data file.
						self.frame_input.grid_forget()
						self.label_vault.configure(text=f"Vault key data is being generated. \nPlease be patient.")
						self.update()
						self.update_idletasks()
						new_vault_password_file = utils.create_keys(utils.hash_sha3_256(new_password), f"Keys - PyPersonalVault - {new_name}.pvk")
						self.label_vault.configure(text=f"Vault key data is being generated. \nPlease be patient.")
						
						# Set the current vault to a new instance of the VaultManagerObject based on the input above and the new key file.
						new_vault = VaultManagerObject(new_name, new_vault_password_file, [])
						new_vault.save_vault_data()
						self.current_vault = new_vault
						
						# Update the GUI.
						self.label_vault.configure(text=f"PyPersonalVault - {self.current_vault.name}")
						self.label_vault.cget("font").configure(size=16)
						self.sidebar_button_1.configure(state="disabled")
						self.sidebar_button_2.configure(state="normal")
						self.sidebar_button_3.configure(state="disabled")
						
						self.label_console = customtkinter.CTkLabel(self.frame_vault, text="")
						self.label_console.grid(row=1, column=0, padx=20, pady=20)
						self.label_console.configure(text="Vault created and opened successfully.")
						self.encrypt_button = customtkinter.CTkButton(self.frame_vault, text="Encrypt a file", width=250, height=50, command=self.gui_encrypt)
						self.encrypt_button.grid(row=2, column=0, padx=10, pady=5)
						self.decrypt_button = customtkinter.CTkButton(self.frame_vault, text="Decrypt a file", width=250, height=50, command=self.gui_decrypt)
						self.decrypt_button.grid(row=3, column=0, padx=10, pady=5)
				
				# The new passwords do not match.
				else:
					# Update the GUI to inform the user of the issue.
					self.input_password_confirm_label.configure(text="Confirm Password: Passwords do not match!")
			
			# The vault name includes spaces.
			else:
				# Update the GUI to inform the user of the issue.
				self.input_name_label.configure(text="New Vault Name: Cannot include spaces!")
	
	# Create the password popup GUI.
	def open_input_dialog_event(self, prompt_text, window_title="PyPersonalVault", show_instead=None):
		# Create a new window with an input based on the arguments passed to the function.
		dialog = customtkinter.CTkInputDialog(text=prompt_text, title=window_title)
		dialog.after(20, lambda: dialog._entry.configure(show=show_instead))
		# Return the user's input
		return dialog.get_input()

	# Modify the main GUI to run the new vault creation sequence.
	def input_for_new_vault(self):
		# Display the input form for creating a new vault. 
		self.label_vault.configure(text=f"Create a new vault")
		self.label_console.grid_forget()
		self.encrypt_button.grid_forget()
		self.decrypt_button.grid_forget()
		self.frame_input = customtkinter.CTkFrame(self.frame_vault)
		self.frame_input.grid(row=1, column=0, padx=5, pady=5)
		self.input_name = customtkinter.CTkEntry(self.frame_input, placeholder_text="Name...", width=250)
		self.input_name_label = customtkinter.CTkLabel(self.frame_input, text="New Vault Name:")
		self.input_password = customtkinter.CTkEntry(self.frame_input, placeholder_text="Password...",show='*', width=250)
		self.input_password_label = customtkinter.CTkLabel(self.frame_input, text="New Vault Password:")
		self.input_password_confirm = customtkinter.CTkEntry(self.frame_input, placeholder_text="Password...",show='*', width=250)
		self.input_password_confirm_label = customtkinter.CTkLabel(self.frame_input, text="Confirm Password:")
		self.input_button = customtkinter.CTkButton(self.frame_input, text="Create New Vault", width=250, command=self.gui_new_vault)

		self.input_name_label.grid(row=1, column=0, padx=10, pady=5)
		self.input_name.grid(row=2, column=0, padx=10, pady=5)

		self.input_password_label.grid(row=3, column=0, padx=10, pady=5)
		self.input_password.grid(row=4, column=0, padx=10, pady=5)
		
		self.input_password_confirm_label.grid(row=5, column=0, padx=10, pady=5)
		self.input_password_confirm.grid(row=6, column=0, padx=10, pady=5)
		
		self.input_button.grid(row=7, column=0, padx=10, pady=5)

if __name__ == "__main__":
	""" Run the application """
	app = App()
	app.mainloop()
