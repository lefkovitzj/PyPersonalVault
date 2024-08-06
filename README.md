# PyPersonalVault
PyPersonalVault is a file encryption application built in Python. It allows users to securely encrypt their files (any filetypes except .py and PyPersonalVault-related files should work) with a password. Multiple seperate vaults can be created, with each having a seperate password.


The graphical user interface (GUI) is built with TKinter and CustomTkinter (pip install customtkinter). Cryptographic algorithms are sourced from the RSA, AES, and SHA3_256 portions of the PyCryptodome package (pip install pycryptodomex), and various Python Standard Library modules are used throughout. Many thanks to the developers of and contributors to these excellent tools!


Currently on version 1.0.1, PyPersonal Vault allows creation of multiple vaults, file encryption using a specific vault and password, and file decryption using the same vault and password used in encrypting the file. 
If you are interested in a lighter-weight alternative to this application check out my <a href="https://github.com/lefkovitzj/PyCrypter">PyCrypter project</a> as well!


Possible features for future updates to PyPersonalVault include:
1. Displaying a list of all files encrypted by a specific PyPersonalVault.
2. Delete a PyPersonalVault.
3. Change username and/or password for a PyPersonalVault.
4. Encrypt and decrypt all files in a folder at once.
5. A command-line version of the application.


The necessary files to run PyPersonalVault are:
<ul> 
  <li>app.py </li>
  <li>utils.py</li>
  <li>application_data.json</li>
  <li>license.txt</li>
</ul>

If any file is missing, the application will inform the user on startup and will provide a button that links to this project repository. If data is corrupted, a similar message will be displayed. All files are necessary for the project to permit the user to run core functionality. Run the project by executing the app.py file in the command line, IDE, or any other method to run a Python file.

The following dependencies must be installed in order for the application to run:
<ul>
  <li><a href="https://pycryptodome.readthedocs.io/en/latest/src/installation.html" style="text-decoration:none"> PyCryptodome </a> - pip install pycryptodomex</li>
  <li><a href="https://customtkinter.tomschimansky.com/documentation/" style="text-decoration:none"> CustomTkinter </a> - pip install customtkinter</li>
</ul>

Feel free to reach out to me with ideas, questions, or other comments regarding this project by opening an Issue or by email at <a href="mailto:flaskdoggo@gmail.com" style="text-decoration:none">flaskdoggo@gmail.com</a>!
