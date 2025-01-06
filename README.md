# PasswordGen-and-Evaluator----Python
A secure and feature-rich password management application built with Python and Tkinter.

## Features

- **Password Generation**
  - Customizable length (8-128 characters)
  - Include/exclude character types:
    - Uppercase letters
    - Lowercase letters
    - Numbers
    - Special symbols
  - Random and secure generation

- **Password Management**
  - Copy passwords to clipboard
  - Save encrypted passwords locally
  - Load saved passwords
  - Export passwords to CSV
  - Password history tracking

- **Security Features**
  - Password strength evaluation
  - Password hashing (SHA-256)
  - Encryption using Fernet (symmetric encryption)
  - Secure storage of passwords

- **User Interface**
  - Clean and intuitive GUI
  - Dark/Light theme toggle
  - Password history display
  - Real-time password strength feedback

## Requirements

pip install cryptography
pip install pyperclip
pip install tkinter

## Usage

Run the application using the following command:
python app.py

## Generate a Password:
Set desired password length
Select character types to include
Click "Generate Password"

## Password Management:
Use "Copy to Clipboard" to copy generated passwords
"Save Password" stores encrypted passwords
"Load Passwords" retrieves saved passwords
"Export Password" saves to CSV format

## Password Evaluation:
Enter a password to evaluate
Get instant feedback on password strength
Generate SHA-256 hash of passwords
Security Features
Passwords are encrypted before storage using Fernet symmetric encryption
Password strength evaluation checks for:
Minimum length (8 characters)
Presence of numbers
Uppercase letters
Lowercase letters
Special characters

## File Structure
app.py: Main application file
passwords.txt: Encrypted password storage
exported_passwords.csv: CSV export file

## Technical Details
Built with Python 3.x
GUI: Tkinter
Encryption: cryptography.fernet
Clipboard handling: pyperclip
Hashing: hashlib (SHA-256)

## Best Practices
Regularly backup your passwords.txt file
Use strong passwords (mix of all character types)
Keep your system and Python packages updated
Don't share your encryption keys

## License
## This project is open source and available under the MIT License.


## This README provides a comprehensive overview of your password manager application, including all its features, setup instructions, and security considerations. Users will find everything they need to get started and make the most of the application's capabilities.
