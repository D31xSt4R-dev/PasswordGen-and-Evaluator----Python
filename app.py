import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import hashlib
import pyperclip
import csv
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator and Evaluator")
        self.master.geometry("700x900")
        self.master.resizable(False, False)

        self.key = generate_key()
        self.cipher = Fernet(self.key)

        self.create_widgets()
        self.password_history = []

    def create_widgets(self):
        self.style = ttk.Style()
        self.style.theme_use("default")

        ttk.Button(self.master, text="Toggle Theme", command=self.toggle_theme).pack(pady=10)

        tk.Label(self.master, text="Password Generator", font=("Arial", 14)).pack(pady=10)

        tk.Label(self.master, text="Length:").pack()
        self.password_length = tk.Spinbox(self.master, from_=8, to=128, width=10)
        self.password_length.pack()

        tk.Label(self.master, text="Include:").pack()
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_digits = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)

        tk.Checkbutton(self.master, text="Uppercase Letters", variable=self.include_uppercase).pack()
        tk.Checkbutton(self.master, text="Lowercase Letters", variable=self.include_lowercase).pack()
        tk.Checkbutton(self.master, text="Digits", variable=self.include_digits).pack()
        tk.Checkbutton(self.master, text="Symbols", variable=self.include_symbols).pack()

        ttk.Button(self.master, text="Generate Password", command=self.generate_password).pack(pady=10)

        tk.Label(self.master, text="Generated Password:").pack()
        self.generated_password = tk.StringVar()
        tk.Entry(self.master, textvariable=self.generated_password, width=50).pack()

        ttk.Button(self.master, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(pady=5)
        ttk.Button(self.master, text="Save Password", command=self.save_password).pack(pady=5)
        ttk.Button(self.master, text="Load Passwords", command=self.load_passwords).pack(pady=5)
        ttk.Button(self.master, text="Export Password", command=self.export_password).pack(pady=5)

        tk.Label(self.master, text="Evaluate Password:").pack()
        self.password_input = tk.StringVar()
        tk.Entry(self.master, textvariable=self.password_input, width=50).pack()
        ttk.Button(self.master, text="Evaluate", command=self.evaluate_password).pack(pady=5)
        self.result = tk.StringVar()
        tk.Label(self.master, textvariable=self.result).pack()

        tk.Label(self.master, text="Hash Password:").pack()
        self.hash_result = tk.StringVar()
        ttk.Button(self.master, text="Hash", command=self.hash_password).pack(pady=5)
        tk.Label(self.master, textvariable=self.hash_result).pack()

        tk.Label(self.master, text="Password History:").pack()
        self.history_text = tk.Text(self.master, height=10, width=50, state='disabled')
        self.history_text.pack()

    def toggle_theme(self):
        if self.style.theme_use() == "default":
            self.style.theme_use("alt")
            self.master.configure(bg="#2E2E2E")
            for widget in self.master.winfo_children():
                widget.configure(bg="#2E2E2E", fg="white")
        else:
            self.style.theme_use("default")
            self.master.configure(bg="SystemButtonFace")
            for widget in self.master.winfo_children():
                widget.configure(bg="SystemButtonFace", fg="black")

    def generate_password(self):
        length = int(self.password_length.get())
        if length < 8 or length > 128:
            messagebox.showwarning("Warning", "The password length must be between 8 and 128 characters.")
            return
        
        characters = ""
        if self.include_uppercase.get():
            characters += string.ascii_uppercase
        if self.include_lowercase.get():
            characters += string.ascii_lowercase
        if self.include_digits.get():
            characters += string.digits
        if self.include_symbols.get():
            characters += string.punctuation

        if not characters:
            messagebox.showwarning("Warning", "Please select at least one character type.")
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        self.generated_password.set(password)
        self.password_history.append(password)
        self.update_history_display()

    def copy_to_clipboard(self):
        password = self.generated_password.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard.")
        else:
            messagebox.showwarning("Warning", "No password generated to copy.")

    def save_password(self):
        password = self.generated_password.get()
        if password:
            try:
                encrypted = self.cipher.encrypt(password.encode())
                with open("passwords.txt", "ab") as file:
                    file.write(encrypted + b"\n")
                messagebox.showinfo("Saved", "Password saved successfully.")
            except Exception as e:
                messagebox.showwarning("Error", f"Error saving password: {str(e)}")
        else:
            messagebox.showwarning("Warning", "No password generated to save.")

    def load_passwords(self):
        try:
            with open("passwords.txt", "rb") as file:
                passwords = file.readlines()
                decrypted_passwords = [self.cipher.decrypt(p).decode() for p in passwords]
                messagebox.showinfo("Loaded", f"Loaded {len(decrypted_passwords)} passwords.")
        except Exception as e:
            messagebox.showwarning("Error", f"Error loading passwords: {str(e)}")

    def export_password(self):
        password = self.generated_password.get()
        if password:
            with open("exported_passwords.csv", "a", newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([password])
            messagebox.showinfo("Exported", "Password exported to CSV.")
        else:
            messagebox.showwarning("Warning", "No password generated to export.")

    def evaluate_password(self):
        password = self.password_input.get()
        if len(password) < 8:
            self.result.set("Too weak: Password must be at least 8 characters long.")
        elif not any(char.isdigit() for char in password):
            self.result.set("Moderate: Password should include at least one digit.")
        elif not any(char.islower() for char in password):
            self.result.set("Moderate: Password should include at least one lowercase letter.")
        elif not any(char.isupper() for char in password):
            self.result.set("Moderate: Password should include at least one uppercase letter.")
        elif not any(char in string.punctuation for char in password):
            self.result.set("Moderate: Password should include at least one special character.")
        else:
            self.result.set("Secure: Your password is strong!")

    def hash_password(self):
        password = self.password_input.get()
        if password:
            hashed = hashlib.sha256(password.encode()).hexdigest()
            self.hash_result.set(f"Hashed: {hashed}")
        else:
            messagebox.showwarning("Warning", "No password to hash.")

    def update_history_display(self):
        self.history_text.config(state='normal')
        self.history_text.delete(1.0, tk.END)
        for pwd in self.password_history:
            self.history_text.insert(tk.END, f"{pwd}\n")
        self.history_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
