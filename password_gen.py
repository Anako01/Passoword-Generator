"""

Turns a memorable (weak) password into a strong, reproducible password.
Same memorable password + same length -> always the same strong password.

Method: PBKDF2-HMAC-SHA256 (200,000 iterations) derives bytes from the
memorable password; the bytes are mapped onto a character set. One character
from each category (upper, lower, digit, symbol) is then forced in, and the
characters are shuffled using more of the derived bytes (still reproducible).

"""



import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import string

# Character categories - no space character, so a password can never start/end with a space
UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"
CHARSET = UPPER + LOWER + DIGITS + SYMBOLS


def derive_strong_password(memorable_password: str, length: int) -> str:
    if not memorable_password:
        raise ValueError("Memorable password cannot be empty.")
    if length < 8:
        raise ValueError("Desired password length must be at least 8 characters.")

    # Constant application salt for deterministic key derivation
    salt = b"COS738-StrongPasswordGenerator-UWC-v1"

    # Derive pseudorandom byte stream using PBKDF2 with SHA-256 (200,000 iterations)
    derived_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        memorable_password.encode("utf-8"),
        salt,
        iterations=200000,
        dklen=length * 2 + 8,  
    )

    # Map derived bytes to characters in the character set
    password_chars = [CHARSET[b % len(CHARSET)] for b in derived_bytes[:length]]

   
    categories = [UPPER, LOWER, DIGITS, SYMBOLS]
    for idx, category in enumerate(categories):
        password_chars[idx] = category[derived_bytes[length + idx] % len(category)]

    for i in range(length - 1, 0, -1):
        j = derived_bytes[length + 4 + (length - 1 - i)] % (i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


class PasswordGeneratorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Strong Password Generator")
        self.root.geometry("560x440")
        self.root.resizable(False, False)

        # Configure modern TTK styles
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Main frame container
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header label
        header_label = ttk.Label(
            main_frame,
            text="Password Generator",
            font=("Helvetica", 14, "bold"),
        )
        header_label.grid(row=0, column=0, columnspan=2, pady=(0, 15))

        # Field 1: Memorable weak password input
        ttk.Label(
            main_frame,
            text="Memorable Weak Password:",
            font=("Helvetica", 10),
        ).grid(row=1, column=0, sticky=tk.W, pady=8)

        self.memorable_password_entry = ttk.Entry(main_frame, width=32, show="*")
        self.memorable_password_entry.grid(row=1, column=1, sticky=tk.W, pady=8)

        # show / hide the memorable password
        self.show_memorable_var = tk.BooleanVar(value=False)
        self.chk_show = ttk.Checkbutton(
            main_frame,
            text="Show memorable password",
            variable=self.show_memorable_var,
            command=self.toggle_memorable_visibility,
        )
        self.chk_show.grid(row=2, column=1, sticky=tk.W)

        # Field 2: Desired length input
        ttk.Label(
            main_frame,
            text="Desired Password Length (min 8):",
            font=("Helvetica", 10),
        ).grid(row=3, column=0, sticky=tk.W, pady=8)

        self.length_entry = ttk.Entry(main_frame, width=12)
        self.length_entry.insert(0, "24")
        self.length_entry.grid(row=3, column=1, sticky=tk.W, pady=8)

        # Action button: Generate strong password
        self.btn_generate = ttk.Button(
            main_frame,
            text="Generate Strong Password",
            command=self.on_generate,
        )
        self.btn_generate.grid(row=4, column=0, columnspan=2, pady=15)

        # Field 3: Output strong password
        ttk.Label(
            main_frame,
            text="Generated Strong Password:",
            font=("Helvetica", 10, "bold"),
        ).grid(row=5, column=0, sticky=tk.W, pady=8)

        self.output_var = tk.StringVar()
        self.entry_output = ttk.Entry(
            main_frame,
            textvariable=self.output_var,
            width=32,
            font=("Consolas", 10, "bold"),
            state="readonly",
        )
        self.entry_output.grid(row=5, column=1, sticky=tk.W, pady=8)

        # Option: include the memorable password in the saved file, off by default
        self.include_memorable_var = tk.BooleanVar(value=False)
        self.chk_include = ttk.Checkbutton(
            main_frame,
            text="Include memorable password in saved file",
            variable=self.include_memorable_var,
        )
        self.chk_include.grid(row=6, column=1, sticky=tk.W)

        # Buttons for copy and save actions
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=15)

        self.btn_copy = ttk.Button(
            button_frame,
            text="Copy to Clipboard",
            command=self.on_copy,
        )
        self.btn_copy.pack(side=tk.LEFT, padx=5)

        self.btn_save = ttk.Button(
            button_frame,
            text="Save Password to File",
            command=self.on_save,
        )
        self.btn_save.pack(side=tk.LEFT, padx=5)

    def toggle_memorable_visibility(self):
        # Show plain text when ticked, mask with asterisks otherwise
        if self.show_memorable_var.get():
            self.memorable_password_entry.config(show="")
        else:
            self.memorable_password_entry.config(show="*")

    def on_generate(self):
        # Handle the password generation
        memorable = self.memorable_password_entry.get().strip()
        length_str = self.length_entry.get().strip()

        if not memorable:
            messagebox.showwarning("Input Error", "Please enter a memorable password.")
            return

        try:
            length = int(length_str)
            strong_pw = derive_strong_password(memorable, length)
            self.output_var.set(strong_pw)
        except ValueError as err:
            messagebox.showerror("Input Error", str(err))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")

    def on_copy(self):
        # Copy password to clipboard
        strong_pw = self.output_var.get()
        if not strong_pw:
            messagebox.showwarning(
                "Copy Error", "No password to copy. Please generate a password first."
            )
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(strong_pw)
        self.root.update()
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def on_save(self):
        # Save the password to a file
        strong_pw = self.output_var.get()
        memorable = self.memorable_password_entry.get().strip()

        if not strong_pw:
            messagebox.showwarning(
                "Save Error", "No password to save. Please generate a password first."
            )
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    if self.include_memorable_var.get():
                        f.write(f"Memorable Weak Password: {memorable}\n")
                    f.write(f"Generated Strong Password: {strong_pw}\n")
                    f.write(f"Password Length: {len(strong_pw)} characters\n")
                messagebox.showinfo("Saved", f"Password saved to {file_path}.")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save password: {str(e)}")


def main():
    root = tk.Tk()
    app = PasswordGeneratorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()