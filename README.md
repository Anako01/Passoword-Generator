# Files
- password_gen.py - the Python GUI (Tkinter).
- PasswordGeneratorGUI.java - the Java (Swing) translation.
- password_generator.html - the HTML/JavaScript translation.


# How to run
- Python (Python 3 with Tkinter):
   ```bash
   python password_gen.py
    ```
- Java (JDK 11 or later):
   ```bash
   javac PasswordGeneratorGUI.java
   java PasswordGeneratorGUI
    ```


- HTML: double-click password_generator.html to open it in a web browser. 

# How it works
PBKDF2-HMAC-SHA256 (fixed salt, 200,000 iterations) turns the memorable password into bytes. Each byte selects a character from 88 letters, digits and symbols; one character from each of the four groups is guaranteed, and the result is shuffled using the same bytes. Example (identical in all three programs): anako123 with length 10 gives xh*{a*H8C<.
The strong password is only as unpredictable as the memorable password, so use a long one. Testing and limitations are in the analysis document.
