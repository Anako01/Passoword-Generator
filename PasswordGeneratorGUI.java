/**
 *
 *Translates the Python Tkinter implementation into Java Swing.
 *Converts a memorable weak password into a cryptographically strong, deterministic password using PBKDF2-HMAC-SHA256 key derivation.
 */


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


public class PasswordGeneratorGUI extends JFrame {

    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    // No space character, so a password can never start/end with a space
    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?";
    private static final String CHARSET = UPPER + LOWER + DIGITS + SYMBOLS;

    private JPasswordField txtMemorable;
    private JTextField txtLength;
    private JTextField txtOutput;
    private JCheckBox chkShowMemorable;
    private JCheckBox chkIncludeMemorable;
    private char defaultEchoChar;

    public PasswordGeneratorGUI() {
        setTitle("Strong Password Generator (Java)");
        setSize(540, 440);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(false);
        initUI();
    }

    private void initUI() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridBagLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Title Header
        JLabel lblHeader = new JLabel(" Password Generator App", JLabel.CENTER);
        lblHeader.setFont(new Font("SansSerif", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        mainPanel.add(lblHeader, gbc);
        gbc.gridwidth = 1;

        // Field 1: Memorable Password
        JLabel lblMemorable = new JLabel("Memorable Weak Password:");
        gbc.gridx = 0;
        gbc.gridy = 1;
        mainPanel.add(lblMemorable, gbc);

        txtMemorable = new JPasswordField(20);
        defaultEchoChar = txtMemorable.getEchoChar();
        gbc.gridx = 1;
        gbc.gridy = 1;
        mainPanel.add(txtMemorable, gbc);

        // Option: show / hide the memorable password
        chkShowMemorable = new JCheckBox("Show memorable password");
        chkShowMemorable.addActionListener(e -> toggleMemorableVisibility());
        gbc.gridx = 1;
        gbc.gridy = 2;
        mainPanel.add(chkShowMemorable, gbc);

        // Field 2: Output Length
        JLabel lblLength = new JLabel("Desired Password Length:");
        gbc.gridx = 0;
        gbc.gridy = 3;
        mainPanel.add(lblLength, gbc);

        txtLength = new JTextField("24", 10);
        gbc.gridx = 1;
        gbc.gridy = 3;
        mainPanel.add(txtLength, gbc);

        // Action Button: Generate
        JButton btnGenerate = new JButton("Generate Strong Password");
        btnGenerate.setFont(new Font("SansSerif", Font.BOLD, 12));
        btnGenerate.addActionListener(e -> generatePassword());
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        mainPanel.add(btnGenerate, gbc);
        gbc.gridwidth = 1;

        // Field 3: Output Password
        JLabel lblOutput = new JLabel("Generated Strong Password:");
        lblOutput.setFont(new Font("SansSerif", Font.BOLD, 12));
        gbc.gridx = 0;
        gbc.gridy = 5;
        mainPanel.add(lblOutput, gbc);

        txtOutput = new JTextField(20);
        txtOutput.setFont(new Font("Monospaced", Font.BOLD, 12));
        txtOutput.setEditable(false);
        gbc.gridx = 1;
        gbc.gridy = 5;
        mainPanel.add(txtOutput, gbc);

        // include the memorable password in the saved file (off by default)
        chkIncludeMemorable = new JCheckBox("Include memorable password in saved file");
        gbc.gridx = 1;
        gbc.gridy = 6;
        mainPanel.add(chkIncludeMemorable, gbc);

        // Button Panel: Copy & Save
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));

        JButton btnCopy = new JButton("Copy to Clipboard");
        btnCopy.addActionListener(e -> copyToClipboard());
        buttonPanel.add(btnCopy);

        JButton btnSave = new JButton("Save Password to File");
        btnSave.addActionListener(e -> saveToFile());
        buttonPanel.add(btnSave);

        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.gridwidth = 2;
        mainPanel.add(buttonPanel, gbc);

        add(mainPanel);
    }

    private void toggleMemorableVisibility() {
        // 0 echo char = show plain text; default echo char = masked
        if (chkShowMemorable.isSelected()) {
            txtMemorable.setEchoChar((char) 0);
        } else {
            txtMemorable.setEchoChar(defaultEchoChar);
        }
    }

    private void generatePassword() {
        String memorable = new String(txtMemorable.getPassword()).trim();
        String lengthStr = txtLength.getText().trim();

        if (memorable.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a memorable password.",
                    "Input Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            int length = Integer.parseInt(lengthStr);
            if (length < 8) {
                JOptionPane.showMessageDialog(this,
                        "Desired password length must be at least 8 characters.",
                        "Input Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String derivedPw = deriveStrongPassword(memorable, length);
            txtOutput.setText(derivedPw);
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Length must be a valid integer number.",
                    "Input Error", JOptionPane.ERROR_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error deriving password: " + ex.getMessage(),
                    "System Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String deriveStrongPassword(String memorablePassword, int length)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = "StrongPasswordGenerator".getBytes(StandardCharsets.UTF_8);
        // bytes needed: mapping (length) + forcing (4) + shuffling (length - 1) -> length * 2 + 8
        int bitLength = (length * 2 + 8) * 8;

        PBEKeySpec spec = new PBEKeySpec(memorablePassword.toCharArray(), salt, 200000, bitLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derivedBytes = skf.generateSecret(spec).getEncoded();

        char[] pwChars = new char[length];
        for (int i = 0; i < length; i++) {
            int b = derivedBytes[i] & 0xFF;
            pwChars[i] = CHARSET.charAt(b % CHARSET.length());
        }

        
        String[] categories = {UPPER, LOWER, DIGITS, SYMBOLS};
        for (int catIdx = 0; catIdx < categories.length; catIdx++) {
            String cat = categories[catIdx];
            int b = derivedBytes[length + catIdx] & 0xFF;
            pwChars[catIdx] = cat.charAt(b % cat.length());
        }

        
        for (int i = length - 1; i > 0; i--) {
            int j = (derivedBytes[length + 4 + (length - 1 - i)] & 0xFF) % (i + 1);
            char tmp = pwChars[i];
            pwChars[i] = pwChars[j];
            pwChars[j] = tmp;
        }

        return new String(pwChars);
    }

    private void copyToClipboard() {
        String pw = txtOutput.getText();
        if (pw.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No password available to copy.",
                    "Copy Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }
        StringSelection selection = new StringSelection(pw);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
        JOptionPane.showMessageDialog(this, "Strong password copied to clipboard.",
                "Clipboard Success", JOptionPane.INFORMATION_MESSAGE);
    }

    private void saveToFile() {
        String pw = txtOutput.getText();
        String memorable = new String(txtMemorable.getPassword()).trim();

        if (pw.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No password available to save.",
                    "Save Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save Password Output");
        fileChooser.setSelectedFile(new File("strong_password.txt"));

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File targetFile = fileChooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(targetFile, StandardCharsets.UTF_8)) {
                writer.write("=== Cyber Security - Strong Password Output (Java) ===\n");
                if (chkIncludeMemorable.isSelected()) {
                    writer.write("Memorable Weak Password: " + memorable + "\n");
                }
                writer.write("Generated Strong Password: " + pw + "\n");
                writer.write("Password Length: " + pw.length() + " characters\n");
                JOptionPane.showMessageDialog(this,
                        "Password saved successfully to " + targetFile.getName(),
                        "Save Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Failed to save file: " + ex.getMessage(),
                        "Save Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {
            }
            new PasswordGeneratorGUI().setVisible(true);
        });
    }
}
