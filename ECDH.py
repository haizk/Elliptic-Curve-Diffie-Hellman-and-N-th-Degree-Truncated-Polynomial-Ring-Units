import time
import tkinter
from tkinter import ttk, filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from ECDHtools import *


class ECDH:
    def __init__(self, master):
        # ECDH Tab Frame
        self.frame = ttk.Frame(master, padding=20)
        self.frame.grid(sticky="NESW")

        # Alice (Pengirim)
        # Alice Frame
        self.alice_frame = ttk.LabelFrame(self.frame, text="Alice (Pengirim)", padding=10)
        self.alice_frame.grid(row=0, rowspan=2, column=1, padx=10, pady=10)

        # Alice Diffie Hellman
        self.alice_df = DiffieHellman()
        self.alice_df.diffieHellman = None
        self.alice_df.public_key = None

        # Alice PUBLIC KEY
        # Alice Public Key Frame
        self.alice_pub_frame = ttk.LabelFrame(self.alice_frame, text="Public Key", padding=10)
        self.alice_pub_frame.grid(row=0, column=0, padx=10, pady=10)

        # Alice Public Key Text
        self.alice_pub_text = tkinter.Text(self.alice_pub_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.alice_pub_textbar = ttk.Scrollbar(self.alice_pub_frame, command=self.alice_pub_text.yview, orient="vertical")
        self.alice_pub_text.configure(yscrollcommand=self.alice_pub_textbar.set)
        self.alice_pub_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.alice_pub_textbar.grid(row=0, column=2, sticky="NS")

        # Alice Public Key Load Button
        self.alice_pub_load_btn = ttk.Button(self.alice_pub_frame, text="Load", style="Accent.TButton")
        self.alice_pub_load_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Alice Public Key Save Button
        self.alice_pub_save_btn = ttk.Button(self.alice_pub_frame, text="Save", style="Accent.TButton")
        self.alice_pub_save_btn.grid(row=1, column=1, sticky="NESW", padx=10, pady=10)

        # Alice PRIVATE KEY
        # Alice Private Key Frame
        self.alice_pri_frame = ttk.LabelFrame(self.alice_frame, text="Private Key", padding=10)
        self.alice_pri_frame.grid(row=1, column=0, padx=10, pady=10)

        # Alice Private Key Text
        self.alice_pri_text = tkinter.Text(self.alice_pri_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.alice_pri_textbar = ttk.Scrollbar(self.alice_pri_frame, command=self.alice_pri_text.yview, orient="vertical")
        self.alice_pri_text.configure(yscrollcommand=self.alice_pri_textbar.set)
        self.alice_pri_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.alice_pri_textbar.grid(row=0, column=2, sticky="NS")

        # Alice Private Key Load Button
        self.alice_pri_load_btn = ttk.Button(self.alice_pri_frame, text="Load", style="Accent.TButton")
        self.alice_pri_load_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Alice Private Key Save Button
        self.alice_pri_save_btn = ttk.Button(self.alice_pri_frame, text="Save", style="Accent.TButton")
        self.alice_pri_save_btn.grid(row=1, column=1, sticky="NESW", padx=10, pady=10)

        # Bob (Penerima)
        # Bob Frame
        self.bob_frame = ttk.LabelFrame(self.frame, text="Bob (Penerima)", padding=10)
        self.bob_frame.grid(row=0, rowspan=2, column=2, padx=10, pady=10)

        # Bob Diffie Hellman
        self.bob_df = DiffieHellman()
        self.bob_df.diffieHellman = None
        self.bob_df.public_key = None

        # Bob PUBLIC KEY
        # Bob Public Key Frame
        self.bob_pub_frame = ttk.LabelFrame(self.bob_frame, text="Public Key", padding=10)
        self.bob_pub_frame.grid(row=0, column=0, padx=10, pady=10)

        # Bob Public Key Text
        self.bob_pub_text = tkinter.Text(self.bob_pub_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.bob_pub_textbar = ttk.Scrollbar(self.bob_pub_frame, command=self.bob_pub_text.yview, orient="vertical")
        self.bob_pub_text.configure(yscrollcommand=self.bob_pub_textbar.set)
        self.bob_pub_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.bob_pub_textbar.grid(row=0, column=2, sticky="NS")

        # Bob Public Key Load Button
        self.bob_pub_load_btn = ttk.Button(self.bob_pub_frame, text="Load", style="Accent.TButton")
        self.bob_pub_load_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Bob Public Key Save Button
        self.bob_pub_save_btn = ttk.Button(self.bob_pub_frame, text="Save", style="Accent.TButton")
        self.bob_pub_save_btn.grid(row=1, column=1, sticky="NESW", padx=10, pady=10)

        # Bob PRIVATE KEY
        # Bob Private Key Frame
        self.bob_pri_frame = ttk.LabelFrame(self.bob_frame, text="Private Key", padding=10)
        self.bob_pri_frame.grid(row=1, column=0, padx=10, pady=10)

        # Bob Private Key Text
        self.bob_pri_text = tkinter.Text(self.bob_pri_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.bob_pri_textbar = ttk.Scrollbar(self.bob_pri_frame, command=self.bob_pri_text.yview, orient="vertical")
        self.bob_pri_text.configure(yscrollcommand=self.bob_pri_textbar.set)
        self.bob_pri_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.bob_pri_textbar.grid(row=0, column=2, sticky="NS")

        # Bob Private Key Load Button
        self.bob_pri_load_btn = ttk.Button(self.bob_pri_frame, text="Load", style="Accent.TButton")
        self.bob_pri_load_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Bob Private Key Save Button
        self.bob_pri_save_btn = ttk.Button(self.bob_pri_frame, text="Save", style="Accent.TButton")
        self.bob_pri_save_btn.grid(row=1, column=1, sticky="NESW", padx=10, pady=10)

        # GENERATE KEY
        # Generate Key Frame
        self.gen_frame = ttk.LabelFrame(self.frame, text="Generate Key", padding=10)
        self.gen_frame.grid(row=0, column=0, padx=10, pady=10)

        # Generate Key Combobox
        self.gen_option = ttk.Combobox(self.gen_frame)
        self.gen_option['values'] = ("CHOOSE CURVE", "SECP256R1", "SECP384R1", "SECP521R1", "SECP224R1", "SECP192R1", "SECP256K1", "BrainpoolP256R1", "BrainpoolP384R1", "BrainpoolP512R1", "SECT571K1", "SECT409K1", "SECT283K1", "SECT233K1", "SECT163K1", "SECT571R1", "SECT409R1", "SECT283R1", "SECT233R1", "SECT163R2")
        self.gen_option.current(0)
        self.gen_option.grid(row=2, column=0, sticky="NESW", pady=10)

        # Generate Key Button
        self.gen_btn = ttk.Button(self.gen_frame, text="Generate Key", style="Accent.TButton", command=self.gen_key)
        self.gen_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Generate Key Clear Button
        self.gen_clear_btn = ttk.Button(self.gen_frame, text="Clear")
        self.gen_clear_btn.grid(row=0, column=0, sticky="NESW", padx=10, pady=10)
        self.gen_clear_btn.focus_force()

        # GENERATE SHARED KEY
        # Generate Shared Key Frame
        self.shr_frame = ttk.LabelFrame(self.frame, text="Shared Key", padding=10)
        self.shr_frame.grid(row=1, column=0, padx=10, pady=10)

        # Generate Shared Key Text
        self.shr_text = tkinter.Text(self.shr_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.shr_textbar = ttk.Scrollbar(self.shr_frame, command=self.shr_text.yview, orient="vertical")
        self.shr_text.configure(yscrollcommand=self.shr_textbar.set)
        self.shr_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.shr_textbar.grid(row=0, column=2, sticky="NS")

        # Generate Shared Key Button
        self.shr_btn = ttk.Button(self.shr_frame, text="Generate Shared Key", style="Accent.TButton", command=self.shr_key)
        self.shr_btn.grid(row=1, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)

        # PLAIN TEXT
        # Plain Text Frame
        self.pla_frame = ttk.LabelFrame(self.frame, text="Plain Text", padding=10)
        self.pla_frame.grid(row=0, column=3, padx=10, pady=10)

        # Plain File
        self.pla_file_label = ttk.Label(self.pla_frame, text="File : ", width=35)
        self.pla_file_byte = [0]

        # Plain Text Text
        self.pla_text = tkinter.Text(self.pla_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.pla_textbar = ttk.Scrollbar(self.pla_frame, command=self.pla_text.yview, orient="vertical")
        self.pla_text.configure(yscrollcommand=self.pla_textbar.set)
        self.pla_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.pla_textbar.grid(row=0, column=2, sticky="NS")

        # Plain Text Load Button
        self.pla_load_btn = ttk.Button(self.pla_frame, text="Load", style="Accent.TButton")
        self.pla_load_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Plain Text Save Button
        self.pla_save_btn = ttk.Button(self.pla_frame, text="Save", style="Accent.TButton")
        self.pla_save_btn.grid(row=1, column=1, sticky="NESW", padx=10, pady=10)

        # CIPHER TEXT
        # Cipher Text Frame
        self.cip_frame = ttk.LabelFrame(self.frame, text="Cipher Text", padding=10)
        self.cip_frame.grid(row=1, column=3, padx=10, pady=10)

        # Cipher File
        self.cip_file_label = ttk.Label(self.cip_frame, text="File : ", width=35)
        self.cip_file_byte = [0]

        # Cipher Text Text
        self.cip_text = tkinter.Text(self.cip_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.cip_textbar = ttk.Scrollbar(self.cip_frame, command=self.cip_text.yview, orient="vertical")
        self.cip_text.configure(yscrollcommand=self.cip_textbar.set)
        self.cip_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.cip_textbar.grid(row=0, column=2, sticky="NS")

        # Cipher Text Load Button
        self.cip_load_btn = ttk.Button(self.cip_frame, text="Load", style="Accent.TButton")
        self.cip_load_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Cipher Text Save Button
        self.cip_save_btn = ttk.Button(self.cip_frame, text="Save", style="Accent.TButton")
        self.cip_save_btn.grid(row=1, column=1, sticky="NESW", padx=10, pady=10)

        # ENCRYPT DECRYPT
        # Encrypt Decrypt Frame
        self.ed_frame = ttk.LabelFrame(self.frame, text="Encrypt Decrypt", padding=10)
        self.ed_frame.grid(row=0, rowspan=2, column=4, padx=10, pady=10)

        # Encrypt Button
        self.ed_e_btn = ttk.Button(self.ed_frame, text="Encrypt", style="Accent.TButton", command=self.encrypt_ecdh)
        self.ed_e_btn.grid(row=1, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)

        # Decrypt Button
        self.ed_d_btn = ttk.Button(self.ed_frame, text="Decrypt", style="Accent.TButton", command=self.decrypt_ecdh)
        self.ed_d_btn.grid(row=2, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)

        # Encrypt Decrypt Clear Button
        self.ed_clear_btn = ttk.Button(self.ed_frame, text="Clear")
        self.ed_clear_btn.grid(row=3, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)

        # Encrypt Decrypt Toggle Type
        self.ed_radio_var = tkinter.StringVar(None, "Text")
        self.ed_radio_txt = ttk.Radiobutton(self.ed_frame, text="Text", value="Text", variable=self.ed_radio_var, command=self.toggle_type)
        self.ed_radio_file = ttk.Radiobutton(self.ed_frame, text="File", value="File", variable=self.ed_radio_var, command=self.toggle_type)
        self.ed_radio_txt.grid(row=4, column=0, sticky="NESW", padx=(50, 10), pady=10)
        self.ed_radio_file.grid(row=4, column=1, sticky="NESW", padx=(10, 50), pady=10)

        # Button Bind
        self.gen_clear_btn.bind("<Button-1>", lambda event, subject="gen": self.erase_text(subject))
        self.ed_clear_btn.bind("<Button-1>", lambda event, subject="ed": self.erase_text(subject))
        self.alice_pri_load_btn.bind("<Button-1>", lambda event, access="private", subject="Alice": self.load_key(access, subject))
        self.bob_pri_load_btn.bind("<Button-1>", lambda event, access="private", subject="Bob": self.load_key(access, subject))
        self.alice_pub_load_btn.bind("<Button-1>", lambda event, access="public", subject="Alice": self.load_key(access, subject))
        self.bob_pub_load_btn.bind("<Button-1>", lambda event, access="public", subject="Bob": self.load_key(access, subject))
        self.alice_pri_save_btn.bind("<Button-1>", lambda event, access="private", subject="Alice": self.save_key(access, subject))
        self.bob_pri_save_btn.bind("<Button-1>", lambda event, access="private", subject="Bob": self.save_key(access, subject))
        self.alice_pub_save_btn.bind("<Button-1>", lambda event, access="public", subject="Alice": self.save_key(access, subject))
        self.bob_pub_save_btn.bind("<Button-1>", lambda event, access="public", subject="Bob": self.save_key(access, subject))
        self.pla_load_btn.bind("<Button-1>", lambda event, subject="Plain": self.load_file(subject))
        self.cip_load_btn.bind("<Button-1>", lambda event, subject="Cipher": self.load_file(subject))
        self.pla_save_btn.bind("<Button-1>", lambda event, subject="Plain": self.save_file(subject))
        self.cip_save_btn.bind("<Button-1>", lambda event, subject="Cipher": self.save_file(subject))

    def erase_text(self, subject):
        if subject == "gen":
            self.gen_option.current(0)
            self.shr_text.delete("1.0", "end")
            self.alice_pri_text.delete("1.0", "end")
            self.alice_pub_text.delete("1.0", "end")
            self.bob_pri_text.delete("1.0", "end")
            self.bob_pub_text.delete("1.0", "end")
        elif subject == "ed":
            self.pla_text.delete("1.0", "end")
            self.cip_text.delete("1.0", "end")
            self.pla_file_label["text"] = "File : "
            self.cip_file_label["text"] = "File : "
            self.pla_file_byte = None
            self.cip_file_byte = None
        self.alert("Cleared!")

    def load_key(self, access, subject):
        if access == "public":
            public_filename = filedialog.askopenfilename(
                initialdir="/",
                title="Select " + subject + " Public Key File",
                filetypes=[("Public Key", "*.pub")]
            )
            if public_filename != "":
                public_file = open(public_filename, "r")
                public_key = public_file.read()
                public_file.close()
                if subject == "Alice":
                    self.alice_pub_text.delete("1.0", "end")
                    self.alice_pub_text.insert("1.0", public_key)
                elif subject == "Bob":
                    self.bob_pub_text.delete("1.0", "end")
                    self.bob_pub_text.insert("1.0", public_key)
        elif access == "private":
            private_filename = filedialog.askopenfilename(
                initialdir="/",
                title="Select " + subject + " Private Key File",
                filetypes=[("Private Key", "*.pri")]
            )
            if private_filename != "":
                private_file = open(private_filename, "r")
                private_key = private_file.read()
                private_file.close()
                if subject == "Alice":
                    self.alice_pri_text.delete("1.0", "end")
                    self.alice_pri_text.insert("1.0", private_key)
                elif subject == "Bob":
                    self.bob_pri_text.delete("1.0", "end")
                    self.bob_pri_text.insert("1.0", private_key)

    def save_key(self, access, subject):
        if access == "public":
            public_filename = filedialog.asksaveasfilename(
                initialdir="/",
                title="Save " + subject + " Public Key File",
                filetypes=[("Public Key", "*.pub")],
                defaultextension="*.pub"
            )
            if public_filename != "":
                public_file = open(public_filename, "w")
                if subject == "Alice":
                    public_file.write(self.alice_pub_text.get("1.0", "end")[:-1])
                elif subject == "Bob":
                    public_file.write(self.bob_pub_text.get("1.0", "end")[:-1])
                public_file.close()
        elif access == "private":
            private_filename = filedialog.asksaveasfilename(
                initialdir="/",
                title="Save " + subject + " Private Key File",
                filetypes=[("Private Key", "*.pri")],
                defaultextension="*.pri"
            )
            if private_filename != "":
                private_file = open(private_filename, "w")
                if subject == "Alice":
                    private_file.write(self.alice_pri_text.get("1.0", "end")[:-1])
                elif subject == "Bob":
                    private_file.write(self.bob_pri_text.get("1.0", "end")[:-1])
                private_file.close()

    def load_file(self, subject):
        if self.ed_radio_var.get() == "Text":
            filename = filedialog.askopenfilename(
                initialdir="/",
                title="Select " + subject + " File",
                filetypes=[("Text File (.txt)", "*.txt")],
            )
            if filename != "":
                file = open(filename, "r")
                file_text = file.read()
                file.close()
                if subject == "Plain":
                    self.pla_text.delete("1.0", "end")
                    self.pla_text.insert("1.0", file_text)
                elif subject == "Cipher":
                    self.cip_text.delete("1.0", "end")
                    self.cip_text.insert("1.0", file_text)
        elif self.ed_radio_var.get() == "File":
            filename = filedialog.askopenfilename(
                initialdir="/",
                title="Select  file",
                filetypes=[("All files", "*.*")],
            )
            if filename != "":
                input_file = open(filename, "rb")
                byteint_array = []
                byte = input_file.read(1)
                while byte:
                    byteint = int.from_bytes(byte, byteorder='little')
                    byteint_array.append(byteint)
                    byte = input_file.read(1)
                input_file.close()
                if subject == "Plain":
                    self.pla_file_label["text"] = "File : " + filename
                    self.pla_file_byte = byteint_array
                elif subject == "Cipher":
                    self.cip_file_label["text"] = "File : " + filename
                    self.cip_file_byte = byteint_array

    def save_file(self, subject):
        if self.ed_radio_var.get() == "Text":
            filename = filedialog.asksaveasfilename(
                initialdir="/",
                title="Save " + subject + " File",
                filetypes=[("Text File (.txt)", "*.txt")]
            )
            if filename != "":
                file = open(filename, "w")
                if subject == "Plain":
                    file.write(self.pla_text.get("1.0", "end")[:-1])
                elif subject == "Cipher":
                    file.write(self.cip_text.get("1.0", "end")[:-1])
                file.close()
        elif self.ed_radio_var.get() == "File":
            filename = filedialog.asksaveasfilename(
                initialdir="/",
                title="Select  file",
                filetypes=[("All files", "*.*")],
            )
            if filename != "":
                output_file = open(filename, "wb")
                if subject == "Plain":
                    self.pla_file_label["text"] = "File : " + filename
                    for byteint in self.pla_file_byte:
                        output_file.write(byteint.to_bytes(1, byteorder='little'))
                elif subject == "Cipher":
                    self.cip_file_label["text"] = "File : " + filename
                    for byteint in self.cip_file_byte:
                        output_file.write(byteint.to_bytes(1, byteorder='little'))
                output_file.close()

    def toggle_type(self):
        if self.ed_radio_var.get() == "Text":
            self.pla_file_label.grid_forget()
            self.cip_file_label.grid_forget()
            self.pla_frame.configure(text="Plain Text")
            self.cip_frame.configure(text="Cipher Text")
            self.pla_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
            self.pla_textbar.grid(row=0, column=2, sticky="NS")
            self.cip_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
            self.cip_textbar.grid(row=0, column=2, sticky="NS")
        elif self.ed_radio_var.get() == "File":
            self.pla_frame.configure(text="Plain File")
            self.cip_frame.configure(text="Cipher File")
            self.pla_text.grid_forget()
            self.pla_textbar.grid_forget()
            self.cip_text.grid_forget()
            self.cip_textbar.grid_forget()
            self.pla_file_label.grid(row=0, column=0, columnspan=2, sticky="NESW")
            self.cip_file_label.grid(row=0, column=0, columnspan=2, sticky="NESW")

    def alert(self, txt):
        alert_window = tkinter.Toplevel(self.frame, background="#57C8FF")
        alert_window.title("Alert")
        ttk.Label(master=alert_window, text=txt).pack(padx=120, pady=20)
        ttk.Button(master=alert_window, text="OK", width=10, command=lambda: alert_window.destroy()).pack(pady=10)
        alert_window.grab_set()

    def gen_key(self):
        if self.gen_option.get() != "CHOOSE CURVE":
            self.alice_df = DiffieHellman(self.gen_option.get())
            self.bob_df = DiffieHellman(self.gen_option.get())
            self.alice_pub_text.delete("1.0", "end")
            self.alice_pub_text.insert("1.0", self.alice_df.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            self.alice_pri_text.delete("1.0", "end")
            self.alice_pri_text.insert("1.0", self.alice_df.diffieHellman.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
            self.bob_pub_text.delete("1.0", "end")
            self.bob_pub_text.insert("1.0", self.bob_df.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            self.bob_pri_text.delete("1.0", "end")
            self.bob_pri_text.insert("1.0", self.bob_df.diffieHellman.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        else:
            self.alert("Choose Curve!")

    def shr_key(self):
        try:
            self.alice_df.diffieHellman = load_pem_private_key(bytes(self.alice_pri_text.get("1.0", "end")[:-1], 'utf-8'), password=None)
            self.alice_df.public_key = load_pem_public_key(bytes(self.alice_pub_text.get("1.0", "end")[:-1], 'utf-8'), default_backend())
            self.bob_df.diffieHellman = load_pem_private_key(bytes(self.bob_pri_text.get("1.0", "end")[:-1], 'utf-8'), password=None)
            self.bob_df.public_key = load_pem_public_key(bytes(self.bob_pub_text.get("1.0", "end")[:-1], 'utf-8'), default_backend())
            hexstring = ''
            for byte in self.alice_df.diffieHellman.exchange(ec.ECDH(), self.bob_df.public_key):
                cipher_hex = str(hex(byte))[2:].upper()
                if len(cipher_hex) == 1:
                    cipher_hex = '0' + cipher_hex
                hexstring = hexstring + cipher_hex
            byteint_array = []
            i = 0
            while i < len(hexstring):
                if i == len(hexstring) - 1:
                    byteint_array.append(int(hexstring[i] + "0", 16))
                    i = i + 1
                else:
                    byteint_array.append(int(hexstring[i:i + 2], 16))
                    i = i + 2
            self.shr_text.delete("1.0", "end")
            self.shr_text.insert("1.0", hexstring)
        except ValueError:
            self.alert("Invalid Keys!")

    def get_shr_key(self):
        byteint_array = []
        i = 0
        while i < len(self.shr_text.get("1.0", "end")[:-1]):
            if i == len(self.shr_text.get("1.0", "end")[:-1]) - 1:
                byteint_array.append(int(self.shr_text.get("1.0", "end")[:-1][i] + "0", 16))
                i = i + 1
            else:
                byteint_array.append(int(self.shr_text.get("1.0", "end")[:-1][i:i + 2], 16))
                i = i + 2
        return bytes(byteint_array)

    def encrypt_ecdh(self):
        try:
            self.alice_df.diffieHellman = load_pem_private_key(bytes(self.alice_pri_text.get("1.0", "end")[:-1], 'utf-8'), password=None)
            self.alice_df.public_key = load_pem_public_key(bytes(self.alice_pub_text.get("1.0", "end")[:-1], 'utf-8'), default_backend())
            self.bob_df.diffieHellman = load_pem_private_key(bytes(self.bob_pri_text.get("1.0", "end")[:-1], 'utf-8'), password=None)
            self.bob_df.public_key = load_pem_public_key(bytes(self.bob_pub_text.get("1.0", "end")[:-1], 'utf-8'), default_backend())
            if self.get_shr_key() != self.alice_df.diffieHellman.exchange(ec.ECDH(), self.bob_df.public_key):
                raise AttributeError("Invalid Shared Key!")
            start_time = time.time()
            if self.ed_radio_var.get() == "Text":
                encrypted_message = self.alice_df.encrypt(self.bob_df.public_key, self.pla_text.get("1.0", "end")[:-1])
                hexstring = ""
                for byte in encrypted_message:
                    cipher_hex = str(hex(byte))[2:].upper()
                    if len(cipher_hex) == 1:
                        cipher_hex = '0' + cipher_hex
                    hexstring = hexstring + cipher_hex
                self.cip_text.delete("1.0", "end")
                self.cip_text.insert("1.0", hexstring)
            elif self.ed_radio_var.get() == "File":
                hexstring = ""
                for byteint in self.pla_file_byte:
                    hexstring = hexstring + (format(byteint, 'x') if len(format(byteint, 'x')) == 2 else "0" + format(byteint, 'x'))
                encrypted_message = self.alice_df.encrypt(self.bob_df.public_key, hexstring)
                self.cip_file_byte = encrypted_message
                self.cip_file_label["text"] = "ENCRYPTED!"
            end_time = time.time()
            self.alert("Encrypted!\nTime Used: " + str((end_time - start_time)) + " seconds.")
        except AttributeError:
            self.alert("Invalid Shared Key!")
        except ValueError:
            self.alert("Invalid Public Keys or Private Keys!")

    def decrypt_ecdh(self):
        try:
            self.alice_df.diffieHellman = load_pem_private_key(bytes(self.alice_pri_text.get("1.0", "end")[:-1], 'utf-8'), password=None)
            self.alice_df.public_key = load_pem_public_key(bytes(self.alice_pub_text.get("1.0", "end")[:-1], 'utf-8'), default_backend())
            self.bob_df.diffieHellman = load_pem_private_key(bytes(self.bob_pri_text.get("1.0", "end")[:-1], 'utf-8'), password=None)
            self.bob_df.public_key = load_pem_public_key(bytes(self.bob_pub_text.get("1.0", "end")[:-1], 'utf-8'), default_backend())
            if self.get_shr_key() != self.bob_df.diffieHellman.exchange(ec.ECDH(), self.alice_df.public_key):
                raise AttributeError("Invalid Shared Key!")
            start_time = time.time()
            if self.ed_radio_var.get() == "Text":
                encrypted_message = self.cip_text.get("1.0", "end")[:-1]
                byteint_array = []
                i = 0
                while i < len(encrypted_message):
                    if i == len(encrypted_message) - 1:
                        byteint_array.append(int(encrypted_message[i] + "0", 16))
                        i = i + 1
                    else:
                        byteint_array.append(int(encrypted_message[i:i + 2], 16))
                        i = i + 2
                decrypted_message = self.bob_df.decrypt(self.alice_df.public_key, bytes(byteint_array), self.alice_df.IV)
                self.pla_text.delete("1.0", "end")
                self.pla_text.insert("1.0", decrypted_message)
            elif self.ed_radio_var.get() == "File":
                decrypted_message = self.bob_df.decrypt(self.alice_df.public_key, bytes(self.cip_file_byte), self.alice_df.IV).decode()
                byteint_array = []
                i = 0
                while i < len(decrypted_message):
                    if i == len(decrypted_message) - 1:
                        byteint_array.append(int(decrypted_message[i] + "0", 16))
                        i = i + 1
                    else:
                        byteint_array.append(int(decrypted_message[i:i + 2], 16))
                        i = i + 2
                self.pla_file_byte = byteint_array
                self.pla_file_label["text"] = "DECRYPTED!"
            end_time = time.time()
            self.alert("Decrypted!\nTime Used: " + str((end_time - start_time)) + " seconds.")
        except AttributeError:
            self.alert("Invalid Shared Key!")
        except ValueError:
            self.alert("Invalid Public Keys or Private Keys!")

# Hello future me :) Maaf ga ada komen penjelasan, semoga masih bisa paham. Iya kamu ngoding ini :v Semangat terus!
