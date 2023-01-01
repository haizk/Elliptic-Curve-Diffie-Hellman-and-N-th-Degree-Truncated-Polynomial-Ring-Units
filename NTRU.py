import time
import tkinter
from tkinter import ttk, filedialog
from NTRUencrypt import NTRUencrypt
from NTRUdecrypt import NTRUdecrypt


class NTRU:
    def __init__(self, master):
        # NTRU Tab Frame
        self.frame = ttk.Frame(master, padding=20)
        self.frame.grid(sticky="NESW")
        self.N1 = NTRUdecrypt()
        self.N2 = NTRUencrypt()

        # PUBLIC KEY
        # Public Key Frame
        self.pub_frame = ttk.LabelFrame(self.frame, text="Public Key", padding=10)
        self.pub_frame.grid(row=0, column=1, padx=10, pady=10)

        # Public Key Text
        self.pub_text = tkinter.Text(self.pub_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.pub_textbar = ttk.Scrollbar(self.pub_frame, command=self.pub_text.yview, orient="vertical")
        self.pub_text.configure(yscrollcommand=self.pub_textbar.set)
        self.pub_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.pub_textbar.grid(row=0, column=2, sticky="NS")

        # Public Key Load Button
        self.pub_load_btn = ttk.Button(self.pub_frame, text="Load", style="Accent.TButton")
        self.pub_load_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Public Key Save Button
        self.pub_save_btn = ttk.Button(self.pub_frame, text="Save", style="Accent.TButton")
        self.pub_save_btn.grid(row=1, column=1, sticky="NESW", padx=10, pady=10)

        # PRIVATE KEY
        # Private Key Frame
        self.pri_frame = ttk.LabelFrame(self.frame, text="Private Key", padding=10)
        self.pri_frame.grid(row=1, column=1, padx=10, pady=10)

        # Private Key Text
        self.pri_text = tkinter.Text(self.pri_frame, wrap=tkinter.WORD, width=30, height=10, font="Consolas")
        self.pri_textbar = ttk.Scrollbar(self.pri_frame, command=self.pri_text.yview, orient="vertical")
        self.pri_text.configure(yscrollcommand=self.pri_textbar.set)
        self.pri_text.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.pri_textbar.grid(row=0, column=2, sticky="NS")

        # Private Key Load Button
        self.pri_load_btn = ttk.Button(self.pri_frame, text="Load", style="Accent.TButton")
        self.pri_load_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Private Key Save Button
        self.pri_save_btn = ttk.Button(self.pri_frame, text="Save", style="Accent.TButton")
        self.pri_save_btn.grid(row=1, column=1, sticky="NESW", padx=10, pady=10)

        # GENERATE KEY
        # Generate Key Frame
        self.gen_frame = ttk.LabelFrame(self.frame, text="Generate Key", padding=10)
        self.gen_frame.grid(row=0, column=0, padx=10, pady=10)

        # Generate Key Clear Button
        self.gen_clear_btn = ttk.Button(self.gen_frame, text="Clear")
        self.gen_clear_btn.grid(row=0, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)
        self.gen_clear_btn.focus_force()

        # Generate Key Button
        self.gen_btn = ttk.Button(self.gen_frame, text="Generate Key", style="Accent.TButton", command=self.gen_key)
        self.gen_btn.grid(row=1, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)

        # Generate Key Parameters
        self.gen_N_label = ttk.Label(self.gen_frame, text="N", justify=tkinter.RIGHT)
        self.gen_N_label.grid(row=2, column=0, sticky="NESW", padx=10, pady=10)
        self.gen_N_var = tkinter.StringVar()
        self.gen_N = ttk.Entry(self.gen_frame, textvariable=self.gen_N_var)
        self.gen_N.grid(row=2, column=1, sticky="NESW", padx=10, pady=10)

        self.gen_p_label = ttk.Label(self.gen_frame, text="p", justify=tkinter.RIGHT)
        self.gen_p_label.grid(row=3, column=0, sticky="NESW", padx=10, pady=10)
        self.gen_p_var = tkinter.StringVar()
        self.gen_p = ttk.Entry(self.gen_frame, textvariable=self.gen_p_var)
        self.gen_p.grid(row=3, column=1, sticky="NESW", padx=10, pady=10)

        self.gen_q_label = ttk.Label(self.gen_frame, text="q", justify=tkinter.RIGHT)
        self.gen_q_label.grid(row=4, column=0, sticky="NESW", padx=10, pady=10)
        self.gen_q_var = tkinter.StringVar()
        self.gen_q = ttk.Entry(self.gen_frame, textvariable=self.gen_q_var)
        self.gen_q.grid(row=4, column=1, sticky="NESW", padx=10, pady=10)

        self.gen_df_label = ttk.Label(self.gen_frame, text="df", justify=tkinter.RIGHT)
        self.gen_df_label.grid(row=5, column=0, sticky="NESW", padx=10, pady=10)
        self.gen_df_var = tkinter.StringVar()
        self.gen_df = ttk.Entry(self.gen_frame, textvariable=self.gen_df_var)
        self.gen_df.grid(row=5, column=1, sticky="NESW", padx=10, pady=10)

        self.gen_dg_label = ttk.Label(self.gen_frame, text="dg", justify=tkinter.RIGHT)
        self.gen_dg_label.grid(row=6, column=0, sticky="NESW", padx=10, pady=10)
        self.gen_dg_var = tkinter.StringVar()
        self.gen_dg = ttk.Entry(self.gen_frame, textvariable=self.gen_dg_var)
        self.gen_dg.grid(row=6, column=1, sticky="NESW", padx=10, pady=10)

        self.gen_d_label = ttk.Label(self.gen_frame, text="d", justify=tkinter.RIGHT)
        self.gen_d_label.grid(row=7, column=0, sticky="NESW", padx=10, pady=10)
        self.gen_d_var = tkinter.StringVar()
        self.gen_d = ttk.Entry(self.gen_frame, textvariable=self.gen_d_var)
        self.gen_d.grid(row=7, column=1, sticky="NESW", padx=10, pady=10)

        # PLAIN TEXT
        # Plain Text Frame
        self.pla_frame = ttk.LabelFrame(self.frame, text="Plain Text", padding=10)
        self.pla_frame.grid(row=0, column=2, padx=10, pady=10)

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
        self.cip_frame.grid(row=1, column=2, padx=10, pady=10)

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
        self.ed_frame.grid(row=1, column=0, padx=10, pady=10)

        # Encrypt Button
        self.ed_e_btn = ttk.Button(self.ed_frame, text="Encrypt", style="Accent.TButton", command=self.encrypt_ntru)
        self.ed_e_btn.grid(row=1, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)

        # Decrypt Button
        self.ed_d_btn = ttk.Button(self.ed_frame, text="Decrypt", style="Accent.TButton", command=self.decrypt_ntru)
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
        self.pri_load_btn.bind("<Button-1>", lambda event, access="private": self.load_key(access))
        self.pub_load_btn.bind("<Button-1>", lambda event, access="public": self.load_key(access))
        self.pri_save_btn.bind("<Button-1>", lambda event, access="private": self.save_key(access))
        self.pub_save_btn.bind("<Button-1>", lambda event, access="public": self.save_key(access))
        # self.pla_load_btn.bind("<Button-1>", lambda event, subject="Plain": self.load_file(subject))
        # self.cip_load_btn.bind("<Button-1>", lambda event, subject="Cipher": self.load_file(subject))
        # self.pla_save_btn.bind("<Button-1>", lambda event, subject="Plain": self.save_file(subject))
        # self.cip_save_btn.bind("<Button-1>", lambda event, subject="Cipher": self.save_file(subject))

    def erase_text(self, subject):
        if subject == "gen":
            self.pri_text.delete("1.0", "end")
            self.pub_text.delete("1.0", "end")
        elif subject == "ed":
            self.pla_text.delete("1.0", "end")
            self.cip_text.delete("1.0", "end")
            self.pla_file_label["text"] = "File : "
            self.cip_file_label["text"] = "File : "
            self.pla_file_byte = None
            self.cip_file_byte = None
        self.alert("Cleared!")

    def load_key(self, access):
        if access == "public":
            public_filename = filedialog.askopenfilename(
                initialdir="/",
                title="Select Public Key File",
                filetypes=[("Public Key", "*.pub")]
            )
            if public_filename != "":
                public_file = open(public_filename, "r")
                public_key = public_file.read()
                public_file.close()
                self.pub_text.delete("1.0", "end")
                self.pub_text.insert("1.0", public_key)
        elif access == "private":
            private_filename = filedialog.askopenfilename(
                initialdir="/",
                title="Select Private Key File",
                filetypes=[("Private Key", "*.pri")]
            )
            if private_filename != "":
                private_file = open(private_filename, "r")
                private_key = private_file.read()
                private_file.close()
                self.pri_text.delete("1.0", "end")
                self.pri_text.insert("1.0", private_key)

    def save_key(self, access):
        if access == "public":
            public_filename = filedialog.asksaveasfilename(
                initialdir="/",
                title="Save Public Key File",
                filetypes=[("Public Key", "*.pub")],
                defaultextension="*.pub"
            )
            if public_filename != "":
                public_file = open(public_filename, "w")
                public_file.write(self.pub_text.get("1.0", "end")[:-1])
                public_file.close()
        elif access == "private":
            private_filename = filedialog.asksaveasfilename(
                initialdir="/",
                title="Save Private Key File",
                filetypes=[("Private Key", "*.pri")],
                defaultextension="*.pri"
            )
            if private_filename != "":
                private_file = open(private_filename, "w")
                private_file.write(self.pri_text.get("1.0", "end")[:-1])
                private_file.close()

    # def load_file(self, subject):
    #     if self.ed_radio_var.get() == "Text":
    #         filename = filedialog.askopenfilename(
    #             initialdir="/",
    #             title="Select " + subject + " File",
    #             filetypes=[("Text File (.txt)", "*.txt")],
    #         )
    #         if filename != "":
    #             file = open(filename, "r")
    #             file_text = file.read()
    #             file.close()
    #             if subject == "Plain":
    #                 self.pla_text.delete("1.0", "end")
    #                 self.pla_text.insert("1.0", file_text)
    #             elif subject == "Cipher":
    #                 self.cip_text.delete("1.0", "end")
    #                 self.cip_text.insert("1.0", file_text)
    #     elif self.ed_radio_var.get() == "File":
    #         filename = filedialog.askopenfilename(
    #             initialdir="/",
    #             title="Select file",
    #             filetypes=[("All files", "*.*")],
    #         )
    #         if filename != "":
    #             input_file = open(filename, "rb")
    #             byteint_array = []
    #             byte = input_file.read(1)
    #             while byte:
    #                 byteint = int.from_bytes(byte, byteorder='little')
    #                 byteint_array.append(byteint)
    #                 byte = input_file.read(1)
    #             input_file.close()
    #             if subject == "Plain":
    #                 self.pla_file_label["text"] = "File : " + filename
    #                 self.pla_file_byte = byteint_array
    #             elif subject == "Cipher":
    #                 self.cip_file_label["text"] = "File : " + filename
    #                 self.cip_file_byte = byteint_array
    #
    # def save_file(self, subject):
    #     if self.ed_radio_var.get() == "Text":
    #         filename = filedialog.asksaveasfilename(
    #             initialdir="/",
    #             title="Save " + subject + " File",
    #             filetypes=[("Text File (.txt)", "*.txt")]
    #         )
    #         if filename != "":
    #             file = open(filename, "w")
    #             if subject == "Plain":
    #                 file.write(self.pla_text.get("1.0", "end")[:-1])
    #             elif subject == "Cipher":
    #                 file.write(self.cip_text.get("1.0", "end")[:-1])
    #             file.close()
    #     elif self.ed_radio_var.get() == "File":
    #         filename = filedialog.asksaveasfilename(
    #             initialdir="/",
    #             title="Select file",
    #             filetypes=[("All files", "*.*")],
    #         )
    #         if filename != "":
    #             output_file = open(filename, "wb")
    #             if subject == "Plain":
    #                 self.pla_file_label["text"] = "File : " + filename
    #                 for byteint in self.pla_file_byte:
    #                     output_file.write(byteint.to_bytes(1, byteorder='little'))
    #             elif subject == "Cipher":
    #                 self.cip_file_label["text"] = "File : " + filename
    #                 for byteint in self.cip_file_byte:
    #                     output_file.write(byteint.to_bytes(1, byteorder='little'))
    #             output_file.close()

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
        # Initialise the private and public keys, write them out (and test reading)
        self.N1 = NTRUdecrypt()
        self.N1.setNpq(N=int(self.gen_N_var.get()), p=int(self.gen_p_var.get()), q=int(self.gen_q_var.get()), df=int(self.gen_df_var.get()), dg=int(self.gen_dg_var.get()), d=int(self.gen_d_var.get()))
        self.N1.genPubPriv()

        # Encrypt a test mesage array
        self.N2 = NTRUencrypt()
        self.N2.readPub()
        self.N2.setM([1, -1, 0, 0, 0, 0, 0, 1, -1])
        self.N2.encrypt()

        self.pub_text.delete("1.0", "end")
        self.pub_text.insert("1.0", str("GENERATED!\nCheck key.pub"))
        self.pri_text.delete("1.0", "end")
        self.pri_text.insert("1.0", str("GENERATED!\nCheck key.pri"))

    def encrypt_ntru(self):
        start_time = time.time()
        self.N2.encryptString(self.pla_text.get("1.0", "end"))
        end_time = time.time()
        self.cip_text.delete("1.0", "end")
        self.cip_text.insert("1.0", self.N2.Me)
        self.alert("Encrypted!\nTime Used: " + str(end_time - start_time))

    def decrypt_ntru(self):
        start_time = time.time()
        self.N1.decryptString(self.N2.Me)
        end_time = time.time()
        self.pla_text.delete("1.0", "end")
        self.pla_text.insert("1.0", self.N1.M)
        self.alert("Decrypted!\nTime Used: " + str(end_time - start_time))
