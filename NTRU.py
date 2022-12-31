import tkinter
from tkinter import ttk
from NTRUlib import *


class NTRU:
    def __init__(self, master):
        # NTRU Tab Frame
        self.frame = ttk.Frame(master, padding=20)
        self.frame.grid(sticky="NESW")

        # PUBLIC KEY
        # Public Key Frame
        self.pub_frame = ttk.LabelFrame(self.frame, text="Public Key", padding=10)
        self.pub_frame.grid(row=0, column=0, padx=10, pady=10)

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
        self.pri_frame.grid(row=0, column=1, padx=10, pady=10)

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
        self.gen_frame.grid(row=0, column=2, padx=10, pady=10)

        # Generate Key p
        self.gen_p = ttk.Label(self.gen_frame, text="p", padding=(0, 10, 0, 10), anchor="center")
        self.gen_p.grid(row=0, column=0, sticky="NESW", pady=10)
        self.gen_p_text = ttk.Entry(self.gen_frame, width=10)
        self.gen_p_text.grid(row=0, column=1, sticky="NESW", pady=10)

        # Generate Key q
        self.gen_q = ttk.Label(self.gen_frame, text="q", padding=(0, 10, 0, 10), anchor="center")
        self.gen_q.grid(row=1, column=0, sticky="NESW", pady=10)
        self.gen_q_text = ttk.Entry(self.gen_frame, width=10)
        self.gen_q_text.grid(row=1, column=1, sticky="NESW", pady=10)

        # Generate Key df
        self.gen_df = ttk.Label(self.gen_frame, text="df", padding=(0, 10, 0, 10), anchor="center")
        self.gen_df.grid(row=2, column=0, sticky="NESW", pady=10)
        self.gen_df_text = ttk.Entry(self.gen_frame, width=10)
        self.gen_df_text.grid(row=2, column=1, sticky="NESW", pady=10)

        # Generate Key Text
        self.gen_var = tkinter.StringVar()
        self.gen_text = ttk.Label(self.gen_frame, width=30, textvariable=self.gen_var, anchor="center")
        self.gen_text.grid(row=3, column=0, columnspan=2, sticky="NESW", pady=10)

        # Generate Key Button
        self.gen_btn = ttk.Button(self.gen_frame, text="Generate Key", style="Accent.TButton")
        self.gen_btn.grid(row=4, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)

        # Generate Key Clear Button
        self.gen_clear_btn = ttk.Button(self.gen_frame, text="Clear")
        self.gen_clear_btn.grid(row=5, column=0, columnspan=2, sticky="NESW", padx=10, pady=10)
        self.gen_clear_btn.focus_force()

        # PLAIN TEXT
        # Plain Text Frame
        self.pla_frame = ttk.LabelFrame(self.frame, text="Plain Text", padding=10)
        self.pla_frame.grid(row=1, column=0, padx=10, pady=10)

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
        self.cip_frame.grid(row=1, column=1, padx=10, pady=10)

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
        self.ed_frame.grid(row=1, column=2, padx=10, pady=10)

        # Encrypt Decrypt Text
        self.ed_var = tkinter.StringVar()
        self.ed_text = ttk.Label(self.ed_frame, width=30, textvariable=self.ed_var, anchor="center")
        self.ed_text.grid(row=0, column=0, sticky="NESW", pady=10)

        # Encrypt Button
        self.ed_e_btn = ttk.Button(self.ed_frame, text="Encrypt", style="Accent.TButton")
        self.ed_e_btn.grid(row=1, column=0, sticky="NESW", padx=10, pady=10)

        # Decrypt Button
        self.ed_d_btn = ttk.Button(self.ed_frame, text="Decrypt", style="Accent.TButton")
        self.ed_d_btn.grid(row=2, column=0, sticky="NESW", padx=10, pady=10)

        # Encrypt Decrypt Clear Button
        self.ed_clear_btn = ttk.Button(self.ed_frame, text="Clear")
        self.ed_clear_btn.grid(row=3, column=0, sticky="NESW", padx=10, pady=10)

        # Button Bind
        self.gen_clear_btn.bind("<Button-1>", lambda event, subject="gen": self.erase_text(subject))
        self.ed_clear_btn.bind("<Button-1>", lambda event, subject="ed": self.erase_text(subject))

    def erase_text(self, subject):
        if subject == "gen":
            self.gen_p_text.delete(0, tkinter.END)
            self.gen_q_text.delete(0, tkinter.END)
            self.gen_df_text.delete(0, tkinter.END)
            self.pub_text.delete("1.0", "end")
            self.pri_text.delete("1.0", "end")
            self.gen_var.set("")
        elif subject == "ed":
            self.pla_text.delete("1.0", "end")
            self.cip_text.delete("1.0", "end")
            self.ed_var.set("")
