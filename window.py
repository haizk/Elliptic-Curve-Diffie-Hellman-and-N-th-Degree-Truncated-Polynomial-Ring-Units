import tkinter
from tkinter import ttk, font
import sv_ttk
import ctypes
from NTRU import *
from ECDH import *


class Window(tkinter.Tk):
    def __init__(self):
        super().__init__()
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        sv_ttk.set_theme("dark")
        self.title("M0521030 Hezkiel Bram Setiawan - UAS Cryptography")

        # Manage Tabs
        self.tab = ttk.Notebook(self)
        self.ecdh = ECDH(self)
        self.ntru = NTRU(self)
        self.tab.add(self.ecdh.frame, text="Elliptic-Curve Diffie-Hellman (ECDH)")
        self.tab.add(self.ntru.frame, text="N-th Degree Truncated Polynomial Ring Units (NTRU)")
        self.tab.pack(expand=True, fill="both")
