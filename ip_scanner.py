# Testing done via Kali Purple. WinPcap is EOL so not safe to run on PROD system
from tkinter import (Tk, ttk, Label, Entry, Button, Frame, Scrollbar, W, EW, E, Text,
                     DISABLED, Y, BOTH, NORMAL, END, CENTER, NO, filedialog)
from threading import Thread
import scapy.all as scapy
import collections
import tkinter


def start_scan_pressed():
    pass


def stop_scan_pressed():
    pass


thread = None
stop_scan = True
subdomain = ''
source_ip_dict = collections.defaultdict(list)

""" ================= Init GUI & design ================="""
# Window size is set by GUI elements
root = Tk()
root.title('SwissPy - by Sean Scretchen')
root.iconbitmap('snake.ico')

# colors
outline = '#00ee00'  # neon green
background = '#222222'  # black
foreground = '#00ee00'
root.tk_setPalette(background=background,
                   foreground=outline,
                   activeBackground=foreground,
                   activeForeground=background,
                   highlightColor=outline,
                   highlightBackground=outline)

""" ================= Labels ================="""
# Title label
Label(root, text="Wifi Scanner", font=('calibri', 20, 'bold')).grid(row=0, column=1, sticky=W)

# Domain entry Label
Label(root, text='IP domain (ex:172.568.2.0) :', font=('calibri', 16, 'bold')).grid(row=1, column=1, sticky=E, padx=5,
                                                                                    pady=5)
host_entry = Entry(root, font=('calibri', 16))
host_entry.grid(row=1, column=2, sticky=EW, padx=5, pady=5)

# Results label
Label(root, text='Scan Results :', font=('calibri', 16, 'bold')).grid(row=5, column=1, sticky=W, padx=5, pady=5)

""" ================= Treeview ================="""
tree_style = ttk.Style()
tree_style.theme_use("clam")
tree_style.configure("Treeview",
                     background="#222222",
                     foreground="#00ee00",
                     rowheight=25,
                     fieldbackground="#222222"
                     )
tree_style.map('Treeview',
               background=[('selected', 'green')]
               )

tree_frame = ttk.Treeview(root, columns=("c1", "c2"), show='headings')
tree_frame.grid(row=6, column=1, columnspan=2)
tree_frame.column("#1", anchor=tkinter.W, stretch=NO)
tree_frame.column("#2", anchor=tkinter.W, stretch=NO)

tree_frame.heading("#1", text="SRC Host")
tree_frame.heading("#2", text="DST Host")

# Sample data
tree_frame.insert('', 'end', text="1", values=('1.1.1.1', '2.2.2.2'))
tree_frame.insert('', 'end', text="2", values=('3.3.3.3', '4.4.4.4'))

""" ================= Buttons ================="""
# Start scan
Button(root, text='Start Scan', font=('calibri', 12, 'bold'), command=start_scan_pressed).grid(
    row=4, column=2, sticky=W, padx=5, pady=5)

# Stop scan
Button(root, text='Stop Scan', font=('calibri', 12, 'bold'), command=stop_scan_pressed).grid(
    row=4, column=2, sticky=E, padx=5, pady=5)

# Save button // no functionality for now
Button(root, text='Save results', font=('calibri', 12, 'bold')).grid(row=7, column=1, sticky=EW, padx=5, pady=5,
                                                                     columnspan=2)

root.mainloop()
