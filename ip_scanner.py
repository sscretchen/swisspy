# Testing done via Kali Purple. WinPcap is EOL so not safe to run on PROD system
from tkinter import (Tk, ttk, Label, Button, W, EW, CENTER, NO)
from scapy.all import sniff


def start_scan_pressed():
    """
    Init sniff function
    filter by IP traffic
    """
    tree_frame.insert('', 'end', text='[*] Sniffing traffic...')
    sniff(filter='ip', prn=output_to_tree, count=2)


def output_to_tree(packet):
    """
    Take Scapy Sniff function details
    Print out src and dst data in treeview
    """
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    tree_frame.insert('', 'end', text="1", values=(src_ip, dst_ip))


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
Label(root, text="IP Scanner", font=('calibri', 20, 'bold')).grid(row=0, column=1, sticky=W)

# Results label
Label(root, text='Scan Results :', font=('calibri', 16, 'bold')).grid(row=2, column=1, sticky=W, padx=5, pady=5)

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

tree_frame = ttk.Treeview(root, columns=("src", "dst"), show='headings')
tree_frame.grid(row=3, column=1, columnspan=4)
tree_frame.column("src", anchor=CENTER, stretch=NO)
tree_frame.column("dst", anchor=CENTER, stretch=NO)

tree_frame.heading("src", text="SRC Host")
tree_frame.heading("dst", text="DST Host")

""" ================= Buttons ================="""
# Start scan
Button(root, text='Start Scan', font=('calibri', 12, 'bold'), command=start_scan_pressed).grid(
    row=1, column=1, sticky=W, padx=5, pady=5)

root.mainloop()
