import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
import threading
import collections


def start_button():
    global thread
    global should_we_stop
    global subdomain

    print('Start button clicked')
    subdomain_entry.get()

    if (thread is None) or (not thread.is_alive()):
        should_we_stop = False
        thread = threading.Thread(target=sniffing)
        thread.start()


def stop_button():
    global should_we_stop
    should_we_stop = True


def sniffing():
    scapy.sniff(prn=find_ips, stop_filter=stop_sniffing)


def stop_sniffing(packet):
    global should_we_stop
    return should_we_stop


def find_ips(packet):
    global thread
    global should_we_stop
    global subdomain

    print(packet.show())

    if 'IP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst

        if src_ip[0:len(subdomain)] == subdomain:
            if src_ip not in src_ip_dict:
                src_ip_dict[src_ip].append(dst_ip)

                row = treev.insert('', index=tk.END, text=src_ip)
                treev.insert(row, tk.END, text=dst_ip)
                treev.pack(fill=tk.X)
            else:
                if dst_ip not in src_ip_dict[src_ip]:
                    src_ip_dict[src_ip].append(dst_ip)

                    cur_item = treev.focus()

                    # This could be where I move the dstIP to the second col 'if cur_item is src'
                    if treev.item(cur_item)['text'] == src_ip:
                        treev.insert(cur_item, tk.END, text=dst_ip)


thread = None
should_we_stop = True
subdomain = ''

src_ip_dict = collections.defaultdict(list)

root = tk.Tk()
root.geometry('500x500')
root.title('IP Scanner w\' Threading')

tk.Label(root, text='IP Scanner', font='calibri 20 bold').pack()
tk.Label(root, text='Enter IP domain', font='calibri 16 bold').pack()

subdomain_entry = tk.Entry(root)
subdomain_entry.pack(ipady=5, ipadx=50, pady=10)

treev = ttk.Treeview(root, height=400)
button_frame = tk.Frame(root)

tk.Button(button_frame, text='Start', command=start_button, width=15, font='calibri 14 bold').pack(side=tk.LEFT)
tk.Button(button_frame, text='Stop', command=stop_button, width=15, font='calibri 14 bold').pack(side=tk.LEFT)

button_frame.pack(side=tk.BOTTOM, pady=10)

""" ================= Init GUI & design ================="""
# Window details. Grid layout in the class sets window size
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

root.mainloop()
