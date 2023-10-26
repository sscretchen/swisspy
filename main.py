from threading import Thread
from tkinter import (Tk, Label, Entry, Button, Frame, Scrollbar, W, EW, E, Text,
                     DISABLED, Y, BOTH, NORMAL, END, filedialog)
from datetime import datetime
import tkinter
import socket


class PortScanner:
    stop = False

    def __init__(self, root):
        self.root = root
        self.create_gui()

    def empty_console(self):
        """
        Clear console each time start scan button is clicked
        """
        self.console_text.config(state=NORMAL)
        self.console_text.delete('1.0', END)
        self.console_text.config(state=DISABLED)

    def scan_new_thread(self):
        """
        Capture user args
        Pass to start_scan for the process to start
        This function keeps the start_scan call from blocking tkinter main loop
        """
        url = self.host_entry.get()
        start_port = int(self.start_port_entry.get())
        end_port = int(self.end_port_entry.get())
        thread = Thread(target=self.start_scan,
                        args=(url, start_port, end_port))
        thread.start()

    def start_scan(self, url, start_port, end_port):
        """
        Scan user specified range of ports
        if port open or closed pass to console for printing
        check port range before scanning
        """

        # check that end port entry is not higher than starting port
        if end_port < start_port:
            self.output_to_console(f'[!] End port ({end_port}) cannot be less than start port ({start_port}). '
                                   f'Please enter a valid range')
        else:
            start_time = datetime.now()
            self.output_to_console(f"SCANNING TARGET: {url}\n")
            self.output_to_console(f"SCAN STARTED ON: {start_time.strftime('%A')} "
                                   f"{start_time.strftime('%m-%d-%Y, %H:%M:%S')}\n\n")
            for port in range(start_port, end_port + 1):
                if not self.stop:
                    self.output_to_console(f"Scanning port {port}")
                    if self.is_port_open(url, port):
                        self.output_to_console(f"\t\t[+] open\n")
                    else:
                        self.output_to_console(f"\t\t[-] closed\n")

            finish_time = datetime.now()
            total_time = finish_time - start_time
            self.output_to_console(f"\nSCAN STOPPED AT: {finish_time.strftime('%A')} "
                                   f"{finish_time.strftime('%m-%d-%Y, %H:%M:%S')}\n")
            self.output_to_console(f"TIME ELAPSED: {total_time}")

    def is_port_open(self, url, port):
        """
        Check for an open port using a socket
        return True or False
        pass result back to start_scan
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((socket.gethostbyname(url), port))
            s.close()
            return True
        except:
            return False

    def scan_button_clicked(self):
        """
        Start scan function
        Empty console before printing new results
        Pass users supplied data to new thread function
        """
        self.stop = False  # This fixed the issue of starting new scan. Program could not reach start_scan it seems
        self.empty_console()
        self.scan_new_thread()

    def stop_button_clicked(self):
        """
        Stop scan and trigger the if loop in start_scan to break
        """
        self.stop = True

    def save_scan_results(self):
        """
        Save console window results to .txt file
        """
        fp = tkinter.filedialog.asksaveasfilename(defaultextension=".txt",
                                                  filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if fp:
            with open(fp, 'w') as file:
                text_content = self.console_text.get("1.0", END)
                file.write(text_content)

    def output_to_console(self, new_text):
        """
        Print scan results to console.
        new_text arg is what the start_scan function passes in if a port is open or closed
        """
        self.console_text.config(state=NORMAL)
        self.console_text.insert(END, new_text)
        self.console_text.see(END)  # keep most recent scan in view if results extend past console view
        self.console_text.config(state=DISABLED)

    def create_gui(self):
        """
        initiate the GUI
        Buttons and labels will be created here
        """

        """ ================= Labels ================="""
        # Title label
        Label(root, text="Port Scanner", font=('calibri', 20, 'bold')).grid(row=0, column=1, sticky=W)

        # host entry Label
        Label(root, text='Host :', font=('calibri', 16, 'bold')).grid(row=1, column=1, sticky=E, padx=5, pady=5)
        self.host_entry = Entry(self.root, font=('calibri', 16))
        self.host_entry.insert(0, 'ex: somesite.com / 5.5.5.5')  # Using metasploitable IP
        self.host_entry.grid(row=1, column=2, sticky=EW, padx=5, pady=5)

        # Start port label
        Label(root, text='Start Port :', font=('calibri', 16, 'bold')).grid(row=2, column=1, sticky=E, padx=5, pady=5)
        self.start_port_entry = Entry(root, font=('calibri', 16))
        self.start_port_entry.insert(0, '1')
        self.start_port_entry.grid(row=2, column=2, sticky=EW, padx=5, pady=5)

        # End port label
        Label(root, text='End Port :', font=('calibri', 16, 'bold')).grid(row=3, column=1, sticky=E, padx=5, pady=5)
        self.end_port_entry = Entry(root, font=('calibri', 16))
        self.end_port_entry.insert(0, '150')
        self.end_port_entry.grid(row=3, column=2, sticky=EW, padx=5, pady=5)

        # Results label & Frame
        Label(root, text='Scan Results :', font=('calibri', 16, 'bold')).grid(row=5, column=1, sticky=W, padx=5, pady=5)

        # Frame
        console_frame = Frame(self.root)  # initiate
        console_frame.grid(row=6, column=1, columnspan=2)  # placement

        """ console_text =  text within the frame. State remains disabled until output_to_console call. bd=border"""
        self.console_text = Text(console_frame, fg="green", bg="black", font=('calibri', 14), state=DISABLED, bd=10)

        # -- Scrollbar
        scrollbar = Scrollbar(console_frame, command=self.console_text.yview)
        scrollbar.pack(side="right", fill=Y)  # "tuck" scrollbar to the right of frame
        self.console_text.pack(expand=1, fill=BOTH)
        self.console_text['yscrollcommand'] = scrollbar.set

        """ ================= Buttons ================="""
        # Start scan
        Button(self.root, text='Start Scan', font=('calibri', 12, 'bold'), command=self.scan_button_clicked).grid(
            row=4, column=2, sticky=W, padx=5, pady=5)

        # Stop scan
        Button(self.root, text='Stop Scan', font=('calibri', 12, 'bold'), command=self.stop_button_clicked).grid(
            row=4, column=2, sticky=E, padx=5, pady=5)

        # Save button // no functionality for now
        Button(root, text='Save results', font=('calibri', 12, 'bold'), command=self.save_scan_results).grid(
            row=7, column=1, sticky=EW, padx=5, pady=5, columnspan=2)


""" ================= Init GUI & design ================="""
# Window details. Grid layout in the class sets window size
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

if __name__ == '__main__':
    PortScanner(root)
    root.mainloop()
