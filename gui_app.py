import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from datetime import datetime
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

from collections import Counter
# Import Logic Module
import security_core
class StandardApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Secure System Call Interface")
        self.geometry("900x600")
        
        # Connect to Module 1 (Logic)
        self.db = security_core.SecurityDatabase()
        self.detector = security_core.AnomalyDetector()
        self.sys = security_core.SyscallWrapper(self.db, self.detector)
        
        self.current_user = None
        self.current_role = None
        
        self.show_login()

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    # --- LOGIN SCREEN ---
    def show_login(self):
        self.clear_window()
        
        # Center frame
        frame = ttk.Frame(self, padding=20)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="System Login", font=("Segoe UI", 16, "bold")).pack(pady=10)
        
        ttk.Label(frame, text="Username:").pack(anchor="w")
        self.entry_user = ttk.Entry(frame, width=30)
        self.entry_user.pack(pady=5)
        
        ttk.Label(frame, text="Password:").pack(anchor="w")
        self.entry_pass = ttk.Entry(frame, width=30, show="*")
        self.entry_pass.pack(pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=15)
        
        ttk.Button(btn_frame, text="Login", command=self.do_login).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Register", command=self.do_register).pack(side="left", padx=5)

    def do_login(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()
        success, role = self.db.verify_login(u, p)
        if success:
            self.current_user = u
            self.current_role = role
            self.show_main_interface()
        else:
            messagebox.showerror("Error", "Invalid Credentials")

    def do_register(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()
        if self.db.create_user(u, p):
            messagebox.showinfo("Success", "User Registered. Please Login.")
        else:
            messagebox.showerror("Error", "Username already exists.")

    # --- MAIN INTERFACE ---
    def show_main_interface(self):
        self.clear_window()
        
        # Top Info Bar
        top_bar = ttk.Frame(self, padding=5)
        top_bar.pack(fill="x")
        ttk.Label(top_bar, text=f"Logged in as: {self.current_user} ({self.current_role.upper()})", 
                  font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(top_bar, text="Logout", command=self.show_login).pack(side="right")

        # Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_ops = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)
        self.tab_viz = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_ops, text="Control Panel")
        self.notebook.add(self.tab_logs, text="Audit Logs")
        self.notebook.add(self.tab_viz, text="Threat Dashboard")

        self.build_ops_tab()
        self.build_logs_tab()
        self.build_viz_tab()

    # --- TAB 1: CONTROL PANEL ---
    def build_ops_tab(self):
        # Action Buttons
        frame = ttk.LabelFrame(self.tab_ops, text="System Calls", padding=10)
        frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(frame, text="List Processes", command=lambda: self.run_syscall('list_procs')).pack(side="left", padx=5)
        ttk.Button(frame, text="Read Directory", command=self.ask_read_dir).pack(side="left", padx=5)
        ttk.Button(frame, text="Create File", command=self.ask_create_file).pack(side="left", padx=5)
        

        
        # Admin Button
        state = "normal" if self.current_role == "admin" else "disabled"
        ttk.Button(frame, text="Terminate Process (Admin)", state=state, command=self.ask_terminate).pack(side="left", padx=5)
        
        # Simulation Button (Crucial for Demo)
        ttk.Button(frame, text="⚠️ Simulate Attack", command=self.simulate_attack).pack(side="right", padx=5)

        # Output Log
        lbl = ttk.Label(self.tab_ops, text="Live Kernel Output:")
        lbl.pack(anchor="w", padx=10)
        
        self.console = tk.Text(self.tab_ops, height=15)
        self.console.pack(fill="both", expand=True, padx=10, pady=5)

    def run_syscall(self, cmd, **kwargs):
        success, output = self.sys.execute(self.current_user, self.current_role, cmd, **kwargs)
        ts = datetime.now().strftime('%H:%M:%S')
        tag = "SUCCESS" if success else "BLOCKED"
        
        self.console.insert("end", f"[{ts}] [{tag}] {output}\n")
        self.console.see("end")
        
        # Refresh other tabs if they exist
        self.refresh_logs()

    def simulate_attack(self):
        for _ in range(8):
            self.run_syscall('list_procs')
            self.update()

    def ask_read_dir(self):
        path = filedialog.askdirectory()
        if path: self.run_syscall('read_dir', path=path)

    def ask_create_file(self):
        path = filedialog.asksaveasfilename()
        if path:
            content = simpledialog.askstring("File Content", "Enter text:")
            self.run_syscall('create_file', path=path, content=content or "")

    def ask_terminate(self):
        pid = simpledialog.askinteger("Terminate", "Enter PID:")
        if pid: self.run_syscall('terminate_proc', pid=pid)

    # --- TAB 2: LOGS ---
    def build_logs_tab(self):
        # Refresh Button
        ttk.Button(self.tab_logs, text="Refresh Data", command=self.refresh_logs).pack(pady=5)

        cols = ('ID', 'Time', 'User', 'Action', 'Result', 'Threat')
        self.tree = ttk.Treeview(self.tab_logs, columns=cols, show='headings')
        
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=100)
        
        self.tree.pack(fill='both', expand=True, padx=10, pady=5)
        self.refresh_logs()

    def refresh_logs(self):
        # Clear tree
        if hasattr(self, 'tree'):
            for row in self.tree.get_children():
                self.tree.delete(row)
            # Fetch from DB
            for row in self.db.fetch_logs():
                self.tree.insert("", "end", values=row)

    # --- TAB 3: VISUALIZATION ---
    def build_viz_tab(self):
        ttk.Button(self.tab_viz, text="Generate/Refresh Charts", command=self.draw_charts).pack(pady=5)
        
        self.chart_frame = ttk.Frame(self.tab_viz)
        self.chart_frame.pack(fill='both', expand=True, padx=10, pady=5)

    def draw_charts(self):
        for widget in self.chart_frame.winfo_children():
            widget.destroy()


        logs = self.db.fetch_logs()
        if not logs: return

        actions = [x[3] for x in logs]
        threats = [x[5] for x in logs if x[5] > 0]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        
        # 1. Actions
        counts = Counter(actions)
        ax1.pie(counts.values(), labels=counts.keys(), autopct='%1.1f%%')
        ax1.set_title("System Call Types")

        # 2. Threats
        if threats:
            ax2.hist(threats, color='red', bins=5)
            ax2.set_title("Threat Score Distribution")
        else:
            ax2.text(0.5, 0.5, "No Threats Detected", ha='center')

        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)