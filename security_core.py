import sqlite3
import hashlib
import secrets
import time
import os
from datetime import datetime

# Try importing psutil, handle gracefully if missing

try:
    import psutil
except ImportError:
    psutil = None

DB_FILE = 'syscall_security.db'

class SecurityDatabase:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self._setup_db()

    def _setup_db(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (username TEXT PRIMARY KEY, hash TEXT, salt TEXT, role TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs 
                     (id INTEGER PRIMARY KEY, timestamp TEXT, username TEXT, 
                      action TEXT, result TEXT, threat_score INTEGER)''')
        self.conn.commit()
        if not self.get_user('admin'):
            self.create_user('admin', 'admin123', 'admin')

    def create_user(self, username, password, role='user'):
        salt = secrets.token_hex(8)
        pwd_hash = self._hash_pwd(password, salt)
        try:
            self.conn.execute('INSERT INTO users VALUES (?,?,?,?)', 
                              (username, pwd_hash, salt, role))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_login(self, username, password):
        user = self.get_user(username)
        if user:
            if self._hash_pwd(password, user[2]) == user[1]:
                return True, user[3]
        return False, None

    def get_user(self, username):
        c = self.conn.cursor()
        c.execute('SELECT * FROM users WHERE username=?', (username,))
        return c.fetchone()

    def log_event(self, username, action, result, threat_score=0):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.conn.execute('INSERT INTO logs (timestamp, username, action, result, threat_score) VALUES (?,?,?,?,?)',
                          (ts, username, action, result, threat_score))
        self.conn.commit()

    def fetch_logs(self):
        c = self.conn.cursor()
        c.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 500')
        return c.fetchall()

    def _hash_pwd(self, password, salt):
        return hashlib.sha256((password + salt).encode()).hexdigest()

class AnomalyDetector:
    def __init__(self):
        self.recent_actions = [] 

    def analyze(self, username, action, role):
        score = 0
        warning = "Normal"
        now = time.time()
        
        self.recent_actions = [x for x in self.recent_actions if now - x[0] < 10]
        self.recent_actions.append((now, username, action))
        
        user_actions = [x for x in self.recent_actions if x[1] == username]

        if len(user_actions) > 5:
            score += 40
            warning = "High Frequency Requests"
        if role != 'admin' and action in ['terminate_process', 'delete_system_file']:
            score += 80
            warning = "Unauthorized Privilege Escalation"
        if 'system32' in str(action).lower():
            score += 50
            warning = "System Directory Access"

        return min(score, 100), warning



class SyscallWrapper:
    def __init__(self, db, detector):
        self.db = db
        self.detector = detector

    def execute(self, username, role, command, **kwargs):
        threat_score, warning = self.detector.analyze(username, command, role)
        
        if threat_score >= 80:
            self.db.log_event(username, command, "BLOCKED", threat_score)
            return False, f"BLOCKED: {warning}"

        result = "Success"
        output = None
        
        try:
            if command == 'list_procs':
                if not psutil: output = "Error: psutil not installed"
                else: output = [f"{p.info['pid']}: {p.info['name']}" for p in psutil.process_iter(['pid', 'name'])]
            elif command == 'terminate_proc':
                if role != 'admin': raise PermissionError("Admin required")
                if not psutil: output = "Error: psutil not installed"
                else: 
                    psutil.Process(int(kwargs.get('pid'))).terminate()
                    output = f"Process {kwargs.get('pid')} terminated."
            elif command == 'read_dir':
                output = os.listdir(kwargs.get('path'))
            elif command == 'create_file':
                with open(kwargs.get('path'), 'w') as f: f.write(kwargs.get('content'))
                output = f"File created at {kwargs.get('path')}"
            else:
                result = "Unknown Command"
        except Exception as e:
            result = f"Error: {str(e)}"
            threat_score += 10

        self.db.log_event(username, command, result, threat_score)
        return (True, output) if result == "Success" else (False, result)