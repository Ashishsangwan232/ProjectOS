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
