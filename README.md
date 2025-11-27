Secure System Call Interface (SSCI)
🛡️ A Secure Middleware Simulation for Operating System Protection
Project Status: Prototype / Simulation Platform: Windows (Software-Based) Language: Python 3.x

📖 Project Overview
The Secure System Call Interface (SSCI) is a software wrapper designed to sit between the user and the Operating System Kernel. Its primary goal is to prevent unauthorized system access and detect malicious behavioral patterns.

Unlike a standard command line, SSCI intercepts every request (like file creation or process termination), passes it through a Security Logic Engine, and only executes it if the user has the correct Role-Based Access Control (RBAC) permissions and a low Threat Score.

🏗️ Modular Architecture
To ensure separation of concerns and maintainability, the project is divided into three distinct modules:

1. Module A: The Core Logic (security_core.py)
Role: The "Brain" of the system.

Functionality:

Manages the SQLite Database (Users, Logs).

Anomaly Detector: A heuristic engine that analyzes the frequency and type of user actions to calculate a real-time "Threat Score" (0-100).

Syscall Wrapper: The actual interface that sanitizes and executes commands using os and psutil.

2. Module B: The User Interface (gui_app.py)
Role: The Frontend / Visual Layer.

Functionality:

Provides a clean, tabbed interface (Control Panel, Audit Logs, Threat Dashboard).

Prevents direct command-line injection attacks.

Visualizes security data using matplotlib charts.

3. Module C: The Entry Point (main.py)
Role: Application Runner.

Functionality: Initializes the application and launches the GUI.

🚀 Key Features
RBAC (Role-Based Access Control):

Standard Users can view processes and files.

Only Admin users can terminate processes.

Heuristic Anomaly Detection:

The system monitors action frequency. If a user (or script) executes too many commands in <10 seconds, the Threat Score spikes.

Attempts to access sensitive system files (e.g., System32) trigger alerts.

Live Audit Logging:



Every action—successful or blocked—is recorded in a tamper-evident local database (syscall_security.db).

Visual Analytics:



Real-time dashboard showing "Action Distribution" and "Threat Intensity."



SecureSyscallProject/
│
├── main.py              # Entry point
├── gui_app.py           # Frontend (Tkinter)
├── security_core.py     # Backend Logic & Database
├── syscall_security.db  # Auto-generated Log Database
└── README.md            # Documentation