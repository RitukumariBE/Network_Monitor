JINDAL STEEL - NETWORK MONITORING SYSTEM
   Setup & Installation Guide
=====================================================

REQUIREMENTS
------------
- Windows PC connected to the office network
- Internet connection (for first time setup only)
- Python 3.10 or above


STEP 1 - INSTALL PYTHON
------------------------
1. Go to https://www.python.org/downloads/
2. Download and install Python
3. IMPORTANT: During installation, check the box
   "Add Python to PATH"


STEP 2 - COPY PROJECT
----------------------
Copy the entire "network_monitor" folder to this PC
Example location: C:\network_monitor


STEP 3 - INSTALL LIBRARIES
----------------------------
1. Open Command Prompt (Windows + R, type cmd, press Enter)
2. Navigate to project folder:
   cd C:\network_monitor
3. Run this command:
   pip install -r requirements.txt


STEP 4 - RUN THE APP
---------------------
In the same Command Prompt, run:
   python app.py

You will see:
   Scheduler started
   Admin exists
   Ready!
   Running on http://0.0.0.0:5000


STEP 5 - ACCESS DASHBOARD
--------------------------
On the same PC:
   Open browser and go to http://127.0.0.1:5000

On other PCs in the office network:
   First find this PC's IP by running: ipconfig
   Then open browser and go to http://THIS-PC-IP:5000


DEFAULT LOGIN
-------------
   Username : admin
   Password : admin123

IMPORTANT: Change the admin password after first login!


STEP 6 - ADD YOUR DEVICES
--------------------------
Option A - Upload CSV file from dashboard
   Format: ip, device_type, location
   Example: 192.168.1.10, cctv, Gate 1

Option B - Add devices one by one from dashboard
   Go to dashboard and use "Add New Device" form


STEP 7 - EMAIL ALERTS SETUP
-----------------------------
1. Login as admin
2. Click "Email Settings" on dashboard
3. Enter sender Gmail address and App Password
4. All users will receive alerts when a device goes DOWN


FEATURES
--------
- Pings all devices every 10 minutes automatically
- Shows UP / DOWN / UNKNOWN status on dashboard
- Sends email alert when any device goes offline
- Admin can add / delete devices
- Admin can add / delete users
- Upload devices in bulk via CSV file
- Search devices by IP or location


PROJECT FILES
-------------
app.py          - Main application
models.py       - Database tables
ping_engine.py  - Ping logic
monitor.py      - Monitoring engine
email_alerts.py - Email sending
data/devices.csv  - Your devices list
templates/      - Web pages


SUPPORT
-------
Developed by: Ritu Kumari
Internship Project - Jindal Steel & Power
=====================================================