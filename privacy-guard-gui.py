#!/usr/bin/env python3
"""
Windows Privacy Guard - GUI Version
A modern, user-friendly interface for Windows privacy protection
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import json
import os
import sys
from pathlib import Path
import threading
import time

class PrivacyGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Privacy Guard")
        self.root.geometry("1000x800")
        self.root.configure(bg='#2b2b2b')
        self.root.minsize(800, 600)
        
        # Add window icon and properties
        try:
            self.root.iconbitmap(default="privacy.ico")
        except:
            pass  # Icon file not found, continue without it
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        # Variables
        self.config_file = Path.home() / '.privacy-guard' / 'config.json'
        self.log_file = Path.home() / '.privacy-guard' / 'privacy-guard.log'
        self.script_path = Path(__file__).parent / 'privacy-guard.ps1'
        self.backup_dir = Path.home() / '.privacy-guard' / 'backups'
        
        # State variables
        self.is_scanning = False
        self.is_applying = False
        self.last_scan_time = None
        self.privacy_score = 0
        
        # Create main interface
        self.create_widgets()
        self.load_config()
        
        # Auto-scan privacy status on startup
        self.root.after(1000, self.auto_scan_privacy)
        
    def configure_styles(self):
        """Configure the visual styles for modern dark theme"""
        # Configure the main theme
        self.style.theme_use('clam')
        
        # Color scheme
        self.colors = {
            'bg_primary': '#1e1e1e',
            'bg_secondary': '#2d2d2d', 
            'bg_tertiary': '#3c3c3c',
            'accent': '#0078d4',
            'accent_hover': '#106ebe',
            'success': '#107c10',
            'warning': '#ff8c00',
            'error': '#d13438',
            'text_primary': '#ffffff',
            'text_secondary': '#cccccc',
            'text_muted': '#999999',
            'border': '#404040'
        }
        
        # Configure styles
        self.style.configure('Title.TLabel', 
                           font=('Segoe UI', 18, 'bold'),
                           foreground=self.colors['text_primary'],
                           background=self.colors['bg_primary'])
        
        self.style.configure('Header.TLabel',
                           font=('Segoe UI', 12, 'bold'),
                           foreground=self.colors['accent'],
                           background=self.colors['bg_primary'])
        
        self.style.configure('Custom.TCheckbutton',
                           font=('Segoe UI', 10),
                           foreground=self.colors['text_primary'],
                           background=self.colors['bg_primary'],
                           focuscolor='none',
                           selectcolor=self.colors['accent'])
        
        self.style.configure('Custom.TButton',
                           font=('Segoe UI', 10, 'bold'),
                           padding=(12, 8),
                           background=self.colors['accent'],
                           foreground=self.colors['text_primary'])
        
        self.style.map('Custom.TButton',
                      background=[('active', self.colors['accent_hover']),
                                ('pressed', self.colors['accent_hover'])])
        
        self.style.configure('Success.TButton',
                           font=('Segoe UI', 10, 'bold'),
                           padding=(12, 8),
                           background=self.colors['success'],
                           foreground=self.colors['text_primary'])
        
        self.style.configure('Warning.TButton',
                           font=('Segoe UI', 10, 'bold'),
                           padding=(12, 8),
                           background=self.colors['warning'],
                           foreground=self.colors['text_primary'])
        
        self.style.configure('Status.TLabel',
                           font=('Segoe UI', 10, 'bold'),
                           foreground=self.colors['text_secondary'],
                           background=self.colors['bg_primary'])
        
        # Note: Removed custom styles that were causing TclError
        # Using default ttk styles for better compatibility
    
    def create_widgets(self):
        """Create the main GUI widgets"""
        # Configure root window
        self.root.configure(bg=self.colors['bg_primary'])
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title and status indicator
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        title_frame.columnconfigure(1, weight=1)
        
        title_label = ttk.Label(title_frame, text="🔒 Windows Privacy Guard", style='Title.TLabel')
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        # Privacy status indicator with score
        self.privacy_status_label = ttk.Label(title_frame, text="🔍 Scanning...", style='Status.TLabel')
        self.privacy_status_label.grid(row=0, column=1, sticky=tk.E)
        
        # Privacy score indicator
        self.privacy_score_label = ttk.Label(title_frame, text="", style='Status.TLabel')
        self.privacy_score_label.grid(row=0, column=2, sticky=tk.E, padx=(10, 0))
        
        # Left panel - Privacy options
        left_frame = ttk.LabelFrame(main_frame, text="🛡️ Privacy Protection Options", 
                                  padding="15")
        left_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 15))
        
        # Add explanation label with quick actions
        explanation_frame = ttk.Frame(left_frame)
        explanation_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        explanation_label = ttk.Label(explanation_frame, 
                                    text="✅ Checked = Protection ON | ❌ Unchecked = Protection OFF",
                                    font=('Segoe UI', 9, 'italic'),
                                    foreground=self.colors['text_muted'],
                                    background=self.colors['bg_primary'])
        explanation_label.grid(row=0, column=0, sticky=tk.W)
        
        # Quick action buttons
        quick_frame = ttk.Frame(explanation_frame)
        quick_frame.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        ttk.Button(quick_frame, text="Select All", 
                 command=self.select_all_protections, style='Custom.TButton').grid(row=0, column=0, padx=(0, 5))
        ttk.Button(quick_frame, text="Clear All", 
                 command=self.clear_all_protections, style='Custom.TButton').grid(row=0, column=1, padx=(0, 5))
        ttk.Button(quick_frame, text="Recommended", 
                 command=self.set_recommended_protections, style='Success.TButton').grid(row=0, column=2)
        
        # Privacy checkboxes
        self.privacy_vars = {}
        privacy_options = [
            ("Telemetry & Data Collection", "Disable Windows telemetry and data collection"),
            ("Tracking & Monitoring", "Disable activity tracking and monitoring"),
            ("Advertising & Personalization", "Disable advertising ID and personalized content"),
            ("Cortana & Voice Data", "Disable Cortana and voice data collection"),
            ("Location Services", "Disable location tracking and GPS"),
            ("Microsoft Bloatware", "Remove Microsoft pre-installed apps"),
            ("Microsoft Services", "Disable Microsoft data collection services"),
            ("Windows Update Telemetry", "Disable Windows Update data collection"),
            ("OneDrive Sync", "Disable OneDrive automatic syncing"),
            ("Windows Hello", "Disable biometric data collection"),
            ("Feedback Hub", "Disable user feedback collection")
        ]
        
        for i, (option, description) in enumerate(privacy_options):
            var = tk.BooleanVar()
            self.privacy_vars[option] = var
            
            # Create checkbox with better styling (row + 2 because of explanation and quick actions)
            cb = ttk.Checkbutton(left_frame, text=option, variable=var, style='Custom.TCheckbutton')
            cb.grid(row=i+2, column=0, sticky=tk.W, pady=3)
            
            # Description with better styling
            desc_label = ttk.Label(left_frame, text=description, 
                                font=('Segoe UI', 9), 
                                foreground=self.colors['text_secondary'],
                                background=self.colors['bg_primary'])
            desc_label.grid(row=i+2, column=1, sticky=tk.W, padx=(25, 0))
        
        # Right panel - Controls and status
        right_frame = ttk.LabelFrame(main_frame, text="⚙️ Controls & Status", 
                                   padding="15")
        right_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Privacy level selection
        level_frame = ttk.LabelFrame(right_frame, text="🎯 Privacy Level", 
                                   padding="10")
        level_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.level_var = tk.StringVar(value="custom")
        levels = [
            ("Conservative", "conservative", "Safe for most users, keeps essential features"),
            ("Aggressive", "aggressive", "Maximum privacy, disables everything"),
            ("Custom", "custom", "Choose your own privacy settings")
        ]
        
        for i, (name, value, desc) in enumerate(levels):
            rb = ttk.Radiobutton(level_frame, text=name, variable=self.level_var, value=value)
            rb.grid(row=i, column=0, sticky=tk.W, pady=2)
            
            desc_label = ttk.Label(level_frame, text=desc, 
                                 font=('Segoe UI', 9), 
                                 foreground=self.colors['text_secondary'],
                                 background=self.colors['bg_primary'])
            desc_label.grid(row=i, column=1, sticky=tk.W, padx=(15, 0))
        
        # Action buttons
        button_frame = ttk.Frame(right_frame)
        button_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.apply_btn = ttk.Button(button_frame, text="🛡️ Apply Privacy Protection", 
                                 command=self.apply_privacy_protection, style='Success.TButton')
        self.apply_btn.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=3)
        
        self.scan_btn = ttk.Button(button_frame, text="🔍 Scan Current Status", 
                                 command=self.scan_privacy_status, style='Custom.TButton')
        self.scan_btn.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=3)
        
        # Advanced options
        advanced_frame = ttk.Frame(button_frame)
        advanced_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=3)
        
        ttk.Button(advanced_frame, text="📊 Generate Report", 
                 command=self.generate_report, style='Custom.TButton').grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(advanced_frame, text="💾 Backup Settings", 
                 command=self.backup_settings, style='Custom.TButton').grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(advanced_frame, text="📥 Restore Settings", 
                 command=self.restore_settings, style='Custom.TButton').grid(row=0, column=2, sticky=(tk.W, tk.E))
        
        self.restore_btn = ttk.Button(button_frame, text="↩️ Restore Windows Defaults", 
                                     command=self.restore_defaults, style='Warning.TButton')
        self.restore_btn.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=3)
        
        # Status display
        status_frame = ttk.LabelFrame(right_frame, text="📊 Status Report", 
                                    padding="10")
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        
        self.status_text = tk.Text(status_frame, height=8, width=50, 
                                 font=('Consolas', 9), 
                                 bg=self.colors['bg_tertiary'], 
                                 fg=self.colors['text_primary'],
                                 insertbackground=self.colors['text_primary'],
                                 relief='flat', borderwidth=0)
        status_scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=status_scrollbar.set)
        
        self.status_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        status_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Progress bar
        self.progress = ttk.Progressbar(right_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Log display
        log_frame = ttk.LabelFrame(main_frame, text="📝 Activity Log", 
                                 padding="10")
        log_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(15, 0))
        
        self.log_text = tk.Text(log_frame, height=6, width=100, 
                               font=('Consolas', 9), 
                               bg=self.colors['bg_tertiary'], 
                               fg=self.colors['text_primary'],
                               insertbackground=self.colors['text_primary'],
                               relief='flat', borderwidth=0)
        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        main_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        left_frame.columnconfigure(1, weight=1)
        right_frame.columnconfigure(0, weight=1)
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                # Load privacy settings
                if 'privacy' in config:
                    privacy_config = config['privacy']
                    for option, var in self.privacy_vars.items():
                        if option.lower().replace(' & ', '_').replace(' ', '_') in privacy_config:
                            var.set(privacy_config[option.lower().replace(' & ', '_').replace(' ', '_')])
                
                self.log_message("Configuration loaded successfully")
            else:
                self.log_message("No configuration file found, using defaults")
        except Exception as e:
            self.log_message(f"Error loading configuration: {e}")
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            config = {
                'privacy': {},
                'level': self.level_var.get()
            }
            
            for option, var in self.privacy_vars.items():
                key = option.lower().replace(' & ', '_').replace(' ', '_')
                config['privacy'][key] = var.get()
            
            # Ensure config directory exists
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.log_message("Configuration saved successfully")
        except Exception as e:
            self.log_message(f"Error saving configuration: {e}")
    
    def log_message(self, message):
        """Add a message to the log display"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_status(self, message):
        """Update the status display"""
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
        self.root.update_idletasks()
    
    def run_powershell_script(self, arguments):
        """Run the PowerShell script with given arguments"""
        try:
            if not self.script_path.exists():
                self.log_message("PowerShell script not found, creating it...")
                self.create_powershell_script()
            
            # Build command
            cmd = [
                'powershell.exe',
                '-ExecutionPolicy', 'Bypass',
                '-File', str(self.script_path)
            ] + arguments
            
            self.log_message(f"Running: {' '.join(cmd)}")
            
            # Run the script
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self.log_message("Script executed successfully")
                return True, result.stdout
            else:
                self.log_message(f"Script failed with return code {result.returncode}")
                self.log_message(f"Error: {result.stderr}")
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            self.log_message("Script execution timed out")
            return False, "Timeout"
        except Exception as e:
            self.log_message(f"Error running script: {e}")
            return False, str(e)
    
    def create_powershell_script(self):
        """Create the PowerShell script if it doesn't exist"""
        # This would create the actual PowerShell script
        # For now, we'll just log that it's needed
        self.log_message("PowerShell script creation not implemented in GUI version")
    
    def apply_privacy_protection(self):
        """Apply the selected privacy protections"""
        def run_protection():
            self.progress.start()
            self.apply_btn.config(state='disabled')
            
            try:
                self.update_status("Starting privacy protection...")
                self.log_message("Applying privacy protection...")
                
                # Determine what to disable based on level
                level = self.level_var.get()
                arguments = []
                
                if level == "conservative":
                    arguments = ["--conservative"]
                elif level == "aggressive":
                    arguments = ["--aggressive"]
                elif level == "custom":
                    # Build arguments based on selected options
                    # Only apply protection for checked items (protection enabled)
                    for option, var in self.privacy_vars.items():
                        if var.get():  # If checked, apply protection
                            arg_name = option.lower().replace(' & ', '').replace(' ', '')
                            arguments.append(f"--{arg_name}")
                
                if not arguments:
                    arguments = ["--all"]
                
                # Run the protection
                success, output = self.run_powershell_script(arguments)
                
                if success:
                    self.update_status("✅ Privacy protection applied successfully!")
                    self.log_message("Privacy protection completed")
                    messagebox.showinfo("Success", "Privacy protection has been applied successfully!")
                else:
                    self.update_status("❌ Privacy protection failed")
                    self.log_message(f"Protection failed: {output}")
                    messagebox.showerror("Error", f"Privacy protection failed:\n{output}")
                
            except Exception as e:
                self.update_status(f"❌ Error: {e}")
                self.log_message(f"Error: {e}")
                messagebox.showerror("Error", f"An error occurred: {e}")
            
            finally:
                self.progress.stop()
                self.apply_btn.config(state='normal')
                self.save_config()
        
        # Run in a separate thread to avoid blocking the GUI
        thread = threading.Thread(target=run_protection)
        thread.daemon = True
        thread.start()
    
    def scan_privacy_status(self):
        """Scan current privacy status and update checkboxes"""
        def run_scan():
            self.progress.start()
            self.scan_btn.config(state='disabled')
            
            try:
                self.update_status("Scanning privacy status...")
                self.log_message("Scanning current privacy status...")
                
                # Check current privacy settings
                privacy_status = self.check_privacy_settings()
                
                # Update checkboxes based on current status
                self.update_checkboxes_from_status(privacy_status)
                
                # Display status
                self.display_privacy_status(privacy_status)
                
                self.update_status("✅ Privacy status scan completed")
                self.log_message("Status scan completed")
                
            except Exception as e:
                self.update_status(f"❌ Error: {e}")
                self.log_message(f"Error: {e}")
            
            finally:
                self.progress.stop()
                self.scan_btn.config(state='normal')
        
        # Run in a separate thread
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
    
    def check_privacy_settings(self):
        """Check current privacy settings in Windows registry"""
        privacy_status = {}
        
        try:
            import winreg
            
            # Check telemetry settings
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection") as key:
                    telemetry = winreg.QueryValueEx(key, "AllowTelemetry")[0]
                    privacy_status['telemetry'] = telemetry == 0
            except:
                privacy_status['telemetry'] = False
            
            # Check advertising ID
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo") as key:
                    advertising = winreg.QueryValueEx(key, "DisabledByGroupPolicy")[0]
                    privacy_status['advertising'] = advertising == 1
            except:
                privacy_status['advertising'] = False
            
            # Check location services
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors") as key:
                    location = winreg.QueryValueEx(key, "DisableLocation")[0]
                    privacy_status['location'] = location == 1
            except:
                privacy_status['location'] = False
            
            # Check Cortana
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Policies\Microsoft\Windows\Windows Search") as key:
                    cortana = winreg.QueryValueEx(key, "AllowCortana")[0]
                    privacy_status['cortana'] = cortana == 0
            except:
                privacy_status['cortana'] = False
            
            # Check activity history
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Policies\Microsoft\Windows\System") as key:
                    activity = winreg.QueryValueEx(key, "EnableActivityFeed")[0]
                    privacy_status['tracking'] = activity == 0
            except:
                privacy_status['tracking'] = False
            
            # Check OneDrive
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Policies\Microsoft\Windows\OneDrive") as key:
                    onedrive = winreg.QueryValueEx(key, "DisableFileSyncNGSC")[0]
                    privacy_status['onedrive'] = onedrive == 1
            except:
                privacy_status['onedrive'] = False
            
            # Check Windows Hello
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Policies\Microsoft\Windows\Biometrics") as key:
                    hello = winreg.QueryValueEx(key, "Enabled")[0]
                    privacy_status['windows_hello'] = hello == 0
            except:
                privacy_status['windows_hello'] = False
            
            # Check Feedback Hub
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Policies\Microsoft\Windows\FeedbackHub") as key:
                    feedback = winreg.QueryValueEx(key, "DisableFeedbackHub")[0]
                    privacy_status['feedback'] = feedback == 1
            except:
                privacy_status['feedback'] = False
            
            # Check for Microsoft apps (bloatware)
            try:
                import subprocess
                result = subprocess.run(['powershell', '-Command', 
                                       'Get-AppxPackage | Where-Object {$_.Name -match "Microsoft.Bing|Microsoft.Xbox|Microsoft.Office"} | Measure-Object | Select-Object -ExpandProperty Count'], 
                                      capture_output=True, text=True)
                app_count = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
                privacy_status['bloatware'] = app_count == 0
            except:
                privacy_status['bloatware'] = False
            
            # Check services
            try:
                import subprocess
                services_to_check = ['DiagTrack', 'dmwappushservice', 'WerSvc']
                disabled_services = 0
                
                for service in services_to_check:
                    result = subprocess.run(['sc', 'query', service], capture_output=True, text=True)
                    if 'STOPPED' in result.stdout or 'DISABLED' in result.stdout:
                        disabled_services += 1
                
                privacy_status['services'] = disabled_services == len(services_to_check)
            except:
                privacy_status['services'] = False
            
        except Exception as e:
            self.log_message(f"Error checking privacy settings: {e}")
            privacy_status = {}
        
        return privacy_status
    
    def update_checkboxes_from_status(self, privacy_status):
        """Update checkboxes based on current privacy status"""
        # Map privacy status to checkbox variables
        status_mapping = {
            'telemetry': 'Telemetry & Data Collection',
            'tracking': 'Tracking & Monitoring', 
            'advertising': 'Advertising & Personalization',
            'cortana': 'Cortana & Voice Data',
            'location': 'Location Services',
            'bloatware': 'Microsoft Bloatware',
            'services': 'Microsoft Services',
            'onedrive': 'OneDrive Sync',
            'windows_hello': 'Windows Hello',
            'feedback': 'Feedback Hub'
        }
        
        for status_key, checkbox_name in status_mapping.items():
            if status_key in privacy_status:
                var = self.privacy_vars[checkbox_name]
                # Set checkbox to checked if the privacy setting is already disabled (protection is ON)
                # This means: checked = protection enabled, unchecked = protection disabled
                var.set(privacy_status[status_key])
    
    def display_privacy_status(self, privacy_status):
        """Display the current privacy status in the status text area"""
        self.status_text.delete(1.0, tk.END)
        
        status_report = "🔍 PRIVACY STATUS REPORT\n"
        status_report += "=" * 50 + "\n\n"
        
        # Map status to display names
        status_names = {
            'telemetry': 'Telemetry & Data Collection',
            'tracking': 'Tracking & Monitoring',
            'advertising': 'Advertising & Personalization', 
            'cortana': 'Cortana & Voice Data',
            'location': 'Location Services',
            'bloatware': 'Microsoft Bloatware',
            'services': 'Microsoft Services',
            'onedrive': 'OneDrive Sync',
            'windows_hello': 'Windows Hello',
            'feedback': 'Feedback Hub'
        }
        
        enabled_count = 0
        disabled_count = 0
        
        for status_key, display_name in status_names.items():
            if status_key in privacy_status:
                is_disabled = privacy_status[status_key]
                status_icon = "✅ DISABLED" if is_disabled else "❌ ENABLED"
                status_report += f"{status_icon} {display_name}\n"
                
                if is_disabled:
                    disabled_count += 1
                else:
                    enabled_count += 1
            else:
                status_report += f"❓ UNKNOWN {display_name}\n"
        
        status_report += "\n" + "=" * 50 + "\n"
        status_report += f"📊 SUMMARY: {disabled_count} disabled, {enabled_count} enabled\n"
        
        if disabled_count > enabled_count:
            status_report += "🛡️ Your privacy is well protected!\n"
        elif enabled_count > disabled_count:
            status_report += "⚠️ Your privacy needs attention!\n"
        else:
            status_report += "⚖️ Mixed privacy status\n"
        
        self.status_text.insert(tk.END, status_report)
        
        # Update privacy status indicator
        self.update_privacy_status_indicator(disabled_count, enabled_count)
        
        # Calculate and update privacy score
        self.privacy_score = int((disabled_count / len(privacy_status)) * 100) if privacy_status else 0
        self.update_privacy_score_display()
    
    def auto_scan_privacy(self):
        """Automatically scan privacy status on startup"""
        def run_auto_scan():
            try:
                self.log_message("Auto-scanning privacy status on startup...")
                privacy_status = self.check_privacy_settings()
                self.update_checkboxes_from_status(privacy_status)
                self.display_privacy_status(privacy_status)
                self.log_message("Auto-scan completed")
            except Exception as e:
                self.log_message(f"Auto-scan error: {e}")
        
        # Run in a separate thread to avoid blocking startup
        thread = threading.Thread(target=run_auto_scan)
        thread.daemon = True
        thread.start()
    
    def update_privacy_status_indicator(self, disabled_count, enabled_count):
        """Update the privacy status indicator in the title bar"""
        if disabled_count > enabled_count:
            status_text = "🛡️ Well Protected"
            status_color = "#4CAF50"  # Green
        elif enabled_count > disabled_count:
            status_text = "⚠️ Needs Attention"
            status_color = "#FF9800"  # Orange
        else:
            status_text = "⚖️ Mixed Status"
            status_color = "#FFC107"  # Yellow
        
        self.privacy_status_label.config(text=status_text, foreground=status_color)
    
    def update_privacy_score_display(self):
        """Update the privacy score display"""
        if self.privacy_score >= 80:
            score_text = f"🛡️ {self.privacy_score}/100"
            score_color = self.colors['success']
        elif self.privacy_score >= 60:
            score_text = f"⚠️ {self.privacy_score}/100"
            score_color = self.colors['warning']
        else:
            score_text = f"❌ {self.privacy_score}/100"
            score_color = self.colors['error']
        
        self.privacy_score_label.config(text=score_text, foreground=score_color)
    
    def select_all_protections(self):
        """Select all privacy protection options"""
        for var in self.privacy_vars.values():
            var.set(True)
        self.log_message("All privacy protections selected")
    
    def clear_all_protections(self):
        """Clear all privacy protection options"""
        for var in self.privacy_vars.values():
            var.set(False)
        self.log_message("All privacy protections cleared")
    
    def set_recommended_protections(self):
        """Set recommended privacy protection options"""
        recommended = [
            "Telemetry & Data Collection",
            "Tracking & Monitoring",
            "Advertising & Personalization",
            "Location Services",
            "Microsoft Bloatware",
            "Microsoft Services",
            "Windows Update Telemetry",
            "OneDrive Sync",
            "Feedback Hub"
        ]
        
        # Clear all first
        for var in self.privacy_vars.values():
            var.set(False)
        
        # Set recommended ones
        for option in recommended:
            if option in self.privacy_vars:
                self.privacy_vars[option].set(True)
        
        self.log_message("Recommended privacy protections set")
    
    def generate_report(self):
        """Generate a detailed privacy report"""
        def run_report():
            try:
                self.log_message("Generating privacy report...")
                
                # Create report content
                report_content = self.create_privacy_report()
                
                # Save report to file
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                report_file = self.backup_dir / f"privacy_report_{timestamp}.html"
                self.backup_dir.mkdir(parents=True, exist_ok=True)
                
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                
                self.log_message(f"Privacy report saved to: {report_file}")
                messagebox.showinfo("Report Generated", f"Privacy report saved to:\n{report_file}")
                
            except Exception as e:
                self.log_message(f"Error generating report: {e}")
                messagebox.showerror("Error", f"Failed to generate report: {e}")
        
        thread = threading.Thread(target=run_report)
        thread.daemon = True
        thread.start()
    
    def create_privacy_report(self):
        """Create HTML privacy report"""
        privacy_status = self.check_privacy_settings()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Windows Privacy Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #ffffff; }}
        .header {{ background: #0078d4; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .section {{ background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .status-good {{ color: #107c10; }}
        .status-warning {{ color: #ff8c00; }}
        .status-bad {{ color: #d13438; }}
        .score {{ font-size: 24px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Windows Privacy Report</h1>
        <p>Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="section">
        <h2>📊 Privacy Score: <span class="score">{self.privacy_score}/100</span></h2>
        <p>Your privacy protection level based on current settings.</p>
    </div>
    
    <div class="section">
        <h2>🛡️ Protection Status</h2>
"""
        
        status_names = {
            'telemetry': 'Telemetry & Data Collection',
            'tracking': 'Tracking & Monitoring',
            'advertising': 'Advertising & Personalization',
            'cortana': 'Cortana & Voice Data',
            'location': 'Location Services',
            'bloatware': 'Microsoft Bloatware',
            'services': 'Microsoft Services',
            'onedrive': 'OneDrive Sync',
            'windows_hello': 'Windows Hello',
            'feedback': 'Feedback Hub'
        }
        
        for status_key, display_name in status_names.items():
            if status_key in privacy_status:
                is_disabled = privacy_status[status_key]
                status_class = "status-good" if is_disabled else "status-bad"
                status_text = "✅ PROTECTED" if is_disabled else "❌ VULNERABLE"
                html += f'        <p><span class="{status_class}">{status_text}</span> {display_name}</p>\n'
        
        html += """
    </div>
    
    <div class="section">
        <h2>📋 Recommendations</h2>
        <ul>
            <li>Enable all recommended privacy protections</li>
            <li>Regularly scan for new privacy threats</li>
            <li>Keep Windows updated for security patches</li>
            <li>Review and update privacy settings monthly</li>
        </ul>
    </div>
</body>
</html>
"""
        return html
    
    def backup_settings(self):
        """Backup current privacy settings"""
        def run_backup():
            try:
                self.log_message("Creating settings backup...")
                
                # Create backup directory
                self.backup_dir.mkdir(parents=True, exist_ok=True)
                
                # Save current settings
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                backup_file = self.backup_dir / f"privacy_backup_{timestamp}.json"
                
                backup_data = {
                    'timestamp': timestamp,
                    'privacy_settings': {option: var.get() for option, var in self.privacy_vars.items()},
                    'level': self.level_var.get(),
                    'privacy_score': self.privacy_score
                }
                
                with open(backup_file, 'w') as f:
                    json.dump(backup_data, f, indent=2)
                
                self.log_message(f"Settings backed up to: {backup_file}")
                messagebox.showinfo("Backup Created", f"Settings backed up to:\n{backup_file}")
                
            except Exception as e:
                self.log_message(f"Error creating backup: {e}")
                messagebox.showerror("Error", f"Failed to create backup: {e}")
        
        thread = threading.Thread(target=run_backup)
        thread.daemon = True
        thread.start()
    
    def restore_settings(self):
        """Restore privacy settings from backup"""
        try:
            # Get list of backup files
            backup_files = list(self.backup_dir.glob("privacy_backup_*.json"))
            
            if not backup_files:
                messagebox.showwarning("No Backups", "No backup files found.")
                return
            
            # Show file selection dialog
            from tkinter import filedialog
            backup_file = filedialog.askopenfilename(
                title="Select Backup File",
                initialdir=self.backup_dir,
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if backup_file:
                with open(backup_file, 'r') as f:
                    backup_data = json.load(f)
                
                # Restore settings
                for option, enabled in backup_data.get('privacy_settings', {}).items():
                    if option in self.privacy_vars:
                        self.privacy_vars[option].set(enabled)
                
                self.level_var.set(backup_data.get('level', 'custom'))
                self.privacy_score = backup_data.get('privacy_score', 0)
                
                self.log_message(f"Settings restored from: {backup_file}")
                messagebox.showinfo("Settings Restored", "Privacy settings have been restored from backup.")
                
        except Exception as e:
            self.log_message(f"Error restoring settings: {e}")
            messagebox.showerror("Error", f"Failed to restore settings: {e}")
    
    def restore_defaults(self):
        """Restore Windows default privacy settings"""
        def run_restore():
            self.progress.start()
            self.restore_btn.config(state='disabled')
            
            try:
                self.update_status("Restoring Windows defaults...")
                self.log_message("Restoring Windows default privacy settings...")
                
                # Run restore
                success, output = self.run_powershell_script(["--restore"])
                
                if success:
                    self.update_status("✅ Windows defaults restored successfully!")
                    self.log_message("Windows defaults restored")
                    messagebox.showinfo("Success", "Windows default privacy settings have been restored!")
                else:
                    self.update_status("❌ Restore failed")
                    self.log_message(f"Restore failed: {output}")
                    messagebox.showerror("Error", f"Restore failed:\n{output}")
                
            except Exception as e:
                self.update_status(f"❌ Error: {e}")
                self.log_message(f"Error: {e}")
                messagebox.showerror("Error", f"An error occurred: {e}")
            
            finally:
                self.progress.stop()
                self.restore_btn.config(state='normal')
        
        # Confirm before restoring
        if messagebox.askyesno("Confirm Restore", 
                             "Are you sure you want to restore Windows default privacy settings?\n"
                             "This will re-enable all privacy-breaking features."):
            # Run in a separate thread
            thread = threading.Thread(target=run_restore)
            thread.daemon = True
            thread.start()

def main():
    """Main function to run the GUI application"""
    root = tk.Tk()
    app = PrivacyGuardGUI(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
