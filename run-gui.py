#!/usr/bin/env python3
"""
Windows Privacy Guard - GUI Launcher
Simple launcher script for the GUI version
"""

import sys
import os
from pathlib import Path

def main():
    """Launch the GUI application"""
    try:
        # Add current directory to Python path
        current_dir = Path(__file__).parent
        sys.path.insert(0, str(current_dir))
        
        # Import and run the GUI
        from privacy_guard_gui import main as gui_main
        gui_main()
        
    except ImportError as e:
        print(f"Error importing GUI module: {e}")
        print("Make sure you have the required dependencies installed:")
        print("pip install tkinter")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching GUI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
