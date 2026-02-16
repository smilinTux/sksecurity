#!/usr/bin/env python3
"""
SKSecurity Enterprise Dashboard Module
Simple wrapper for the security dashboard functionality
"""

import os
import sys
import subprocess
from pathlib import Path

def launch_dashboard(port=8888, host='localhost'):
    """Launch the SKSecurity security dashboard"""
    # Find the dashboard script
    script_path = Path(__file__).parent.parent / "scripts" / "security_dashboard.py"
    
    if script_path.exists():
        # Run the dashboard script
        subprocess.run([sys.executable, str(script_path), "--port", str(port), "--host", host])
    else:
        print("🚨 Dashboard script not found. Please check your installation.")
        print("Expected location:", script_path)
        return False
    
    return True

def main():
    """Main entry point for dashboard command"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SKSecurity Enterprise Dashboard')
    parser.add_argument('--port', type=int, default=8888, help='Port to run dashboard on')
    parser.add_argument('--host', type=str, default='localhost', help='Host to bind to')
    
    args = parser.parse_args()
    
    print("🛡️ Launching SKSecurity Enterprise Dashboard...")
    print(f"📊 Dashboard will be available at: http://{args.host}:{args.port}")
    
    launch_dashboard(args.port, args.host)

if __name__ == "__main__":
    main()