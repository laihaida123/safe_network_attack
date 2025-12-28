"""
Start multiple instances of the Flask application on different ports.
This script allows running multiple backend instances simultaneously
on ports 5000-5005 for load balancing and high availability.
"""

import subprocess
import sys
import os
from pathlib import Path

def start_server(script_name, port, host='127.0.0.1'):
    """Start a Flask server instance on the specified port."""
    try:
        # Use environment variables to pass host and port information
        # This works because Flask automatically reads these environment variables
        process = subprocess.Popen([
            sys.executable, script_name
        ], env={
            **os.environ,
            'FLASK_RUN_PORT': str(port),
            'FLASK_RUN_HOST': host
        })
        return process
    except Exception as e:
        print(f"Failed to start server on port {port}: {e}")
        return None

def main():
    """Main function to start multiple server instances."""
    # Define which scripts to run on which ports
    servers = [
        ('app.py', 5000),
        ('vuln_unauth.py', 5001),
        ('vuln_dir_traversal.py', 5002),
        ('vuln_ecb_mode.py', 5003),
        ('app.py', 5004),
        ('vuln_sql_injection.py', 5005)
    ]
    
    processes = []
    
    print("Starting multiple Flask instances...")
    
    for script_name, port in servers:
        print(f"Starting {script_name} on port {port}...")
        process = start_server(script_name, port)
        if process:
            processes.append((port, process))
    
    print(f"Started {len(processes)} server instances")
    print("Press Ctrl+C to stop all servers")
    
    try:
        # Keep the script running
        while True:
            pass
    except KeyboardInterrupt:
        print("\nShutting down all servers...")
        for port, process in processes:
            process.terminate()
            process.wait()
        print("All servers stopped")

if __name__ == '__main__':
    main()