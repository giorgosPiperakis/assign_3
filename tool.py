import argparse
import hashlib
import os
import hashlib
import shutil
from datetime import datetime
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re


global signatures
global args

def load_signatures(filename):
    global signatures
    signatures = {}
    with open(filename, "r") as file:
        next(file)  # Skip header line
        next(file)  # -----------------
        for line in file:
            md5_hash, sha256_hash,label = line.strip().split(" | ")
            signatures[(md5_hash, sha256_hash)] = label
def calculate_hashes(file_path):
    with open (file_path,"r") as file:
        for line in file:
            binary_data = bytes.fromhex(line)
    md5_hash = hashlib.md5(binary_data).hexdigest()
    sha256_hash = hashlib.sha256(binary_data).hexdigest()
    return md5_hash, sha256_hash

def determine_threat_level(label):
    levels = {
        "malware": "High",
        "non-malware": "Low",
    }
    return levels.get(label, "Medium")

def log_detection(file_path, file_info, status, log_file):
    
    with open(log_file, "a") as log:
        log.write(f"{datetime.now()} - {file_path} - {status}\n")
        log.write(f"  Size: {file_info['size']} bytes\n")
        log.write(f"  Type: {file_info['type']}\n")
        log.write(f"  MD5: {file_info['md5']}\n")
        log.write(f"  SHA256: {file_info['sha256']}\n")
        log.write("  ------------------------------------\n")

def quarantine_file(file_path, quarantine_dir="quarantine"):
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    file_name = os.path.basename(file_path)
    quarantine_path = os.path.join(quarantine_dir, file_name)
    shutil.move(file_path, quarantine_path)
    print(f"File {file_name} quarantined to {quarantine_path}")

def detect_malware( file_path,log_file):
    results = {}
    global signatures


    md5_hash, sha256_hash = calculate_hashes(file_path)

    file_info = {
        "size": os.path.getsize(file_path),
        "type": file_path.split('.')[-1],
        "md5": md5_hash,
        "sha256": sha256_hash
    }
    status = "Clean"
    if (md5_hash, sha256_hash) in signatures:
        label = signatures[(md5_hash, sha256_hash)]
        threat_level = determine_threat_level(label)
        status = f"Infected ({threat_level})"
        
        #Quarantine the file if infected
        quarantine_file(file_path)
        
        print(f"ALERT: Detected malware in {file_path}")
        print(f"Threat Level: {threat_level}")
        
    # Log the detection details

    log_detection(file_path, file_info, status,log_file)

def scan_directory(directory,log_file):
    global signatures
    

    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            
            # Check if file matches any known malware signature
            status = "Clean"
            

            md5_hash, sha256_hash = calculate_hashes(file_path)
            file_info = {
                "size": os.path.getsize(file_path),
                "type": file_name.split('.')[-1],
                "md5": md5_hash,
                "sha256": sha256_hash
            }

            if (md5_hash, sha256_hash) in signatures:
                label = signatures[(md5_hash, sha256_hash)]
                threat_level = determine_threat_level(label)
                print(label)
                status = f"Infected ({threat_level})"
                
                #Quarantine the file if infected
                quarantine_file(file_path)
                
                print(f"ALERT: Detected malware in {file_path}")
                print(f"Threat Level: {threat_level}")
                
            # Log the detection details

            log_detection(file_path, file_info, status,log_file)
def is_temporary_file( file_path):
    # Add patterns for various temporary files
    temp_file_patterns = [
        r'\.goutputstream-[A-Za-z0-9]+$',  # GNOME temporary files
        r'\.~$',                          # Temporary files ending with .~
        r'\.swp$',                        # Vim swap files
        r'\.tmp$',                        # Common .tmp files
        r'\.part$',                       # Partial download files
        r'\.crdownload$',                 # Chrome download files
    ]
    return any(re.search(pattern, os.path.basename(file_path)) for pattern in temp_file_patterns)

class DirectoryMonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        global args
        print(f"File created: {event.src_path}")
        if not os.path.isfile(event.src_path) :
            return False  # Ignore directories
        if is_temporary_file(event.src_path):
            return False
        print(f"DETECTING MALWARE ON CREATION IN FILE: {event.src_path}")
        detect_malware(event.src_path,args.output)

    def on_modified(self, event):
        global args
        print(f"File modified: {event.src_path}")
        if not os.path.isfile(event.src_path):
            return False  # Ignore directories
        if is_temporary_file(event.src_path):
            return False
        print(f"DETECTING MALWARE ON MODIFICATION IN FILE: {event.src_path}")
        detect_malware(event.src_path,args.output)

    # def on_deleted(self, event):
    #     print(f"File deleted: {event.src_path}")
    #     detect_malware(event.src_path)

def monitor_directory(path_to_watch):
    event_handler = DirectoryMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    print(f"Monitoring directory: {path_to_watch}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def main():
    parser = argparse.ArgumentParser(description="Malware detection tool")
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument("-s", "--signature", required=True, help="Path to malware signature file")
    parser.add_argument("-o", "--output", required=True, help="Output file for infected files report")
    parser.add_argument("-r", "--realtime", action="store_true", help="Run in real-time mode")

    global args 
    args = parser.parse_args()

    # Load malware signatures
    load_signatures(args.signature)

    # Scan the directory
    print(f"Scanning directory: {args.directory}")
    scan_directory(args.directory, args.output)

    # If real-time monitoring is enabled, start it
    if args.realtime:
        print("Starting real-time monitoring...")
        monitor_directory(args.directory)

if __name__ == "__main__":
    main()