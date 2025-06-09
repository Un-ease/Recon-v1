import subprocess
import os
import time
import threading
import json
import re

Resolvers_path = os.path.expanduser('~/Tools/resolvers_trusted.txt')

def banner():
    return r'''
__________________________________________________   
__________                                      
\______   \ ____             ____  ____   ____  
 |       _// __ \   ______ _/ ___\/  _ \ /    \ 
 |    |   \  ___/  /_____/ \  \__(  <_> )   |  \
 |____|_  /\___  >          \___  >____/|___|  /
        \/     \/               \/           \/  
________________________________By___Anij_Gurung__        
        '''

def loading_animation(stop_event):
    symbols = ['|', '/', '-', '\\']
    i = 0
    while not stop_event.is_set():
        print(f"\rRunning... {symbols[i % len(symbols)]}", end="", flush=True)
        i += 1
        time.sleep(0.1)
    print("\r" + " " * 50, end="\r") 

def sub_enum(domain, save_directory):
    os.makedirs(save_directory, exist_ok=True)

    try:
        print("\nStarting Subfinder...")
        stop_event = threading.Event()
        loading_thread = threading.Thread(target=loading_animation, args=(stop_event,))
        loading_thread.start()
        with open(f"{save_directory}/subdomain1.txt", "w") as outfile:
            result =  subprocess.run(
                ["subfinder", "-d", domain, "-all"],
                stdout=outfile,
                stderr=subprocess.PIPE,
                text=True
            )
        stop_event.set()
        loading_thread.join()
        print(f"\rSubfinder {'Completed Successfully' if result.returncode == 0  else 'failed'}. Output saved in {save_directory}/subdomain1.txt")

        print("\nStarting AssetFinder")
        stop_event = threading.Event()
        loading_thread = threading.Thread(target=loading_animation, args=(stop_event,))
        loading_thread.start()
        with open(f"{save_directory}/subdomain2.txt", "w") as outfile:
            result = subprocess.run(
                ["assetfinder", "--subs-only", domain],
                stdout=outfile,
                stderr=subprocess.PIPE,
                text=True
            )

        stop_event.set()
        loading_thread.join()
        print(f"\rAssetFinder {'Completed Successfully' if result.returncode == 0  else 'failed'}. Output saved in {save_directory}/subdomain2.txt")

        print("Merging Subdomains")
        merge_cmd = f"sort -u {save_directory}/subdomain1.txt {save_directory}/subdomain2.txt > {save_directory}/domain.txt"
        remove_cmd = f"rm {save_directory}subdomain1.txt {save_directory}/subdomain2.txt"
    
        subprocess.run(merge_cmd, shell=True)
        subprocess.run(remove_cmd, shell=True)

        print(f"Unique Subdomains Saved at {save_directory}/domain.txt")

    except Exception as e:
        print(f"\rError running subdomain tools: {str(e)}")

def dns_resolve(save_directory):
    print("\nResolving with MassDns")

    with open(f"{save_directory}/domain.txt","r") as f:
        domains = [line.strip() for line in f if line.strip()]

    cmd = [
        'massdns',
        '-s', '15000',
        '-t', 'A',
        '-o', 'J',
        '-r', Resolvers_path,
        '--flush'
    ]

    domains_str = '\n'.join(domains).encode('ascii')
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    stdout, _ = proc.communicate(input = domains_str)

    results = []
    for line in stdout.splitlines():
        try:
            record = json.loads(line.decode('utf-8').strip())
            results.append(record)
        except Exception:
            continue

    with open(f"{save_directory}/resolved_domains.txt", "w") as f:
        for entry in results:
            if 'name'in entry:
                f.write(entry['name'].rstrip('.') + '\n')

    print(f"[+] Resolved Domains saved at {save_directory}/resolved_domains.txt ")

def httpx_prove(save_directory):
    resolved_file = os.path.join(save_directory, 'resolved.txt')
    httpx_output = os.path.join(save_directory, 'httpx-toolkit.txt')
    code_200_file = os.path.join(save_directory, '200.txt')
    plain_file = os.path.join(save_directory, 'plain.txt')

    print("Checking For live servers")

    try:
        subprocess.run([
            "httpx",
            "-l", resolved_file,
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-o", httpx_output
        ], check=True)
    except subprocess.CalledProcessError:
        print("HTTP probing failed")
        return

    total = sum(1 for _ in open(httpx_output))
    print(f"[+] Total live subdomains: {total}")


    with open(httpx_output, 'r', encoding='utf-8') as infile, open(code_200_file, 'w') as outfile:
        for line in infile:
            clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
            if '[200]' in clean_line:
                outfile.write(clean_line)

    code_200_total = sum(1 for _ in open(code_200_file))
    print(f"[+] 200 status code domains: {code_200_total}")

    # Extract URLs from 200.txt
    with (open(code_200_file, 'r', encoding='utf-8') as infile, open(plain_file, 'w') as outfile):
        for line in infile:
            if parts := line.split():
                outfile.write(parts[0] + '\n')

    # Take screenshots with httpx
    print("[+] Taking screenshots...")
    subprocess.run([
        "httpx-toolkit",
        "-l", plain_file,
        "-silent",
        "-screenshot",
        "-srd", save_directory
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"[+] Screenshots saved in {save_directory}")


if __name__ == "__main__":
    print(banner())
    target = input("Enter the Target Domain:")
    directory = input("Enter the Directory where you want the output to be saved")

    os.makedirs(directory, exist_ok=True)
    sub_enum(target,directory)
    dns_resolve(directory)
    httpx_prove(directory)