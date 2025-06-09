import subprocess
import os
import time
import threading

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
                ["assetfinder", "--subs-only", domain]
                stdout=outfile,
                stderr=subprocess.PIPE,
                text=True
            )

        stop_event.set()
        loading_thread.join()
        print(f"\rAssetFinder {'Completed Successfully' if result.returncode == 0  else 'failed'}. Output saved in {save_directory}/subdomain2.txt")

        print("Merging Subdomains")
        merge_cmd = f"sort -u {save_directory}/subdomain1.txt {save_directory}/subdo"

    except Exception as e:
        print(f"\rError running subdomain tools: {str(e)}")