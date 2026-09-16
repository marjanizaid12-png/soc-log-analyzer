threshold=3
failed_ip={}
failed_user={}
with open("more_logs.txt", "r") as f:
    logs = f.readlines()
    print("FILE READ SUCCESSFULLY")
    print("TOTAL LINES:", len(logs))
 
    for line in logs:
        if "login failed" in line.lower():
            username = line.split("user=")[1].split()[0]
            ip = line.split("from ")[1].split()[0]
            failed_ip[ip] = failed_ip.get(ip, 0) + 1
            if ip not in failed_user:
                failed_user[ip] = set()
    for ip, count in failed_ip.items():
        if count >= threshold:
            print("Potential brute force attack detected from ")
            print(f"IP: {ip}, Failed Attempts: {count}")