import psutil
import socket



def suspicious_traffic():
    suspiciousPorts = [80,443,21,20,25,8080,8443,587,443,51190]
    for proc in psutil.process_iter(['pid','name']):
        try:
            connections = proc.connections()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            
            continue

        for conn in connections:
            if conn.status == psutil.CONN_ESTABLISHED and conn.laddr.port in suspiciousPorts:
                try:
                    ip = socket.gethostbyaddr(conn.raddr.ip)[0]
                except (socket.herror, socket.gaierror):
                    ip = conn.raddr.ip

                print(f"Process {proc.name()} | PID {proc.pid} is communicating with {ip} on port {conn.laddr.port}")
                answer = input("Do you want to kill this process? (y/n) ")
                if(answer == "y"):
                    proc.kill()
                    print("Process Terminated")
                    break
                
                elif(answer == "n"):
                    print()
                    break
                
                else:
                    print("Invalid input")
        
suspicious_traffic()




