import time
import socket

# Note: You will need to install paramiko to run this script:
# pip install paramiko

try:
    import paramiko
except ImportError:
    print("Please install paramiko first by running: pip install paramiko")
    exit(1)

def simulate_attack():
    print("Initiating simulated attack on Honeypot (localhost:2222)...")
    
    client = paramiko.SSHClient()
    # Automatically add the server's SSH key
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to the honeypot
        client.connect('localhost', port=2222, username='root', password='root123', timeout=10)
        print("Successfully connected as root!\n")
        
        # Open an interactive shell session (the honeypot expects a shell, not exec_command)
        shell = client.invoke_shell()
        time.sleep(2)
        
        # Read the initial banner
        if shell.recv_ready():
            print(shell.recv(4096).decode('utf-8', errors='ignore'))
        
        # List of commands to simulate an attacker's reconnaissance and data exfiltration
        commands = [
            "whoami",
            "uname -a",
            "ps aux",
            "netstat -tulpn",
            "cat /etc/passwd",
            "ls -la /root",
            "cat /root/.aws/credentials",                      # Honeytoken trigger
            "cat /opt/nexopay/config/stripe.env",              # Honeytoken trigger
            "sqlite3 /opt/nexopay/data/payments.db '.tables'", # Honeytoken trigger
            "sqlite3 /opt/nexopay/data/payments.db 'select * from users'",
            "exit"
        ]
        
        for cmd in commands:
            print(f"\n[Attacker] > {cmd}")
            shell.send(cmd + "\n")
            
            # Wait a bit for the honeypot/AI engine to process and respond
            time.sleep(3) 
            
            # Read and print the output
            output = ""
            while shell.recv_ready():
                output += shell.recv(4096).decode('utf-8', errors='ignore')
            
            # Clean up output to make it readable
            lines = output.split('\n')
            for line in lines:
                if cmd not in line and line.strip():
                    print(line.strip())
                    
    except socket.error as e:
        print(f"Connection failed (is the docker container running?): {e}")
    except paramiko.AuthenticationException:
        print("Authentication failed. Password might be wrong.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client.close()
        print("\nAttack simulation finished.")

if __name__ == "__main__":
    simulate_attack()
