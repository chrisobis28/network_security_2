import socket
import time
import random
import sys

commands = [
    "date",
    "id",
    "uptime",
    "uname -a",
    "ls -l /",
    "echo Hello, World! | /usr/games/cowsay -f tux",
    "seq 1 5 | shuf",
    "/usr/games/fortune | /usr/games/cowsay",
]

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>", flush=True)
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"Connecting to {host}:{port}...", flush=True)
                s.connect((host, port))
                print("Connected.", flush=True)

                while True:
                    command = random.choice(commands)
                    print(f"Executing command: {command}", flush=True)
                    s.sendall(command.encode() + b'\n')

                    s.settimeout(5)
                    output = s.recv(4096).decode(errors='replace')
                    print(f"{output}", flush=True)

                    time.sleep(3)

        except Exception as e:
            print(f"Unexpected error: {e}. Retrying in 10 seconds...", flush=True)
            time.sleep(10)

if __name__ == "__main__":
    main()
