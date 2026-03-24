import socket
import errno

target = "127.0.0.1"
port = 8000

print(f"--- Diagnostic Check: Testing Port {port} on {target} ---")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)

# connect_ex returns an integer. Let's see what that integer is.
result = s.connect_ex((target, port))

if result == 0:
    print("SUCCESS: The port is OPEN.")
else:
    # This translates the number into a human-readable error (e.g., Connection Refused)
    error_message = errno.errorcode.get(result, "Unknown Error")
    print(f"FAILED: Result code is {result} ({error_message})")

s.close()