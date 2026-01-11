#   Script to easily dump TLS keys for debugging purposes
#   The script has configurable options for process name and target 
# ip and port. The IP and port need to match the TLS connection.

import frida
import sys
import paramiko
import asyncio

process_name = "mosquitto_sub"
destination_host = ""
destination_port = ""
remote_host = "127.0.0.1"
remote_port = "44444"
script_path = "scripts/trace_libssl.js"

remote_socket = remote_host + ":" + remote_port

block_connection_command = f"iptables -A OUTPUT -p tcp --dport {destination_port} -d {destination_host} -j REJECT --reject-with tcp-reset"
unblock_connection_command = f"iptables -D OUTPUT -p tcp --dport {destination_port} -d {destination_host} -j REJECT --reject-with tcp-reset"

class SSHConnection:
  def __init__(self, hostname, port, username, password):
    self.hostname = hostname
    self.port = port
    self.username = username
    self.password = password
    self.client = None

  def __enter__(self):
    self.client = paramiko.SSHClient()
    self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    self.client.connect(self.hostname, port=self.port, username=self.username, password=self.password)
    return self.client

  def __exit__(self, exc_type, exc_value, traceback):
    if self.client:
      self.client.close()

def connect_to_remote_process(process_name):
  try:
    manager = frida.get_device_manager()
    remote_frida = manager.add_remote_device(remote_socket)
    pid = remote_frida.get_process(process_name).pid
    print(f"Connected to process {process_name} with PID {pid} on remote host {remote_socket}")
    return remote_frida.attach(pid)
  except Exception as e:
    print(f"Failed to connect to remote process: {e}")
    sys.exit(1)

def load_script(script_path):
  with open(script_path, "r") as f:
    return f.read() 

def on_message(message, data):
    if message['type'] == 'send':
        log_file = open("tls_keys.log", "a")
        if message['payload']['type'] == 'keylog':
            log_file.write(message['payload']['data'] + "\n")
            log_file.flush()
            print(f"Key log line received: {message['payload']['data']}")
        log_file.close()



async def main():
  stop_event = asyncio.Event()
  script_source = load_script(script_path)
  
  attached_process = connect_to_remote_process(process_name)
  print("Loading script into remote process...")
  script = attached_process.create_script(script_source)
  try:
    script.on('message', on_message)
    script.load()
    await stop_event.wait()
  except KeyboardInterrupt:
    print("Detaching from process...")
  finally:
    attached_process.detach()
    print("Detached.")




if __name__ == "__main__":
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    print("Script terminated by user.")
  