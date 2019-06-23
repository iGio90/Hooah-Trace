import os

import frida
import json
import sys


def on_message(message, payload):
    if 'payload' in message:
        message = message['payload']
        print(message)
    else:
        print(message)


if not os.path.exists('compiled_agent.js'):
    print('use `npm install` to build the agent')
    exit(0)

d = frida.get_usb_device()
pid = d.spawn('com.my.target')
session = d.attach(pid)
script = session.create_script(open('compiled_agent.js', 'r').read())
script.on('message', on_message)
script.load()
d.resume(pid)
sys.stdin.read()
