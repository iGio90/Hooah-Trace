"""
 Hooah Trace (htrace) - Copyright (C) 2019 Giovanni (iGio90) Rocca
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>
"""
import frida
import os
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
