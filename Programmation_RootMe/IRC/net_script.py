import time
from irc_class import * 
import base64
import re 
import time
import zlib

server = "212.83.153.145" #irc.root-me.org
port = 6667
channel = "#root-me_challenge"

irc = IRC()
irc.connect(server,channel,port)
time.sleep(0.5)
print("--------------------------------------")
irc.send("PRIVMSG Candy : !ep4")
res = irc.listen()
candy_res = list(res.split("\n"))[-2]
print(res)
print(candy_res)
hash = re.split(":",candy_res)[2]
print(hash)


my_response_bytes = base64.b64decode(hash)
my_response2 = zlib.decompress(my_response_bytes)
my_response = str(my_response2,"utf-8")
print(my_response)
irc.send("PRIVMSG Candy : !ep4 -rep "+ my_response)
print(irc.listen())





