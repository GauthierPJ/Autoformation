import socket 
import time 

class IRC : 

    irc = socket.socket()

    def __init__(self) :
        #Define the socket 
        self.irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self,server,channel,port) : 
        #Connect to the server 
        print("Connecting to ", server,":",port)
        self.irc.connect((server,port))

        #Connect to IRC
        self.send("USER kalimero kalimero kalimero kalimero:python")
        self.send("NICK kalimero")
        self.send("KALISERV IDENTIFY kalimero pass")
        self.send("JOIN " + channel +"\n")
        time.sleep(.3)
    
    def send(self,msg) :
        #Send data 
        print("Sending : ", msg)
        self.irc.send(bytes(msg+"\n", "UTF-8"))

    def listen(self) : 
        time.sleep(1)
        # Get the response
        resp = self.irc.recv(8192).decode("UTF-8")
 
        return resp

    

    