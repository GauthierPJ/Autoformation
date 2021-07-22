import requests

def suite_res(a,plus_ou_moins,b,u_0,rang) : 
    n = 0
    u_n = u_0
    print(text_rep)
    print(a)
    print(plus_ou_moins)
    print(b)
    print(u_0)
    print(rang)
    while(n < rang) : 
        u_n = (a + u_n) + (n*b) if(plus_ou_moins) else (a + u_n) - (n*b)
        n+=1
    return u_n

s = requests.Session()
response = s.get('http://challenge01.root-me.org/programmation/ch1/')
text_rep = response.text

index = text_rep.find("[")+2

a,b,plus_ou_moins,u_0,rang = "","","","",""

#Trouver a
while(text_rep[index] != " ") : 
    a += text_rep[index]
    index+=1
index+=2
#Lecture + ou - 
while(text_rep[index] != "+" and text_rep[index] != "-") :
    index+=1
plus_ou_moins = text_rep[index]
#On se rend à b
while(text_rep[index] != "*") : 
    index +=1
index+=2
#Lecture b
while(text_rep[index] != " ") : 
    b += text_rep[index]
    index +=1
#On se rend à u0
while(text_rep[index] != "=") :
    index+=1
index +=2
#Lecture u0
while(text_rep[index] != "<") :
    u_0 += text_rep[index]
    index +=1
u_0 = u_0.replace("\n","")
#On se rend au rang cherché
while(text_rep[index] != "U") : 
    index+=1
index+=6
#Lecture rang
while(text_rep[index] != "<") :
    rang += text_rep[index]
    index+=1

bool = (plus_ou_moins == "+")

res = suite_res(int(a) , bool ,int(b),int(u_0),int(rang))
print("res = ", res)
final_resp = s.get("http://challenge01.root-me.org/programmation/ch1/ep1_v.php?", params={"result" : res})
print(final_resp.text)



    
