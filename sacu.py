def sacumen(s):
    dictn={}
    c,f=s.find("cat"),s.find("msg")
    fd=s[f-1:].find(".")
   
    s2=s[f:fd+f]
   
    s1p=s[c:f-1].split(" ")
    s3p=s[f+fd+1:].split(" ")
   
    l=[s1p,s2,s3p]
    for i in l :
        if str(i).count(".")>2:
            for j in i:
                 k,v=j.split("=",1)
                 dictn[k]=v
        else:
           k,v=str(i).split("=",1)
           dictn[k]=v
    print(dictn)    
    return dictn
   
   
input_string="SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"

dict_o=sacumen(input_string)
print("{" + ",\n".join("{0}:{1}".format(k, v) for k, v in dict_o.items()) + "}")

