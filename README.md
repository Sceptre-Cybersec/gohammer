[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Lifecycle:Maturing](https://img.shields.io/badge/Lifecycle-Maturing-007EC6)](https://github.com/bcgov/repomountie/blob/master/doc/lifecycle-badges.md)

# 🔨 GOHAMMER 🔨
## Overview
GOHAMMER is a general purpose web fuzzer written in go. This project is partly educational to help me learn and play around with the GO language, but it also serves as a more versatile web fuzzer than many other web fuzzers out there.  
  
After playing many hack the box machines and being frustrated with how hard it is to use hydra for password fuzzing and how inflexible many other web fuzzers are, I decided to make one of my own with some functionality that I wish other web fuzzers had.  

## Useful Functionality:
- Supports request files captured by BurpSuite for a more flexible and easier fuzzing experience
- Fuzz anything in the request, from headers to request methods to upload file content
- Retry failed requests, never miss out on finding an important file due to a bad connection
- DOS mode for stress testing
- *Coming soon:* User configuration yaml file containing your desired default configuration so you don't have to look through your command line history to find you favourite command line parameters to use

## Speed:
Gohammer performs similarily to other fuzzing tools like ffuf and can reach speeds of 1000 requests pers second using 60 threads on some hosts.
One thing to note while using the request file functionality is the `Connection: close` header. This header is there by default on most requests intercepted by
BurpSuite from your browser. It will slow down fuzzing because it tells the host to close each TCP connection after returning an HTTP response. 
For the fastest fuzzing using request files, remove the `Connection: close` header 

## Installation:
If you have GO installed:  
> go install github.com/wadeking98/gohammer@latest  

## Example Usage:
Simple web fuzzing:  
> gohammer -u http://127.0.0.1/@0@ -t 32 -e .txt,.html,.php /home/me/myWordlist.txt  
  
DOS mode:  
> gohammer -u http://127.0.0.1/ -t 32 -dos  
  
DOS mode with wordlist:  
> gohammer -u http://127.0.0.1/@0@ -t 32 -dos /home/me/myWordlist.txt
  
Bruteforce username and password:
> gohammer -u https://some.site.com/ -method POST -d '{"user":"@0@", "password":"@1@"}' -t 32 /home/me/usernames.txt /home/me/passwords.txt  
  
Bruteforce username and password using wordlists like a user:pass list  
> gohammer -u https://some.site.com/ -method POST -d '{"user":"@0@", "password":"@1@"}' -t 32 -no-brute /home/me/usernames.txt /home/me/passwords.txt  
  
Bruteforce username and password using request file:  
> gohammer -u https://some.site.com/ -f /home/me/Desktop/burpReq.txt -t 32 /home/me/usernames.txt /home/me/passwords.txt

## Created and Maintained by:
 <a href="https://app.hackthebox.com/users/254685"><img src="http://www.hackthebox.eu/badge/image/254685" alt="Hack The Box"></a>