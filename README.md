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
- Transforms: mutate your wordlist on the fly using tansform functions
- *Coming soon:* User configuration yaml file containing your desired default configuration

## Speed:
Gohammer performs similarily to other fuzzing tools like ffuf. 
Some differences have been noted when fuzzing through a VPN, Gohammer seems to perform slightly better than ffuf when both are running though a VPN, but slightly worse outside of a VPN.
One thing to note while using the request file functionality is the `Connection: close` header. This header is there by default on most requests intercepted by
BurpSuite from your browser. It will slow down fuzzing because it tells the host to close each TCP connection after returning an HTTP response. 
For the fastest fuzzing using request files, remove the `Connection: close` header 

## Errors, Triggers, Transforms & Other Functionality
Gohammer introduces a number of unique functionalities that can make testing web applications much easier.
However some of these concepts can be fairly complicated and the tool's help message isn't always the best spot
to explain them:
### Errors
In many other fuzzing tools users can't configure what is and isn't an error. In these other fuzzing tools the response 
is considered an error if it is something like a gateway timeout, usually a 503 or 504 status code. Usually users can't
tell the fuzzing tool what is and isn't an error, however, Gohammer does allow this configuration. Users can specify 
which responses to treat as an error my using -emc to match status codes -emr to match response content and many
other flags in the error section of the tool's help message. Responses matching these flags are then repeated up to
the number of times specified in the -retry flag. This recently came in handy when I was using fireprox for a password audit on a client's web portal. For some reason fireprox would sometimes return an intermittent error message. Using
the error functionality I was able to match and retry requests that triggered this intermittent error.
### Triggers
Gohammer allows the user to execute OS commands on certain response criteria. Similar to the error flags a user can
specify which responses they want to trigger their OS command by using flags like -tmc to match response codes -tmr to
match response content, etc. The content of the -ontrigger flag runs as an OS command once the response matches the
specified flags. The response content is passed to the command line context via the RES environment variable, users
can access this variable through their -ontrigger command. One application someone might use this for is to build
a poor-man's rate limit bypasser like fireprox without needing an aws account. Users can configure the trigger to
match rate-limit responses (status code 429) and switch their IP address using tor or VPN packages through the
-ontrigger flag. 
### Multi Requests
Sometimes making an action on a site requires something like a CSRF token generated in the html form. A user needs
to first send a GET request to retrieve the CSRF token before they can submit an html form and take an action.
Gohammer allows users to specify multiple requests in a sort of "request chain". Adding multiple HTTP request file
flags (-f) creates a chain of requests where the requests are sent one after the other. The response from previous
requests can be accessed by any other later request using the `prevResponse(index)` transform. The index selects the
specified response from the chain 0 for the first request, 1 for the second etc. Transforms are explained in greater
detail in the next section. The configuration to get and send the CSRF token would look something like this:
> gohammer -u 'https://some-site.com' -f get-csrf-req.txt -f do-action-req.txt -transform 'regex(prevResponse(0),\`Csrf-Token: (.*)\`,1)' /home/user/usernames.txt /home/user/passwords.txt
### Transforms
Transforms allow users to dynamically inject content into their HTTP requests using some predefined function. There is a
list of current supported transforms in the tool's help message but I've included it here in greater detail as well.
- b64Encode(string): takes a single string and returns a base 64 encoding of the string
- b64Decode(string): takes a single base64 encoded string and returns the decoded string
- urlEncode(string): takes a single string and encodes unsafe url characters
- urlDecode(string): takes a single url encoded string and returns the decoded string
- concat(string, string, string, ...): takes any number of strings and returns all the strings joined together. Note that concat is only needed when joining the output of a function to another function, or to a string. It is not needed to join two strings
- randStr([int,[int]]): generates a random string of letters and numbers. Optionally specify an minimum and maximum length. Default is 10, 65
- randInt([int,[int]]): generates a random integer. Optionally specify an minimum and maximum int. Default is 0, MAX_INT64
- randBytes([int,[int]]): generates a random string of bytes. Optionally specify an minimum and maximum length. Default is 10, 1024
- regex(string, string, [int]): runs a regular expression and returns the specified capture group. Note that special characters still need to be escaped unless you use a string literal \`my-string\`.
- prevResponse(int): returns the content of a previous response when using multiple request files. An index of 0 selects the response from the first request file.
  
To use any of these transform functions use the -transform flag and then use @t0@ to use the computer value in any
HTTP request. Multiple transforms are supported, is which case use the -transform flag multiple times and @t0@, @t1@, etc
for the computed values.

## Installation:
If you have GO installed:  
> go install github.com/Sceptre-Cybersec/gohammer@latest  

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

Bruteforce HTTP Basic Auth using transforms:
> gohammer -u https://some.site.com/ -H 'Authorization: Basic @t0@' -transform 'b64Encode(@0@:@1@)' -t 32 /home/me/usernames.txt /home/me/passwords.txt

Rate-limit Bypass
> proxychains gohammer -u https://some.site.com/ -f req.txt -tmc 429 -trigger-requeue -ontrigger 'service tor reload && sleep 5' /home/me/usernames.txt /home/me/passwords.txt

Bruteforce with CSRF token
> proxychains gohammer -u https://some.site.com/ -f ger-csrf-req.txt -f req.txt -transform 'regex(prevResponse(0), `Csrf-Token: (.*)`, 1)' /home/me/usernames.txt /home/me/passwords.txt
  

## Please feel free to contribute to this project, pull requests are welcome!

## Created and Maintained by:
 <a href="https://app.hackthebox.com/users/254685"><img src="http://www.hackthebox.eu/badge/image/254685" alt="Hack The Box"></a>