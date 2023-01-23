# 100dayofcyber
Tracking my progress for 100 days learning something new daily....


## Day 1

Revisiting Computer Networks:
1. [Computer Networking Full Course - OSI Model Deep Dive with Real Life Examples](https://www.youtube.com/watch?v=IPvYjXCsTg8&t=2063s)
2. [OSI MODEL in easiest Way (best way to remember OSI layers and their role)](https://www.youtube.com/watch?v=Dppl6iA2G8Q&list=PLBGx66SQNZ8ZvdIoctCTWB3ApXQpQGEin&index=3)

--

Read book till pg 20 

[zseanos methodology](https://www.bugbountyhunter.com/methodology/zseanos-methodology.pdf)

## Day 2

1. Read a good blog on BugBounty Methodology : 
* [BUG HUNTING METHODOLOGY FOR BEGINNERS](https://infosecwriteups.com/bug-hunting-methodology-for-beginners-20b56f5e7d19)

2. Subdomain Takeover: https://github.com/EdOverflow/can-i-take-over-xyz

3. [How to take over a subdomain in Google Cloud DNS](https://binx.io/2022/01/27/how-to-take-over-a-subdomain-in-google-cloud-dns/)

4. Found a subdomain takeover in a private Bugbounty Program

## Day 3

1. Learing Google Cloud Platform from Youtube: https://www.youtube.com/playlist?list=PLBGx66SQNZ8YWRUw6yicKtD4AIpUl_YiJ

2. Tried exploiting subdomain takeover but google cloud not assigning the desired namesever shard while creating DNS Zone. Build script to create Zones recursively but it is randomly assigning only -a1 and -b1, But I need ns-cloud-d1.googledomains[.]com.

## Day 4

1. Did recon on a Private Bug Bounty Program.

2. Read on SSTI from [Portswigger Labs](https://portswigger.net/web-security/server-side-template-injection)

3. Solved [Basic server-side template injection](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic)

## Day 5

Solved all the server-side template injection (SSTI) labs from Portswigger Web-Security Labs.

* [Basic server-side template injection (code context)](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)

* [Server-side template injection using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)

* [Server-side template injection in an unknown language with a documented exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)

* [Server-side template injection with information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)

* [Server-side template injection in a sandboxed environment](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment)

* [Server-side template injection with a custom exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-a-custom-exploit)

## Day 6

1. Did recon on a private program.
2. Read Book: 
* [Protection of National Critical Information Infrastructure](https://www.vifindia.org/sites/default/files/Protection-of-National-Critical-Information-Infrastructure.pdf)

## Day 7

1. Completed all the [Access control vulnerabilities labs from Portswigger Web-Security Labs.](https://portswigger.net/web-security/all-labs#access-control-vulnerabilities)
2. Read Blog on SSTI: [Handlebars template injection and RCE in a Shopify app](http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)
3. Stared working on my BugBounty Recon Tool : Designed Basic Workflow Diagram

## Day 8

1. Read writeup: [Delete any Video or Reel on Facebook (11,250$)](http://bugreader.com/social/write-ups-general-delete-any-video-or-reel-on-facebook-11-250--100965?fbclid=IwAR16bED_J9-xqmnVq98jSp-JIyrCAhtfnns7gsdMGpFpEVZKr6VL7tVPebA)
2. Watched the First Half playlist by [technical guftgu on CCNA for revisiting networking concepts](http://youtube.com/playlist?list=PLBGx66SQNZ8ZvdIoctCTWB3ApXQpQGEin)

## Day 9

1. Solved Portswigger Labs:Authentication Bypass
2. Read Blogs:
* [Fastly Subdomain Takeover $2000](http://infosecwriteups.com/fastly-subdomain-takeover-2000-217bb180730f)
* [Bypass IP Restrictions with Burp Suite](http://medium.com/r3d-buck3t/bypass-ip-restrictions-with-burp-suite-fb4c72ec8e9c)
* [OTP Leaking Through Cookie Leads to Account Takeover](http://medium.com/@sharp488/access-any-owner-account-without-authentication-auth-bypass-2fa-bypass-94d0d3ef0d9c)
* [Determining your hacking targets with recon and automation](https://labs.detectify.com/2022/12/07/determining-your-hacking-targets-with-recon-and-automation/)

## Day 10

1. Did recon on a bugbounty target.
2. Read Blogs:
* [OTP Bypassing and Vulnerabilities from E-Mail fields](https://akash-venky091.medium.com/otp-bypassing-and-vulnerabilities-from-e-mail-fields-a5c326efa605)
* [$350 XSS in 15 minutes](https://therceman.medium.com/350-xss-in-15-minutes-dcb74ad93d5f)

## Day 11

1. Found critical IDOR revealing PII and OTP bypass on a domain
2. Read blog:

* [Params — Discovering Hidden Treasure in WebApps](http://medium.com/geekculture/params-discovering-hidden-treasure-in-webapps-b4a78509290f)

## Day 12

Prepared Detailed Report of both the bugs (critical IDOR revealing PII & OTP-bypass) and submitted them.

Read Blog:  
* [What I learnt from reading 220* IDOR bug reports](http://medium.com/@nynan/what-i-learnt-from-reading-220-idor-bug-reports-6efbea44db7)

## Day 13

1. Read: [Guide to Bug Bounty Hunting](https://github.com/bobby-lin/study-bug-bounty)
2. Did recon on an domain.

## Day 14

1. Found another IDOR on a domain.
2. Read Blog: 
[Swagger API](http://medium.com/@ghostlulzhacks/swagger-api-c07eca05441e)

## Day 15

1. Solved CORS labs from Portswigger Web Security Academy 

2. Read blogs
* [Bypassing SSRF Protection](http://medium.com/@tobydavenn/bypassing-ssrf-protections-45e5e3ac31e9)
* [Oauth misconfiguration == Pre-Account Takeover](http://0xraminfosec.medium.com/oauth-misconfiguration-pre-account-takeover-988a2905a900)
* [Authentication Bypass,File Upload,Arbitrary File Overwrite](https://medium.com/@h4x0r_dz/23000-for-authentication-bypass-file-upload-arbitrary-file-overwrite-2578b730a5f8)

## Day 16

1. Did enumeration on a domain.
2. Read about Business logic vulnerabilities:
http://portswigger.net/web-security/logic-flaws

## Day 17

1. Tried exploiting OTP bypass on a BugBounty program
2. Solved some of the Business logic vulnerabilities from portswigger labs

## Day 18

Read Blogs: 
1. [SSRF leading to AWS keys leakage](http://an0nymisss.blogspot.com/2023/01/ssrf-leading-to-aws-keys-leakage-bug.html?m=1)
2. [Bypass Apple’s redirection process with the dot (“.”) character](http://infosecwriteups.com/bypass-apples-redirection-process-with-the-dot-character-c47d40537202)
3. [Cross site leaks](http://gupta-bless.medium.com/ways-to-exploit-cross-site-leaks-4ab48f0a056a)
4. [What is Doxing?](http://system32.ink/what-is-doxing-is-doxing-illegal/)
5. [$500 in 5 minutes
(broken link automation)](http://medium.com/@coffeeaddict_exe/500-in-5-minutes-45977e89a337)

## Day 19

1. Did recon on a domain
2. Read blogs
* [Using Nuclei template to find subdomain takeover](http://hacklido.com/blog/198-how-i-found-130-sub-domain-takeover-vulnerabilities-using-nuclei)
* [Automated and Continuous Recon/Attack Surface Management — Amass Track and DB](http://medium.com/@nynan/automated-and-continuous-recon-attack-surface-management-amass-track-and-db-fabcaffce3c3)

## Day 20

1. Solved labs of Bussiness logic flaws Portswigger.
2. Read Blogs:

* [Blind XSS in Email Field; 1000$ bounty](http://yaseenzubair.medium.com/blind-xss-in-email-field-1000-bounty-b19b25a23236)
* [Web-Cache Poisoning $$$? Worth it?](http://yaseenzubair.medium.com/web-cache-poisoning-worth-it-e7c6d88797b1)

## Day 21


Read Race Conditon Blogs:
* [What Is a Race Condition?](https://www.veracode.com/security/race-condition)
* [RACE Condition vulnerability found in bug-bounty program](https://pravinponnusamy.medium.com/race-condition-vulnerability-found-in-bug-bounty-program-573260454c43)
* [Hacktricks.xyz Race Condition](https://book.hacktricks.xyz/pentesting-web/race-condition)

## Day22 


1. Working on the recon tool.
2. Read blog:
* [Broken Authentication and Session Management Tips](http://hacklido.com/blog/207-broken-authentication-and-session-management-tips)

## Day23

1. Working on the recon tool
2. Read blogs:
* [How I Found AWS API Keys using “Trufflehog” and Validated them using “enumerate-iam” tool](http://0xkayala.medium.com/how-i-found-aws-api-keys-using-trufflehog-and-validated-them-using-enumerate-iam-tool-cd6ba7c86d09)
* [Subdomain takeover on GitHub Pages using Google Dorks](http://hacklido.com/blog/212-how-to-find-sub-domain-takeover-on-github-pages-using-google-dork)

## Day24

1. Solved remaining bussiness logic vulnerability labs from Portswigger Web Security Academy.
2. Read blog:
* [How I fuzz and hack APIs?](http://rashahacks.com/how-i-fuzz-and-hack-api/)

## Day25


1. Tested API on an edtech website exposing PII.
2. Read Blog:
*  [Everything about Cookie and Its Security](http://medium.com/@capturethebugs/everything-about-cookie-and-its-security-5edb55b0750d)


## Day26


1. Revisted notes.
2. Read blogs:
* [How I Earned $1000 From Business Logic Vulnerability](http://andika-here.medium.com/how-i-earned-1000-from-business-logic-vulnerability-account-takeover-f03547950c82)
* [Seven Common Ways To Bypass Login Page](http://medium.com/@uttamgupta_/seven-common-ways-to-bypass-login-page-a023d9dd073c)
* [Password Stealing from HTTPS Login Page & CSRF Protection bypass via XSS](http://medium.com/dark-roast-security/password-stealing-from-https-login-page-and-csrf-bypass-with-reflected-xss-76f56ebc4516)


## Day27


1. Working on the recon tool.
2. Read blog:
* [Horizontal domain correlation](http://ghostlulz.com/horizontal-domain-correlation)
* [How to pull off a successful NoSQL Injection attack](http://infosecwriteups.com/nosql-injection-8732c2140576)
* [OWASP NoSQL(Fun with Objects and Arrays)](http://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf)


## Day28


1. Completed Udemy Course on "[Cybersecurity Incident Handling and Response](http://udemy.com/course/cyber-security-incident-handling-and-response/)"

2. Read blog:
* [A Story of a $750 Broken Access Control](http://cyberweapons.medium.com/a-story-of-a-700-broken-access-control-2ec2c21f6ffe)

* [XSS via Chat bot — Cloudflare Bypassed](http://cyberweapons.medium.com/xss-via-chat-bot-cloudflare-bypassed-212cf5ee3e55)


## Day29


1. Read blog:
* [She hacked a billionaire, a bank and you could be next](http://youtube.com/watch?v=8MIIeIa25tE)
* Flipper Zero:
    * http://youtube.com/watch?v=VF3xlAm_tdo
    * http://youtube.com/watch?v=yKTzek8EZ4E
* [Grey Areas of Bugbounty World](http://medium.com/@know.0nix/grey-areas-of-bugbounty-world-5dd794c697a3)


## Day30


1. Working on Enum Tool.
2. Read blog:
* [How to spoof e-mails. (DMARC, SPF, and Phishing)](http://medium.com/bugbountywriteup/how-to-spoof-e-mails-dmarc-spf-and-phishing-5184c10679a0)
* [How I could have read your confidential bug reports by simple mail?](http://medium.com/bugbountywriteup/how-i-could-have-read-your-confidential-bug-reports-by-simple-mail-cfd2e4f8e25c)
* [Destroying the Scammers Portal — SBI Scam](http://infosecwriteups.com/destroying-the-scammers-portal-sbi-scam-2169e21adeeb)


## Day31

1. Working on Enum Tool.
(implemented keylogger and discord webhooks)
2. Read blog:
* [Tips for BAC and IDOR Vulnerabilities](http://infosecwriteups.com/tips-for-bac-and-idor-vulnerabilities-8a3e58f79d95)
* [Kerala Police YouTube Takeover Incident Analysis](http://blog.initcrew.com/kp-hack/)

## Day32

1. Working on the enum tool:
(Implemented screenshot,system info gathering functionality)
2. Read blog:
* [SSH key injection in Google Cloud Compute Engine](http://blog.stazot.com/ssh-key-injection-google-cloud/)

## Day33

Read Blog:
* [Finding and Exploiting Unintended Functionality in Main Web App APIs](http://bendtheory.medium.com/finding-and-exploiting-unintended-functionality-in-main-web-app-apis-6eca3ef000af)

## Day34


1. Read Guide: [zseanos methodology](https://www.bugbountyhunter.com/methodology/zseanos-methodology.pdf)
(pg: 20-30)
2. Read Blog: 
* [Full Company Building Takeover](http://infosecwriteups.com/company-building-takeover-10a422385390)
* [PHP Type Juggling Vulnerabilities](https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09)

## Day35


1. Revisited Notes of Enumerating Various Services in Pentesting
2. Read Blog:
* [Bypassing Captcha Like a Boss](http://medium.com/bugbountywriteup/bypassing-captcha-like-a-boss-d0edcc3a1c1)
* [Git security audit reveals critical overflow bugs](https://portswigger.net/daily-swig/git-security-audit-reveals-critical-overflow-bugs)


## Day36

1. Solved tryhackme room:
* Intro to Offensive Security
* Web Application Security
* Intro to Digital Forensics
2. Read Blog:
* [3 Step IDOR in HackerResume](http://medium.com/@swapmaurya20/3-step-idor-in-hackerresume-a365f2632996)
* [Hacking Government-Millions of Death-Certificate](http://debprasadbanerjee502.medium.com/hacking-government-millions-of-death-certificate-easy-2c28e67e22c9)
