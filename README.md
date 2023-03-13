# 100daysofcyber
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


## Day37

1. Read about SSRF.
2. Read Blog:
* [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](http://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
* [Dependency Confusion](https://dhiyaneshgeek.github.io/web/security/2021/09/04/dependency-confusion)
* [RCE via Dependency Confusion](https://systemweakness.com/rce-via-dependency-confusion-e0ed2a127013)


## Day38


1. Read about SQLi
2. Read Blogs: 
* [Burp Suite Extensions for Web Hunting](http://infosecwriteups.com/burp-suite-extensions-for-web-hunting-44ffc3b655aa)
* [From Zero to Adversary: APTs](http://socradar.io/from-zero-to-adversary-apts/)


## Day39

1. Read about FTP, SSH, SMTP DNS, and its pentesting.
2. Wrote Blog:
* [Uncovering Vulnerabilities: Overview of Web Application Penetration Testing](https://jaiguptanick.medium.com/uncovering-vulnerabilities-overview-of-web-application-penetration-testing-methodology-79691ea4ba3e)
3. Read Blog:
* [Pentest - Everything SMTP](http://luemmelsec.github.io/Pentest-Everything-SMTP/)


## Day40 


1. Revisted NFS,RDP,VNC, LDAP,WinRM,mssql,MySQL pentesting.
2. Read Blog:
* [A logic flaw in npm](http://elinfosec.com/2022/my-first-report-on-hackerone-a-logic-flaw-in-npm/)


## Day 41


1. Revisted Insecure File Uploads.
2. Tested a webapp.
3. Read blog:
* [Intro to the Content Security Policy (CSP)](http://blog.shiftleft.io/intro-to-the-content-security-policy-csp-c29266fa095f)
* [What is the Same-Origin Policy?](http://blog.shiftleft.io/what-is-the-same-origin-policy-f5e365adad7e)


## Day 42


1. Revisted XSS and javascript.
2. Read Blogs:
* [Top 25 XSS Bug Bounty Reports](http://corneacristian.medium.com/top-25-xss-bug-bounty-reports-b3c90e2288c8)
* [Uncle Rat's Ultimate XSS Beginner Guide](http://youtube.com/watch?v=5r4E4EJwNo0)


## Day 43

1. Revisited SNMP, SMB, MSRPC pentesting.
2. Reading Blog:
* [Top 25 XSS Bug Bounty Reports](https://corneacristian.medium.com/top-25-xss-bug-bounty-reports-b3c90e2288c8)


## Day 44

1. Reading Notes:
* [XSS (Cross Site Scripting)](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)

## Day 45

1. Solved DOM XSS Labs from Portswigger
2. Read Blog: 
* [Reflected XSS Leads to 3,000$ Bug Bounty Rewards from Microsoft Forms](http://infosecwriteups.com/reflected-xss-leads-to-3-000-bug-bounty-rewards-from-microsoft-forms-efe34fc6b261)
* [How i Hacked Scopely with “Sign in with Google”](http://ph-hitachi.medium.com/how-i-hacked-scopely-using-sign-in-with-google-298a9c166ad)

## Day 46

1. Watched networking tutorials (MAC,ARP)
2. Read blogs:
* [XSS, Flash Cross-Domain Policy, and CSRF Discovered on a Single Website](http://medium.com/@koroush.pub/xss-flash-cross-domain-policy-and-csrf-vulnerabilities-discovered-on-a-single-website-4948dff4ec11)

## Day 47


1. Did recon on a domain.
2. Read blogs:
* [Research | How can Local File Inclusion lead to RCE?](http://sl4x0.medium.com/research-how-can-local-file-inclusion-lead-to-rce-b3849d080929)
* [Two Factor Authentication Bypass On Facebook](http://medium.com/pentesternepal/two-factor-authentication-bypass-on-facebook-3f4ac3ea139c)

## Day 48


1. Did recon on a domain and read about 403 bypass.
2. Read blogs:
* [HOW TO LAUNCH COMMAND PROMPT AND POWERSHELL FROM MS PAINT](https://tzusec.com/how-to-launch-command-prompt-and-powershell-from-ms-paint/)
* [Story of a weird vulnerability I found on Facebook](https://amineaboud.medium.com/story-of-a-weird-vulnerability-i-found-on-facebook-fc0875eb5125)


## Day 49


1. Did ssl pinning bypass on Android and learning static analysis.
2. Read blogs:
* [DOM-Based XSS for fun and profit $$$!](https://medium.com/@haroonhameed_76621/dom-based-xss-for-fun-and-profit-bug-bounty-poc-f4b9554e95d)
* [API Misconfiguration - No Swag of SwaggerUI](https://shahjerry33.medium.com/api-misconfiguration-no-swag-of-swaggerui-9b43135346be)
* [How I identified & reported vulnerabilities in Oracle & the rewards of responsible disclosure:From Backup Leak to Hall of Fame](https://medium.com/@Parag_Bagul/how-i-identified-and-reported-vulnerabilities-in-oracle-and-the-rewards-of-responsible-43ee5fea457f)
* [From Error_Log File(P4) To Company Account Takeover(P1) & Unauthorized Actions On API](https://medium.com/@mohanad.hussam23/from-error-log-file-p4-to-company-account-takeover-p1-and-unauthorized-actions-on-api-35e45e43273a)


## Day 50


1. Revisited Linux Privilege Escalation from Notes 
2. Read blog:

* [AWS S3 CTF Challenges](https://n0j.github.io/2017/10/02/aws-s3-ctf.html)


## Day 51

1. Read CORS from Portswigger 
http://portswigger.net/web-security/cors
2. Read blog:
* [How I Was Able to Takeover User Accounts via CSRF on an E-Commerce Website](https://medium.com/@k_kisanak/how-i-was-able-to-takeover-user-accounts-via-csrf-on-an-e-commerce-website-1e2dcf740c3d)
* [Web 3.0 : The Future of Web and CyberSecurity](https://medium.com/@saitle74/web-3-0-the-future-of-web-and-cybersecurity-da9784657fe2)


## Day 52

1. Solved CORS labs from Portswigger 
2. Read blog:
* [How we made $120k bug bounty in a year with good automation](https://vidocsecurity.com/blog/2022-summary-how-we-made-120k-bug-bounty-in-a-year/)
* [Sensitive information disclosure through API](https://medium.com/@rynex797/sensitive-information-disclosure-through-api-750-bug-bounty-3161f0448249)


## Day 53

1. Researched and preparing list of most common interview questions in cybersecurity.
2. Read blog:
* [How I was able to bypass OTP code requirement in Razer](https://infosecwriteups.com/how-i-was-able-to-bypass-otp-token-requirement-in-razer-the-story-of-a-critical-bug-fc63a94ad572)
* [Bug Bounty Hunting 101, Js files Diving](https://medium.com/@haythamkarouata/bug-bounty-hunting-101-js-files-diving-4b1753fefb3d)


## Day 54

1. Solved box MrRobot on [TryHackMe](https://TryHackMe.com)
2. Read blog:
* [Account TakeOver using Resend OTP Functionality](https://infosecwriteups.com/my-first-bug-bounty-write-up-about-my-first-valid-finding-a-very-simple-ato-bug-in-a-target-who-1b8259f531d6)
* [WHAT IS THREAT MODELING?](https://henrikparkkinen.com/2023/01/23/what-is-threat-modeling/)
* [Watch out the links : Account takeover](https://akashhamal0x01.medium.com/watch-out-the-links-account-takeover-32b9315390a7)


## Day 55

1. Solved box Eavesdropper on http://tryhackme.com/room/eavesdropper
2. Read blog:
* [Facebook Information Disclosure  Bug $X000](https://medium.com/bug-bounty-hunting/facebook-bug-bounty-story-x000-for-an-information-disclosure-bug-f0c0d19d7815)
* [How I got a $2000 bounty with RXSS](https://p4n7h3rx.medium.com/how-i-got-a-2000-bounty-with-rxss-e6f45f987793)
* [Subdomain Enumeration Guide](https://sidxparab.gitbook.io/subdomain-enumeration-guide/)

## Day 56

1. Read blog/video:
* [Demystifying Cookies & Tokens!!](https://youtu.be/FZ_7xWZ03cQ)
* [SSRF That Allowed Us to Access Whole Infra Web Services and Many More](https://basu-banakar.medium.com/ssrf-that-allowed-us-to-access-whole-infra-web-services-and-many-more-3424f8efa0e4)
* [HubSpot Full Account Takeover in Bug Bounty](https://omar0x01.medium.com/hubspot-full-account-takeover-in-bug-bounty-4e2047914ab5)

## Day 57

1. Revisited Windows Privilege Escalation from Notes.
2. Read Blogs:
* [Guide to Permutations Subdomain Enumeration](https://rashahacks.com/guide-to-permutations-subdomain-enumeration/)
* [Give me a browser, I’ll give you a Shell](https://systemweakness.com/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
* [Reveal the Cloud with Google Dorks](https://infosecwriteups.com/uncover-hidden-gems-in-the-cloud-with-google-dorks-8621e56a329d)


## Day 58  

1. Revisited AD basics from notes and http://tryhackme.com
2. Read Blogs:
* [We Hacked GitHub for a Month : Here’s What We Found](https://blog.cyberxplore.com/we-hacked-github-for-a-month-heres-what-we-found/?fbclid=PAAabibqae5LAKjn27cUJIxdzUN3QGCdjf4WgWrZFMa2dzX_AJ1-A1H3zz6so)


## Day 59

1. Watched some networking lectures on YouTube.
2. Read Blogs:
* [The Science of Learning for Hackers](https://tcm-sec.com/the-science-of-learning-for-hackers/)
* [Why are you getting indexed by crawlers](https://github.com/tess-ss/writeups/blob/main/why-are-you-getting-indexed-by-crawlers.md)
* [I Cracked OSWE at 18](https://dhakal-ananda.com.np/non-technical/2023/02/09/oswe-journey.html)


## Day 60

Read Blogs:
* [WAF Bypass + XSS on The MOST Popular Movie Ticket website](https://medium.com/@tarang.parmar/xss-on-most-popular-entertaining-website-2fbf5a88df0f)
* [Simplify Your Web Application Testing with These Python Snippets](https://ashraful004.medium.com/simplify-your-web-application-testing-with-these-python-snippets-108f662595f8)
* [The Inside Story of Finding a Reverse Transaction Vulnerability in a Financial Application](https://medium.com/@rajauzairabdullah/the-inside-story-of-finding-a-reverse-transaction-vulnerability-in-a-financial-application-d73f9cd40f6f)
* [How I got $$$$ Bounty within 5 mins](https://medium.com/@p4n7h3rx/how-i-got-bounty-within-5-mins-f1448f6db9b5)


## Day 61

1. Learned some windows priv esc techniques.
2. Read Blogs:
* [Facebook bug: A Journey from Code Execution to S3 Data Leak](https://medium.com/@win3zz/facebook-bug-a-journey-from-code-execution-to-s3-data-leak-698b7d2b02ef)
* [LM, NTLM, Net-NTLMv2, oh my!](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4)
* [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

## Day 62

1. Configured AD for testing purpose.
2. Read Blogs:
* [Found an URL in android application source code which lead to IDOR](https://vengeance.medium.com/found-an-url-in-the-android-application-source-code-which-lead-to-an-idor-1b8768708756)
* [Hacking Apple:Two Successful Exploits and Positive Thoughts on their BB Program](https://blog.infiltrateops.io/hacking-apple-two-successful-exploits-and-positive-thoughts-on-their-bug-bounty-program-963efe7518f6)

## Day 63

1. Read Blogs:
* [Information Disclosure in Adobe Experience Manager](https://medium.com/@fattselimi/information-disclosure-vulnerability-in-adobe-experience-manager-affecting-multiple-companies-2fb0558cd957)
* [[1500$ Worth — Slack] vulnerability, bypass invite accept process](https://medium.com/@siratsami71/1500-worth-slack-vulnerability-bypass-invite-accept-process-8204e5431d52)

## Day 64


1. Read Blogs:
* [Let’s build a Chrome Spy Extension that steals everything](https://system32.ink/lets-build-a-chrome-spy-extension-that-steals-everything/)
* [Cybersecurity Top 10 Predictions for 2023](https://system32.ink/cybersecurity-top-10-predictions-for-2023/)
* [API 101: Securing the REST APIs](https://systemweakness.com/api-101-securing-the-rest-apis-e8b61196778f)


## Day 65


1. Read about Zerologon vuln & Updated OSCP boxes sheet.
2. Read Blogs:
* [Zerologon?? Easy Way To Take Over Active Directory](https://medium.com/mii-cybersec/zerologon-easy-way-to-take-over-active-directory-exploitation-c4b38c63a915)
* [CVE Hunting Tips #004](https://themayor11.medium.com/cve-hunting-tips-004-d998fed85da5)


## Day 66

1. Solved Tryhackme room: Active Directory
https://tryhackme.com/room/winadbasics
2. Read Blogs:
* [How did I found RCE on SHAREit which rewarded $$$ bounty](https://infosecwriteups.com/how-did-i-found-rce-on-shareit-which-rewarded-bounty-7d4196bf1b52)
* [How do I take over another user subdomain name worth $$$$](https://parkerzanta.medium.com/how-do-i-take-over-another-user-subdomain-name-worth-c66bb0c3f2f7)

## Day 67

1. Did recon on Target, found a bug as .git exposed.
2. Read Blogs:
* [Little bug, Big impact. 25k bounty](https://blog.prodefense.io/little-bug-big-impact-25k-bounty-9e47773f959f)
* [$10.000 bounty for exposed .git to RCE](https://medium.com/@levshmelevv/10-000-bounty-for-exposed-git-to-rce-304c7e1f54)
* [The Tale of a Command Injection by Changing the Logo](https://medium.com/@omidxrz/command-injection-by-changing-the-logo-2d730887ab6c)

## Day 68
1. Read Blogs:
* [Exploiting Auto-save Functionality To Steal Login Credentials](https://saadahmedx.medium.com/exploiting-auto-save-functionality-to-steal-login-credentials-bf4c7e1594da)
* [Account Takeover Worth $900](https://saadahmedx.medium.com/account-takeover-worth-900-cacbe10de58e)
* [Easy bounties and Hall of fame](https://medium.com/@milanjain7906/essay-bounties-and-hall-of-fame-540a7e4d4cb8)

