# 100dayofcyber
Tracking my progress for 100 days learning something new daily....


## Day 1

Revisiting Computer Networks:
1. [Computer Networking Full Course - OSI Model Deep Dive with Real Life Examples](https://www.youtube.com/watch?v=IPvYjXCsTg8&t=2063s)
2. [OSI MODEL in easiest Way (best way to remember OSI layers and their role)](https://www.youtube.com/watch?v=Dppl6iA2G8Q&list=PLBGx66SQNZ8ZvdIoctCTWB3ApXQpQGEin&index=3)

--

Read book till pg 20 [zseanos methodology](https://www.bugbountyhunter.com/methodology/zseanos-methodology.pdf)

## Day 2

1. Read a good blog on BugBounty Methodology : [BUG HUNTING METHODOLOGY FOR BEGINNERS](https://infosecwriteups.com/bug-hunting-methodology-for-beginners-20b56f5e7d19)

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

[Basic server-side template injection (code context)](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)

[Server-side template injection using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)

[Server-side template injection in an unknown language with a documented exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)

[Server-side template injection with information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)

[Server-side template injection in a sandboxed environment](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment)

[Server-side template injection with a custom exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-a-custom-exploit)

## Day 6

1. Did recon on a private program.
2. Read Book: Protection of National Critical Information Infrastructure
https://www.vifindia.org/sites/default/files/Protection-of-National-Critical-Information-Infrastructure.pdf

## Day 7

1. [Completed all the Access control vulnerabilities labs from Portswigger Web-Security Labs.](https://portswigger.net/web-security/all-labs#access-control-vulnerabilities)
2. Read Blog on SSTI: [Handlebars template injection and RCE in a Shopify app](http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)
3. Stared working on my BugBounty Recon Tool : Designed Basic Workflow Diagram

## Day 8

1. [Read writeup: Delete any Video or Reel on Facebook (11,250$)](http://bugreader.com/social/write-ups-general-delete-any-video-or-reel-on-facebook-11-250--100965?fbclid=IwAR16bED_J9-xqmnVq98jSp-JIyrCAhtfnns7gsdMGpFpEVZKr6VL7tVPebA)
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
[Params — Discovering Hidden Treasure in WebApps](http://medium.com/geekculture/params-discovering-hidden-treasure-in-webapps-b4a78509290f)

## Day 12

Prepared Detailed Report of both the bugs (critical IDOR revealing PII & OTP-bypass) and submitted them.
Read Blog:  
[What I learnt from reading 220* IDOR bug reports](http://medium.com/@nynan/what-i-learnt-from-reading-220-idor-bug-reports-6efbea44db7)

## Day 13

1. Read: [Guide to Bug Bounty Hunting](https://github.com/bobby-lin/study-bug-bounty)
2. Did recon on an domain.

## Day 14

1. Found another IDOR on a domain.
2. Read Blog: 
[Swagger API](http://medium.com/@ghostlulzhacks/swagger-api-c07eca05441e)

## Day 15

