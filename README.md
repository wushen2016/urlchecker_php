# URLChecker

## Why do this?

Yes, yes, there have already been a lot about **tldextract**, url manipulation. These are a few things I ofen deal with:

- statistics about domain, hosts
- cdn removal
- url filtering about whitelist or blacklist

So, nothing new here, just a wrapper tool for little things.

## Statistics about domain, hosts

Suppose url.txt file contains your urls, looks like
```
www.georgiaupdate.gov.ge
president.gov.ge
kavkaz.org
hacker.ru
mfa.gov.ge
mod.gov.ge
kavkazcenter.com
```
or
```
111.shcangyou.cn/source/web/js/style.swf
apk.aotclouds.net/appcrawler/apk/com.youku.phone_97.apk
apk.aotclouds.net/appcrawler/apk/com.youloft.calendar_77.apk
apk.aotclouds.net/apk/5018523b-8e13-4c3d-9bc4-94af24580e7a.tdp
wic.fnrttz.com/list/20160921/%E5%BF%AB%E6%92%AD%E6%88%90%E4%BA%BA%E7%89%88v_5.0_crwt052_131811.apk
wic.fnrttz.com/list/20160921/%E5%A4%9C%E8%89%B2%E5%BF%AB%E6%92%AD_yylove118_125912.apk
wic.fnrttz.com/list/20160921/%E5%A4%9C%E8%89%B2%E5%BF%AB%E6%92%AD_yylove117_135615.apk
wic.fnrttz.com/list/20160921/%E5%A4%9C%E8%89%B2%E5%BF%AB%E6%92%AD_yylove118_165308.apk
```
Then URLChecker.doStat('urls.txt') will produce these files:
```
urls.txt_domain.txt                  # all the domains within urls.txt
urls.txt_domain_hosts.txt            # all domain and its hosts within urls
```
and urls.txt_domain_hosts.txt will looks like
```
hx7987.com	_domain_	4391	
	h002doql551w.hx7987.com
	ll6rifioytr7.hx7987.com
	np76yv5c09q1.hx7987.com
	t0mx7gs57tso.hx7987.com
	wifu9md44fwk.hx7987.com
	xw27mbcusv8y.hx7987.com
	...
	
xykernel.cn	_domain_	1687	
	cdn.xykernel.cn
	05031248441679005530.xykernel.cn
	05031451589489907363.xykernel.cn
	05031536453411976800.xykernel.cn
	...
```
according to the count of hosts under a specific domain, and these hosts' pattern, you will know whether need to pay more attention to the domain, hosts.

and you may find this:
```
.gov.pk    _invalid_
.sytes.net  _invalid_
an.         _invalid_
```
all these domains are invalid, there are within [PublicSuffix ](https://publicsuffix.org/list/effective_tld_names.dat). So if a domain startswith or endswith '.', it's invalid.

## URL Feature and Suspicious Domain

We want to define suspicious for DOMAIN (yes, not specific urls).

A few feature maybe helpful,  like cnt_hosts, cnt_urls, cnt_hosts / cnt_urls, etc.



## CDN Removal

```
112.17.13.201/files/3092000004AD6D23/shuocdn.108sq.cn/frontEnd/widget/integral_shop/3.0.0.4/integral_shop.zip
    => shuocdn.108sq.cn/frontEnd/widget/integral_shop/3.0.0.4/integral_shop.zip
    
10.0.28.2/qq.com/offline/100/142/354/20160113/comp_bsdiff_35803.zip
    => qq.com/offline/100/142/354/20160113/comp_bsdiff_35803.zip
```
Now cdn is used a lot, you may get urls with ip or other well known hosts as a prefix. 

Perhaps what you really care about is the real-host after cdn removal.

How to remove cdn?
```
1. find the last FQDN as the real host
2. if no FQDN exists, find the last ip as the real host
```
URLChecker.removeCDN(url)  will do this.

## URL Filtering about whitelist or blacklist

[alex_top_1m](http://s3.amazonaws.com/alexa-static/top-1m.csv.zip) is often used as a whitelist filter.

- white_direct: if **A.com** is within alex_top_1m, then we think that  **www.A.com** and **A.com** are white, they are directly in.

- white_indirect: if **A.com** is within alexa_top_1m, then we think that **other hosts except www.A.com and A.com** are white, but they are indirectly in.

baidu.com is in, but pan.baidu.com perhaps is used to properate malware, we should take care of this.

## Reference

https://github.com/golismero/golismero/tree/master/thirdparty_libs/tldextract
