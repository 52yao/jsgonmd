# jsgonmd
调教AI写的一款用来找敏感信息泄露、未授权访问漏洞的工具

blacklist.txt中是黑名单，不扫描其中的域名
形式如下：
baidu.com
bdstatic.com
w3.org

whitelist.txt 是白名单

url.txt中是需要扫描的域名，每行一个

url_cookie.txt 是批量添加cookie的，如无则默认不带cookie
形式如下
http://example.com|||sessionid=abc123
http://test.com/api|||token=xyz789

直接执行python jsgonmd.py或者python3 jsgonmd.py就行，根据你的实际python环境来
