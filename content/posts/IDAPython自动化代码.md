---
title: "IDAPython自动化代码"
date: 2023-04-12T15:22:00+08:00
draft: false
---

#IDA

单个脚本执行

```jsx
C:\\Study\\BinaryAnalyse>C://Pwn/IDA/ida64.exe -LC:/mylog.log -c -A -S"C://Study/BinaryAnalyse/analyse.py" C://Study/BinaryAnalyse/datas/crackme0x03.exe
```

PS:Windows注意-S后的脚本名称需要添加双引号

-   c 表示对要分析的二进制文件生成一个新的IDB文件。 -A表示以autonomous模式运行，如果不加这个选项，则会弹出图形界面。 -S 制定要执行的 plugin script。

批量执行

```jsx
//analyse.py
import idc 
import idautils 
import idaapi 
from collections import defaultdict

def analysis():
    pass
	# 这里是分析的代码

def main():
    """
    控制器
    """
    idc.auto_wait()  # 等IDA分析完后才执行
    analysis()
    idc.qexit(0)  # 关闭IDA

if __name__ == "__main__":
    main()
```

批量

```jsx
//run.py
# -*- coding:utf-8 -*-

# =======Import =======
import os
import subprocess

#C:\\Study\\BinaryAnalyse\\datas
#C:\\Pwn\\IDA Pro 7.6
dir_path = "C://Study/BinaryAnalyse/datas/"  # 原始数据的文件夹
ida64_path = "C://Pwn/IDA/ida64.exe"  # ida64的路径
ana_file = "C://Study/BinaryAnalyse/analyse.py"  # 分析文件的路径

def run():
    for root, dirs, files in os.walk(dir_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            cmd = "{0} -LC:/mylog.log -c -A -S\\"{1}\\" {2}".format(ida64_path, ana_file, file_path)
            print(cmd)
            p = subprocess.Popen(cmd)
            p.wait()

if __name__ == "__main__":
    run()
```

# 参考链接

[IDAPython入门教程 基于IDA7.5_Python3 第一讲 简介与地址获取](https://www.cnblogs.com/iBinary/p/14642662.html)

[Porting from IDAPython 6.x-7.3, to 7.4](https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)

[IDAPython documentation](https://www.hex-rays.com/wp-content/static/products/ida/support/idapython_docs/)

[IDApython插件编写及脚本批量分析教程_y4ung-CSDN博客_ida python脚本](https://blog.csdn.net/qq_35056292/article/details/89421793)

[idapython使用笔记](https://wonderkun.cc/2020/12/11/idapython%E4%BD%BF%E7%94%A8%E7%AC%94%E8%AE%B0/)

[](https://www.keepnight.com/usr/uploads/2020/09/1365696735.pdf)[https://www.keepnight.com/usr/uploads/2020/09/1365696735.pdf](https://www.keepnight.com/usr/uploads/2020/09/1365696735.pdf)