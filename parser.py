import os
import re

reg_open = re.compile("open\(\"([^\"]+)\",\s*([a-zA-Z_\|]+)[^\)]*\)")
file_permission = dict()

with open("./strace_passwd.log") as f :
    for line in f.readlines() :
        if len(line.split('=')) <= 1 :
            continue
        try :
            if int(line.split('=')[1]) < 0 :
                continue
        except :
            continue
        ret = line.split('=')[1].strip()
        pattern = line.split('=')[0].strip()
        res = reg_open.search(pattern)
        if res :
            print(res.group(1))
            permission_list = res.group(2).split('|')
            try :
                for p in permission_list :
                    file_permission[res.group(1)].add(p)
            except :
                file_permission[res.group(1)] = set(permission_list)


exe = set()
for k, v in file_permission.items() :
    print(k, v)
    exe = exe.union(v)
print(exe)


f = open("./passwd.perm", 'w+')
f_u = open("./passwd.perm.unload", 'w+')

line = ""
line_u = ""

for k, v in file_permission.items() :
    if "O_RDWR" in v :
        attr = "read_write"
    elif "O_WRONLY" in v :
        attr = "write-only"
    elif "O_DIRECTORY" in v :
        attr = "dir-write"
    elif "O_RDONLY" in v :
        attr = "read-only"
    else :
        continue

    line += "sudo setfattr -n security.mp4 -v %s %s\n" % (attr, k)
    line_u += "sudo setfattr -x security.mp4 %s\n" % (k)

f.write(line)
f_u.write(line_u)
    





