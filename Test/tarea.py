import re

txt = '<div class="name">Juan</div><div class="lastname">Jara</div>'
x = re.findall(r'<div class=".*?">(.*?)</div>', txt)
print(x[0] + x[1])