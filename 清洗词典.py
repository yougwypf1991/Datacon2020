with open(r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\word.txt') as file:
    data = file.readlines()
print(type(data))

for word in data[200:]:
    if len(word) < 4 or word == 'com\n':
        print(word)
        data.remove(word)

with open(r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\words.txt', 'a') as f:
    for domain in data:
        f.write(domain)