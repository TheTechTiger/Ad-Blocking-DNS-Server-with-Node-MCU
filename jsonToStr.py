file = open("config.json", 'r')
print(file.read().replace('\n', '').replace('  ', '').replace('"', '\\"'))
file.close()