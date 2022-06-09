import csv

nextHops = {}
with open('/rawbgptable.txt', 'r') as f:
  for line in f.readlines()[6:]:
    # print(line)
    # print(line.split())
    if len(line.split()) < 2:
      print(line)
      continue
    prefix = line.split()[1]
    if not '/' in prefix or prefix in nextHops:
      continue
    if not '*' in line.split()[0] or len(line.split()) < 3:
      # print(line)
      # print(line.split())
      continue
    nextHops[prefix] = line.split()[2]
print(len(nextHops))

nexthop_info = ['Prefix', 'Next Hop']
  
with open('bgptable.txt', 'w') as f:
    f.write("Prefix,NextHop\n")

    for key in nextHops.keys():
        f.write("%s,%s\n" % (key, nextHops[key]))
