original_data = open('bgptable.txt', 'r')
lines = original_data.readlines()

new_data = open('formatted_bgptable.txt', 'a')

reversed_lines = list(reversed(lines))
formatted_reversed_lines = []
prev_prefix = reversed_lines[0]

for line in reversed_lines:
    prefix = line.split('/')[0]
    length = line.split('/')[1].split(',')[0]
    nexthop = line.split('/')[1].split(',')[1]

    exists_longer_prefix = "0"
    if(prefix == prev_prefix):
        exists_longer_prefix = "1"
    prev_prefix = prefix
        
    hex_prefix = " 0x"
    for i in range(4):
        cur_hex = hex(int(prefix.split('.')[i])).split('x')[1]
        if(len(cur_hex) == 1):
            cur_hex = '0' + cur_hex
        hex_prefix = hex_prefix + cur_hex.upper()

    hex_nexthop = " 0x"
    for i in range(4):
        cur_hex = hex(int(nexthop.split('.')[i])).split('x')[1]
        if(len(cur_hex) == 1):
            cur_hex = '0' + cur_hex
        hex_nexthop = hex_nexthop + cur_hex.upper()

    formatted_string = "table_add process_dleft.prefix_tab process_dleft.lpm_table_match" + hex_prefix + "/" + length + " => " + length + " " + exists_longer_prefix + hex_nexthop + "\n"
    formatted_reversed_lines.insert(0, formatted_string)

for line in formatted_reversed_lines:
    new_data.write(line)

original_data.close()
new_data.close()