# CS216 Final Project - Psuedo Cache with dleft Hashing

## Test simple model

Compile
```
p4c --target bmv2 --arch v1model --std p4-16 dleft.p4
```

Run
```
sudo python mininet/1sw_mininet.py --behavioral-exe ~/Desktop/behavioral-model/targets/simple_switch/simple_switch --json dleft.json
```

In second terminal:
```
~/Desktop/behavioral-model/tools/runtime_CLI.py < configs/pe_tab.config
~/Desktop/behavioral-model/tools/runtime_CLI.py < configs/prefix_tab.config
~/Desktop/behavioral-model/tools/runtime_CLI.py < configs/forward_tab.config
```

In first terminal, check connectivity:
```
h1 ping h4
```
with current tables, h1 h2 and h4 should all be reachable from each other. Using ping with h3, h5, and h6 will cause the command to hang.

## Test with bgp data

Create full prefix table:
```
cd format_bgp
./generate_config.sh
```
This generates the full bgp prefix_tab and saves it as `configs/bgp\_tab.config`.

