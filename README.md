# CS216 Final Project - Psuedo Cache with dleft Hashing

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
~/Desktop/behavioral-model/tools/runtime_CLI.py < dleft.config
```
