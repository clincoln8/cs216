# CS 216 Project
Kayla Buki, Christie Ellks, Soumya Uppuganti, Peter Wang

## Binary Search
`binary_search.p4` contains the data plane P4 code for forwarding based on staged binary search in the MyIngress component 
- **current status**: compiles, but functionality has not been tested

`commands.txt` contains the contents of the tables that are loaded by mininet (psuedo control plane)

### Commands
compile: 
`p4c --target bmv2 --arch v1model --std p4-16 binsearch.p4`

run bmv2 and mininet:
```
cd behavioral-model/mininet # navigate to mininet folder in behavorial-model repo
sudo python 1sw_demo.py --behavioral-exe ../targets/simple_switch/simple_switch --json {path to this repo}/binsearch.json
```
in second terminal:
```
cd behavorial-model/simple_switch
./runtime_CLI < {path to this repo}/commands.txt 
```
