# TCP Connection Analyzer (Wireshark clone)
### By: Luke Edwards
### Date: 2024-09-27

## General
## Table of Contents
1. [General](#general)
2. [Installation](#installation)
    1. [Prerequisites](#prerequisites)
3. [File structure](#file-structure)
4. [Usage](#usage)
5. [Troubleshooting](#troubleshooting)
6. [Input and Output expectations](#input-and-output-expectations)
    1. [Input](#input)
    2. [Output](#output)

## Installation
### Prerequisites
- Python (minimum 3.0)
- Libraries
    - argparse
    - statistics
    - struct
    - sys
- Custom libraries
    - packetSplit, functions to generate different TCP segments into complete packet packages
    - connectionSort, functions to generate a connection dictionary that associates packets to unique connections
    - packet_struct, defines structs for packet headers and data segments

## File structure

The following files are included in the zip:
- tcp_shark.py
- connectionSort.py
- packet_struct.py
- Sample Capture File.cap (general TCP connection sample)
- README.txt (not required for compilation)

## Usage

1. Use CLI to file directory containing WebTester.py
```
cd Path/to/the/file 
```

2. Put the capture file you are trying to test within the folder that contains the other files.

Directory should look like the following:
> folder_name
    > connectionSort
    > packet_struct.py
    > packetSplit.py
    > tcp_shark
    > <your .cap file here>
    > README.md (but not a required file)

3. Run the file using the following format:
```
python3 tcp_shark.py <.cap file>
```
Note, <.cap file> should be replaced with the cap file you are trying to test.

## Troubleshooting

1. 
```
Usage: python3 WebTester.py '<.cap file>'
```

### Solution:
- Ensure that your cap file is actually in the directory among the other files (see [Usage])
- Make sure that you are surrounding your file name with quotations (see [Usage])

2. S
```
Input file is not .cap, terminating...
```

### Solution:
- Ensure that the file you are passing in .cap file.

3. 
Data is unexpected and/or not returned in an expected way (i.e some fields in d are 0)

### Solution:
- Make sure that your .cap file contains TCP connections and there is more than 1 complete connection, as it will only consider packets that satisfy these conditions.
    - This can be verified using a service such as WireShark or other cap file analyzer.


# Input and Output expectations:

## Input
The program is able to handle any .cap files, but will only consider packets using TCP protocol.

## Output

Output from a successful compilation will resemble the following example:
```
a) Returns a total number of connections found
b) Returns a summary of each connection, complete TCP connections have supplementary data, including packets and data sent/received, as well as connection duration.
c) Returns the total number of complete TCP connections, reset connections, connections that were still open at the end of the trace capture, and connections established before the trace.
d) Returns the average packet RTT, connection duration, window size, and packets sent/received, only complete TCP connections are considered.
```
