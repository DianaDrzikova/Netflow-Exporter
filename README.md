# Netflow exporter

Netflow  exporter processes data in pcap format and creates Netflow records which are sent to Netflow collector.

## Usage

```
./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]

```
where:
```
-f file or STDIN
-c IP adress or hostname of Netflow collector
-a time stamp in seconds until active records are exported
-i time stamp in seconds until inactive records are exported
-m size of flow-cache

(All parameters are optional.)
```
example:
```
./flow -f input.pcap -c 192.168.0.1:2055
```
