# suri-tester

A perfectly adequate packet injecting program to test suricata artifact carving when you do not have access to the network flows. What a niche problem with probably 50 other solutions.

I generated this with AI then touched it up in about 15 minutes, ymmv. 

## Usage example

$ sudo go run suri-tester.go -f /etc/hosts -srcip 10.0.0.1 -srcport 10001 -dstip 10.0.0.2 -dstport 443 -url hXXp://specialsauces.com/test.txt -i lo  
go: downloading github.com/google/gopacket v1.1.19  
Packets injected successfully  


## Prompt

I am trying to test a suricata instance running on interface bond0 on a debian OS base. The test is conducted by injecting packets into bond0 that match criteria set by the user. The criteria are accepted as command line arguments in the format of:

-f \<file to inject\>   
-srcip <ip>   
-dstip <ip>   
-srcport <port>   
-dstport <port>   
-url <text>   
-i <interface to inject the packets onto>  

Please write a Golang program that runs on debian OS as an executable that takes these arguments, checks if the referenced file exists, reads it and injects packets onto the referenced interface as an HTTP RFC2616 formatted packet stream appearing to come from the srcip:srcport to the dstip:dstport with full simulated three way hand shake and relevant push and fin packets. 

The suricata instance is going to read this, so the tcp packets and handshake should be valid RFC793 format, the HTTP request should be valid RFC2616 format, and the file when extracted by Suricata from the packet capture stream should match the file provided.

I am using go version 1.21.0 and please generate a go.mod for this as well. 

requires: libpcap-dev