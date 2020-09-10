# dumbnsspoof
dns spoofing tool

dumbns is a DNS spoofing tool, the attack wont do MITM by it self, you need to do it by yourself, this script listen for DNS traffic and return a response base on the given config, if no requested domain was ask the script will drop the packet.

## legal
any use of this script on unauthorized networks make the user the responsible and not the developer

## problem with DNSspoofing && dumbnsspoof
most systems will store DNS data in a file called HOSTS file so they wont need to go thorug the DNS process again, so this wont always work first time
on visited site, the script does not support DNS tcp connections<br><br>

if you gonna try to redirect a domain to IP that runs multi domains, most of the time you will get 404 error because you redirecting
a domain that the IP does not support

## problem with node http-server
if you are using (for tests) node `http-server`, the script will send the correct spoofed ip but some times the `http-server` wont complete the 3-way handshake
this is a problem with the `http-server` and not the script, to fix it restart the server and refresh the browser, I recommend alternative for `http-server` 

## config file
when running dumbns it will look for a config file (default name "dumbns.config.json" can be changed with `--config`), the config file is in JSON format

|    name   |  requested value  |                                                                                description                                                                               |
|:---------:|:-----------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|    ttl    |        int        |                                                for how much time the DNS response is valid to be stored in the HOSTS file                                                |
|  dns_mac  |       string      | if added it will optimize the filtering, if added with -e3 it will optimize the filtering and the script will be able to send the real dns-server the ICMP type 3 packet |
|   echo3   |        bool       |                                            send ICMP type3 code 3 to the real dns-server when match found (requires `dns_mac`)                                           |
|  targets  |        list       |                                                                            targets list of IP                                                                            |
|  exclude  |        list       |                                                          exclude target IP, cannot be set when `targets` are set                                                         |
|  domains  | dict (aka js obj) |                                                     the key is the attacker IP, the value is a list or regex domains                                                     |
| interface |       string      |                                                                        the interface to listen on                                                                        |

## MITM with dumbns
for home networks a dns request is send to the gateway and then the gateway will send the request to a real DNS server, or some computers have a static DNS ip <br>
but all the traffice goes through the gateway so we need to do MITM attack to see outgoing DNS packets

for this example I will use `arpspoof` from here => https://github.com/byt3bl33d3r/arpspoof <br>

```sh
foo@foo:~$ sudo arpspoof -r -i eth0 -t <target-ip> <gateway ip>
```
this will make the target think you are the gateway and now we will be able to see the outgoing data of the target

```json
# dumbns.config.json
  {
    "targets": ["<target-ip>"],
    "domains": {
      "<attacker-ip>": [
        "google.com",
        "facebook.com"
      ]
    },
    "interface": "eth0"
  }
```
now that we have the config lets run the attack

```sh
foo@foo:~$ sudo python3 dumbnsspoof.py
```


