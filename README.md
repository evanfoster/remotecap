## remotecap

A small utility to perform tcpdump packet captures remotely and stream the results back via SSH. It supports capturing from multiple machines at once using asyncio and can optionally use [uvloop](https://github.com/MagicStack/uvloop) for increased performance. Additionally, it displays the capture file sizes and growth rates so you know how much data you're getting.

### Installation
remotecap has two hard dependencies: `aiofiles` and `asyncssh`. Optional dependencies are:

* [`bcrypt`](https://github.com/pyca/bcrypt/) enables SSH private keys (**strongly recommended**)
* [`libnacl`](https://github.com/saltstack/libnacl) to support more cryptographic options
  * `libnacl` requires [`libsodium`](https://github.com/jedisct1/libsodium) which you should install via your distro's package manager
* [`uvloop`](https://github.com/MagicStack/uvloop) for increased performance

To install all hard and optional dependencies (excluding libsodium), you would run this command:

```bash
pip install aiofiles 'asyncssh[bcrypt,libnacl]' uvloop
```

Once you have all the necessary dependencies, clone this repo and run `python remotecap.py`

### Usage
```text
usage: remotecap [-h] -w FILENAME [-f FILTER] [-k KEY] [-i INTERFACE]
                 [-p PASSWORD] [-s PACKET_LENGTH] [-u USER]
                 [-r REFRESH_INTERVAL]
                 machines [machines ...]

positional arguments:
  machines              Machines to perform the capture on. Required.

optional arguments:
  -h, --help            show this help message and exit
  -w FILENAME, --filename FILENAME
                        File to write to if performing the capture on a single
                        machine. Folder to put captures in if capturing from
                        multiple machines. Required. (default: None)
  -f FILTER, --filter FILTER
                        Filter to pass to tcpdump on the remote machine(s).
                        (default: not port 22)
  -k KEY, --key KEY     Location of SSH private keys to use. Can be specified
                        multiple times. (default:
                        [PosixPath('/home/evan/.ssh/id_rsa')])
  -i INTERFACE, --interface INTERFACE
                        Interface to perform the capture with on the remote
                        machine(s). (default: any)
  -p PASSWORD, --password PASSWORD
                        Password to use for SSH. SSH keys are recommended
                        instead. (default: None)
  -s PACKET_LENGTH, --packet-length PACKET_LENGTH
                        Length of packets to capture. (default: 0)
  -u USER, --user USER  User to SSH as. The user must have sufficient rights.
                        (default: root)
  -r REFRESH_INTERVAL, --refresh-interval REFRESH_INTERVAL
                        Interval to refresh file size and growth rates at.
                        (default: 5)
```

### Reasons this exists

1. I got really sick of sshing into a machine, running `tcpdump` with all of the flags needed, scping the cap file over, and then opening it in Wireshark. Packet traces are incredibly useful in many different situations, so this was bad.
2. Quite often, I had to capture from multiple machines at once. Take the steps above and repeat 2-10 times. I know there are things like tmux or various SSH tools to make this easier, but I wanted something simple that I could share.
3. I got tired of fixing shell scripts I wrote to attempt to resolve 1 and 2. Bash is a wonderful, terrible thing, and it didn't really meet my needs in this context.
4. I wanted semi-live viewing of my capture files. Being able to hit `c-R` to get new packets is nice.
5. I wanted to have a live display of how large my capture files were growing and the rate they were growing at.
6. I wanted more practice using `asyncio` and associated libraries. I've messed with Tornado in the past, but `asyncio` was very different and fun to learn.
