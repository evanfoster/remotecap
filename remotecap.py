#!/usr/bin/env python3
import argparse
import asyncio

import term

try:
    import uvloop

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

except NameError:
    pass
import sys
from asyncio import Queue
from pathlib import Path
import aiofiles
import asyncssh


class MySSHClientSession(asyncssh.SSHClientSession):
    def __init__(self, capture_file, log_file, data_queue, print_queue):
        """

        :type print_queue: Queue
        :type data_queue: Queue
        :type log_file: Path
        :type capture_file: Path
        """
        self.capture_file = capture_file
        self.log_file = log_file
        self.data_queue = data_queue
        self.print_queue = print_queue

    def data_received(self, data, datatype):
        """
        Dumb method that either dumps data into a queue to be written later, or prints it out if it's from stderr.
        Data is sent over as raw bytes to prevent nastiness. asyncio.Queue.put is a coroutine and I can't await here,
        so I need to put_nowait. My queue doesn't have a size limit, so it's fine.
        :type data: bytes
        """
        if datatype == asyncssh.EXTENDED_DATA_STDERR:
            self.data_queue.put_nowait((self.log_file, data))
        else:
            self.data_queue.put_nowait((self.capture_file, data))

    def connection_lost(self, exc):
        if exc:
            self.data_queue.put_nowait((self.log_file, str(exc).encode('ascii')))


async def run_client(machine, capture_file, log_file, keys, password, command, data_queue, print_queue, user):
    def session_factory():
        return MySSHClientSession(capture_file, log_file, data_queue, print_queue)

    conn, client = await asyncssh.create_connection(asyncssh.SSHClient, machine, client_keys=[str(key) for key in keys],
                                                    username=user, known_hosts=None, password=password)

    async with conn:
        chan, session = await conn.create_session(session_factory, command, encoding=None)
        await chan.wait_closed()


async def data_queue_writer(data_queue):
    """
    Doing filesystem stuff with the asyncssh stuff is kinda difficult. I had planned on having this code in
    MySSHClientSession in the data_received method, but to avoid blocking I would need to await, which I can't do
    without making the whole method async. This then goes back up further into asyncssh, requiring more async defs and
    awaits. I got lazy and instead I made a loop that grabs stuff out of a queue and writes it serially in a separate
    thread. So far I haven't noticed any performance problems doing things this way. If I do encounter issues, I'd
    probably break this out into its own process instead of just a coroutine. If I still have problems after that then
    I'd have a process per machine instead of one shared process for all machines.

    But hey, premature optimization and all that jazz. This is cleaner anyways.

    :type data_queue: Queue
    """
    while True:
        file, data = await data_queue.get()
        assert isinstance(file, Path)
        assert isinstance(data, bytes)
        async with aiofiles.open(str(file), mode='ab') as fd:
            await fd.write(data)
        data_queue.task_done()


async def print_queue_worker(print_queue):
    """
    Function to move the cursor to a particular place and begin printing from the beginning of the line.
    Consumes rows and strings to print out of a queue.
    :type print_queue: Queue
    """
    while True:
        row, data = await print_queue.get()
        assert isinstance(data, str)
        term.pos(row, 1)
        term.clearLine()
        print('\r' + data, end='')


class FileSize(object):
    def __init__(self, print_queue, machines, separator, refresh_time=5):
        self.print_queue = print_queue
        self.machines = machines
        self.separator = separator
        self.refresh_time = refresh_time
        self.old_values = {}
        self.size = (0, 0)

    def setup(self):
        term.clear()
        init = 'Capture file:'.ljust(self.separator)
        init += ''.join(str(capture_file.name).ljust(self.separator) for capture_file in self.machines)
        self.print_queue.put_nowait((self.size[0] - 4, init))

    async def file_size_worker(self):
        def sizeof_fmt(num, suffix='B'):
            for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
                if abs(num) < 1024.0:
                    return "%3.1f%s%s" % (num, unit, suffix)
                num /= 1024.0
            return "%.1f%s%s" % (num, 'Yi', suffix)

        while True:
            size = term.getSize()
            if size != self.size:
                self.size = size
                self.setup()
            try:
                size_list = [sizeof_fmt(machine.stat().st_size) for machine in self.machines]
            except FileNotFoundError:
                await asyncio.sleep(self.refresh_time)
                continue
            size_string = 'File size:'.ljust(self.separator)
            size_string += ''.join(size.ljust(self.separator) for size in size_list)
            self.print_queue.put_nowait((self.size[0] - 1, size_string))
            if len(self.old_values) > 0:
                rate_list = [sizeof_fmt((machine.stat().st_size - self.old_values[machine]) / self.refresh_time) + '/s'
                             for machine in self.machines]
                rate_string = 'Rate:'.ljust(self.separator)
                rate_string += ''.join(rate.ljust(self.separator) for rate in rate_list)
                self.print_queue.put_nowait((self.size[0] - 2, rate_string))
            self.old_values = {machine: machine.stat().st_size for machine in self.machines}
            await asyncio.sleep(self.refresh_time)


def main():
    home_directory = Path('~').expanduser()
    parser = argparse.ArgumentParser(prog='remotecap', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    help_string = 'File to write to if performing the capture on a single machine. Folder to put captures in if ' \
                  'capturing from multiple machines. Required.'
    parser.add_argument('-w', '--filename', type=str, help=help_string, required=True)
    help_string = '''Machines to perform the capture on. Required.'''
    parser.add_argument('machines', nargs='+', help=help_string)
    help_string = '''Filter to pass to tcpdump on the remote machine(s).'''
    parser.add_argument('-f', '--filter', default='not port 22', type=str, help=help_string)
    default_key_location = home_directory / '.ssh' / 'id_rsa'
    help_string = '''Location of SSH private keys to use. Can be specified multiple times.'''
    parser.add_argument('-k', '--key',  default=[default_key_location], action='append', help=help_string)
    help_string = '''Interface to perform the capture with on the remote machine(s).'''
    parser.add_argument('-i', '--interface', default='any', type=str, help=help_string)
    help_string = 'Password to use for SSH. SSH keys are recommended instead.'
    parser.add_argument('-p', '--password', type=str, help=help_string)
    help_string = 'Length of packets to capture.'
    parser.add_argument('-s', '--packet-length', type=int, help=help_string, default=0)
    help_string = 'User to SSH as. The user must have sufficient rights.'
    parser.add_argument('-u', '--user', type=str, help=help_string, default='root')
    help_string = 'Interval to refresh file size and growth rates at.'
    parser.add_argument('-r', '--refresh-interval', type=int, help=help_string, default=5)
    args = parser.parse_args()
    # Janky hack to override this issue: https://bugs.python.org/issue16399
    # Basically, if you have a default option and append action, your default will be included instead of being
    # clobbered. Gyar!
    if len(args.key) >= 2:
        keys = [Path(key) for key in args.key if key is not default_key_location]
    else:
        keys = args.key
    if not any([key.exists() for key in keys]):
        print("One of the specified private keys doesn't exist!")
        print(*keys)
        sys.exit(1)
    machines = args.machines
    interface = args.interface
    capture_filter = args.filter
    passwords = args.password
    packet_length = args.packet_length
    user = args.user
    refresh_interval = args.refresh_interval
    if len(machines) > 1:
        Path(args.filename).mkdir(exist_ok=True)
        capture_file_name = {machine: Path(args.filename) / '{}.cap'.format(machine) for machine in machines}
        log_file_name = {machine: Path(args.filename) / '{}.log'.format(machine) for machine in machines}
    else:
        capture_file_name = {machines[0]: Path(args.filename)}
        log_file_name = {machines[0]: Path(args.filename + '.log')}
    for capture_file in capture_file_name.values():
        try:
            capture_file.unlink()
        except FileNotFoundError:
            pass
    command = "tcpdump -i {} -s {} -U -w - '{}'".format(interface, packet_length, capture_filter)
    data_queue = Queue()
    print_queue = Queue()
    task_list = [run_client(machine, capture_file_name[machine], log_file_name[machine], keys, passwords, command,
                            data_queue, print_queue, user) for machine in capture_file_name]
    task_list.append(data_queue_writer(data_queue))
    separator = (max(len(str(capture_file.name)) for capture_file in capture_file_name.values()) + 2)  # For padding
    capture_file_list = [capture_file for capture_file in capture_file_name.values()]
    file_size = FileSize(print_queue, capture_file_list, separator, refresh_interval)
    task_list.append(file_size.file_size_worker())
    task_list.append(print_queue_worker(print_queue))
    tasks = asyncio.gather(*task_list)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(tasks)
    except (KeyboardInterrupt, OSError, asyncssh.Error):
        tasks.cancel()
        loop.run_forever()
        tasks.exception()
    finally:
        loop.close()
        print('Done.')


main()
