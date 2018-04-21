#!/usr/bin/env python3
import argparse
import asyncio
import sys
from asyncio import Queue
from decimal import Decimal
from getpass import getpass
from pathlib import Path
from shlex import quote
from typing import List, NewType, Union

import aiofiles
import asyncssh
# noinspection PyPackageRequirements
import term

# try:
#     import uvloop
#
#     asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
#
# except NameError:
#     pass

Number = NewType('Number', Union[int, float, Decimal])


def sizeof_fmt(num: Number, suffix: str = 'B') -> str:
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


class AsyncWriterSSHClientSession(asyncssh.SSHClientSession):
    def __init__(self, cap_fd, log_fd):

        self.log_fd = log_fd
        self.cap_fd = cap_fd

    def data_received(self, data, datatype):
        if datatype == asyncssh.EXTENDED_DATA_STDERR:
            asyncio.ensure_future(self.log_fd.write(data))
        else:
            asyncio.ensure_future(self.cap_fd.write(data))

    def connection_lost(self, exc):
        if exc:
            asyncio.ensure_future(self.log_fd.write(str(exc).encode()))


async def run_client(user: str, machine: str, command: str, capture_file: Path, keys: List[Path], password: str = None,
                     known_hosts: Path = None):
    log_file = capture_file.with_suffix('.log')

    async with aiofiles.open(str(capture_file), mode='wb') as cap_fd, aiofiles.open(str(log_file), mode='wb') as log_fd:
        def session_factory():
            return AsyncWriterSSHClientSession(cap_fd, log_fd)

        client_keys = [str(key) for key in keys]
        port = 22
        if ':' in machine:
            port = machine.split(':')[1]
            machine = machine.split(':')[0]

        # noinspection PyUnusedLocal
        connection: asyncssh.SSHClientConnection
        async with asyncssh.connect(
                machine, port, client_keys=client_keys, username=user, known_hosts=str(known_hosts),
                password=password) as connection:
            # noinspection PyUnusedLocal
            channel: asyncssh.SSHClientChannel
            # noinspection PyTypeChecker
            channel, _ = await connection.create_session(session_factory, command, encoding=None)
            await channel.wait_closed()


async def print_queue_worker(print_queue: Queue):
    """
    Function to move the cursor to a particular place and begin printing from the beginning of the line.
    Consumes rows and strings to print out of a queue.
    """
    while True:
        # noinspection PyUnusedLocal
        row: int
        # noinspection PyUnusedLocal
        data: str
        row, data = await print_queue.get()
        term.pos(row, 1)
        term.clearLine()
        print('\r' + data, end='')


class FileSize(object):
    """
    Class that calculates the file size of capture files and rate at which those files are growing. Is terminal-size
    aware so changing the size of your window won't screw things up. Doesn't do the printing itself, instead punting
    that over to print_queue_worker.
    """

    def __init__(self, print_queue: Queue, capture_files: List[Path], refresh_time: int = 5):
        self.print_queue = print_queue
        self.capture_files = capture_files
        self.refresh_time = refresh_time
        self.separator_width = max(len(str(capture_file.name)) for capture_file in capture_files) + 4  # For padding
        self.old_values = {}
        # Tuple containing the # rows and # columns
        self.size = (0, 0)

    def setup(self):
        """
        Prepares the terminal for output and  prints the file names 4 rows from the bottom.
        :return:
        :rtype:
        """
        term.clear()
        init = 'Capture file:'.ljust(self.separator_width)
        init += ''.join(str(capture_file.name).ljust(self.separator_width) for capture_file in self.capture_files)
        self.print_queue.put_nowait((self.size[0] - 4, init))

    async def file_size_worker(self):
        """
        Prints the sizes and rates 1 and 2 rows up from the bottom, respectively.
        :return:
        :rtype:
        """
        while True:
            size = term.getSize()
            # Terminal size has changed, we need to set up again or things will look wonky.
            if size != self.size:
                self.size = size
                self.setup()
            try:
                # Well, I said I'd never do it, but I'm going to rely on the fact that dicts are ordered in Python 3.6
                # and above. Sorry!
                capture_files = {file: file.stat().st_size for file in self.capture_files}
            except FileNotFoundError:
                # Since the file size worker starts at the same time we begin capturing, odds are the file won't exist
                # for a while.
                await asyncio.sleep(self.refresh_time)
                continue

            size_string = 'File size:'.ljust(self.separator_width)
            size_string += ''.join(
                    str(sizeof_fmt(capture_file_size)).ljust(self.separator_width) for capture_file_size in
                    capture_files.values())
            self.print_queue.put_nowait((self.size[0] - 1, size_string))
            # Can't make a rate if you don't have a delta.
            if len(self.old_values) > 0:
                capture_growth_rates = []
                for capture_file, capture_file_size in capture_files.items():
                    size_delta = (capture_file_size - self.old_values[capture_file]) / self.refresh_time
                    file_growth = sizeof_fmt(size_delta, suffix='Bps')
                    capture_growth_rates.append(file_growth)

                rate_string = 'Rate:'.ljust(self.separator_width)
                rate_string += ''.join(rate.ljust(self.separator_width) for rate in capture_growth_rates)
                self.print_queue.put_nowait((self.size[0] - 2, rate_string))
            self.old_values = capture_files.copy()

            await asyncio.sleep(self.refresh_time)


def main():
    home_directory = Path('~').expanduser()

    parser = argparse.ArgumentParser(prog='remotecap', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    help_string = 'File to write to if performing the capture on a single machine. Folder to put captures in if ' \
                  'capturing from multiple machines. Required.'
    parser.add_argument('-w', '--filename', type=Path, help=help_string, required=True)
    help_string = '''Machines to perform the capture on. Required.'''
    parser.add_argument('machines', nargs='+', type=str, help=help_string)
    help_string = '''Filter to pass to tcpdump on the remote machine(s).'''
    parser.add_argument('-f', '--filter', default='not port 22', type=str, help=help_string)
    default_key_location = home_directory / '.ssh' / 'id_rsa'
    help_string = '''Location of SSH private keys to use. Can be specified multiple times.'''
    parser.add_argument('-k', '--key', default=[default_key_location], action='append', help=help_string, type=Path)
    help_string = '''Interface to perform the capture with on the remote machine(s).'''
    parser.add_argument('-i', '--interface', default='any', type=str, help=help_string)
    help_string = 'Prompt for password to use for SSH. SSH keys are recommended instead.'
    parser.add_argument('-p', '--password-prompt', default=False, action='store_true', help=help_string)
    help_string = 'Length of packets to capture.'
    parser.add_argument('-s', '--packet-length', type=int, help=help_string, default=0)
    help_string = 'User to SSH as. The user must have sufficient rights.'
    parser.add_argument('-u', '--user', type=str, help=help_string, default='root')
    help_string = 'Interval to refresh file size and growth rates at.'
    parser.add_argument('-r', '--refresh-interval', type=int, help=help_string, default=5)
    help_string = 'Known hosts file to use. Specify "None" if you want to disable known hosts.'
    default_known_hosts_location = home_directory / '.ssh' / 'known_hosts'
    parser.add_argument('-n', '--known-hosts', default=default_known_hosts_location, help=help_string)

    args = parser.parse_args()
    # Janky hack to override this issue: https://bugs.python.org/issue16399
    # Basically, if you have a default option and append action, your default will be included instead of being
    # clobbered. Gyar!
    if len(args.key) >= 2:
        keys: List[Path] = [key for key in args.key if key is not default_key_location]
    else:
        keys: List[Path] = args.key
    if not any([key.exists() for key in keys]):
        print("One of the specified private keys doesn't exist!")
        print(*keys)
        sys.exit(1)
    machines: List[str] = args.machines
    # Using shlex.quote to prevent anyone from injecting random shell commands.
    # No ; rm -rf --no-preserve-root / ; for us here!
    interface: str = quote(args.interface)
    capture_filter: str = quote(args.filter)
    # No need to quote this as argparse is already enforcing int type
    packet_length: int = args.packet_length
    user: str = args.user
    refresh_interval: int = args.refresh_interval
    known_hosts: Union[str, Path, None] = args.known_hosts
    if known_hosts == 'None':
        known_hosts = None
    elif isinstance(known_hosts, str):
        known_hosts = Path(known_hosts)

    password: Union[None, str] = None
    if args.password_prompt:
        password = getpass()

    file_path: Path = args.filename
    file_path = file_path.expanduser().resolve()
    # If we're capturing from more than one machine, we want to create a folder containing our capture files.
    if len(machines) > 1:
        file_path.mkdir(exist_ok=True)
        capture_files = {machine: file_path / f'{machine}.cap' for machine in machines}
    else:
        capture_files = {machines[0]: file_path}

    # Appending to existing capture files makes for invalid capture files.
    for capture_file in capture_files.values():
        try:
            capture_file.unlink()
        except FileNotFoundError:
            pass

    command = f"tcpdump -i {interface} -s {packet_length} -U -w - '{capture_filter}'"

    task_list = [run_client(user, machine, command, file, keys, password=password, known_hosts=known_hosts) for
                 machine, file in capture_files.items()]

    print_queue = Queue()

    file_size = FileSize(print_queue, [*capture_files.values()], refresh_interval)

    task_list.append(file_size.file_size_worker())
    task_list.append(print_queue_worker(print_queue))

    tasks = asyncio.gather(*task_list)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(tasks)
    except (KeyboardInterrupt, OSError, asyncssh.Error):
        tasks.cancel()
        all_tasks = asyncio.gather(*asyncio.Task.all_tasks(loop=loop), loop=loop, return_exceptions=True)
        all_tasks.add_done_callback(lambda t: loop.stop())
        all_tasks.cancel()
        loop.run_forever()
        tasks.exception()
        all_tasks.exception()
    finally:
        loop.close()
        print('Done.')


if __name__ == '__main__':
    main()
