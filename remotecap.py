#!/usr/bin/env python3
import argparse
import asyncio
import traceback
import signal
import sys
from getpass import getpass
from pathlib import Path
from shlex import quote
from typing import Dict, List, Union, Optional

from asciimatics.screen import Screen  # type: ignore
import aiofiles  # type: ignore
import aiofiles.base  # type: ignore
import asyncssh  # type: ignore

Number = Union[int, float]


def sizeof_fmt(num: Number, suffix: str = "B") -> str:
    """
    Takes a number (size in bytes), returns the human readable representation of that (B, KB, MB, GB, etc).
    Thanks Fred!
    https://web.archive.org/web/20111010015624/http://blogmag.net/blog/read/38/Print_human_readable_file_size
    """
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, "Yi", suffix)


async def run_client(
    user: str,
    host: str,
    command: str,
    cap_file: Path,
    keys: List[Path],
    *,
    shutdown_event: asyncio.Event,
    password: str = None,
    known_hosts: Path = None,
    sudo_password: bytes = b"",
    semaphore: asyncio.Semaphore,
):
    log_file = cap_file.with_suffix(".log")

    async with semaphore:
        async with aiofiles.open(str(cap_file), mode="wb") as cap_fd, aiofiles.open(str(log_file), mode="wb") as log_fd:

            client_keys = list(map(str, keys))
            port = 22
            if ":" in host:
                port = int(host.split(":")[1])
                host = host.split(":")[0]

            # noinspection PyUnusedLocal
            connection: asyncssh.SSHClientConnection
            async with asyncssh.connect(
                host, port, client_keys=client_keys, username=user, known_hosts=str(known_hosts), password=password
            ) as connection:
                stdin = b""
                if len(sudo_password) > 0:
                    stdin = sudo_password
                running_command = asyncio.create_task(
                    connection.run(command, input=stdin, stdout=cap_fd, stderr=log_fd, encoding=None)
                )
                await shutdown_event.wait()
                running_command.cancel()


class FileSize(object):
    """
    Class that calculates the file size of capture files and rate at which those files are growing. Is terminal-size
    aware so changing the size of your window won't screw things up.
    """

    def __init__(
        self,
        host_count: int,
        semaphore: asyncio.Semaphore,
        *args: Path,
        shutdown_event: asyncio.Event = None,
        refresh_interval: int = 5,
    ):
        self.host_count = host_count
        self.semaphore = semaphore
        self.capture_files = args
        assert shutdown_event is not None
        self.shutdown_event = shutdown_event
        self.refresh_interval = refresh_interval
        self._file_header_string = "Capture file:"
        longest_file_name = max(len(str(capture_file.name)) for capture_file in args)
        self.separator_width = max(longest_file_name, len(self._file_header_string)) + 4  # For padding
        self.old_values: Dict[Path, int] = {}
        self.size = (0, 0)

    @property
    def terminal_width(self) -> int:
        return self.size[1]

    @property
    def terminal_height(self) -> int:
        return self.size[0]

    @property
    def file_names(self) -> str:
        file_names = self._file_header_string.ljust(self.separator_width)
        file_names += "".join(str(capture_file.name).ljust(self.separator_width) for capture_file in self.capture_files)
        return file_names

    @property
    def file_sizes(self) -> Dict[Path, int]:
        return {file: (file.stat().st_size if file.exists() else 0) for file in self.capture_files}

    @property
    def file_growth_rates(self) -> str:
        capture_files = self.file_sizes
        if len(self.old_values) == 0:
            return "Rate:".ljust(self.separator_width)

        capture_growth_rates = []
        for capture_file, capture_file_size in capture_files.items():
            size_delta = (capture_file_size - self.old_values.get(capture_file, 0)) / self.refresh_interval
            file_growth = sizeof_fmt(size_delta, suffix="Bps")
            capture_growth_rates.append(file_growth)

        rate_string = "Rate:".ljust(self.separator_width)
        rate_string += "".join(rate.ljust(self.separator_width) for rate in capture_growth_rates)
        return rate_string

    @property
    def capture_file_sizes(self) -> str:
        capture_files = self.file_sizes
        size_string = "File size:".ljust(self.separator_width)
        size_string += "".join(
            str(sizeof_fmt(capture_file_size)).ljust(self.separator_width)
            for capture_file_size in capture_files.values()
        )
        return size_string

    async def file_size_worker(self):
        """
        Prints the sizes and rates 1 and 2 rows up from the bottom, respectively.
        :return:
        :rtype:
        """
        # Want to give the other coroutines a chance to increment the semaphore

        screen = Screen.open()
        self.size = screen.dimensions
        try:
            # I wish asyncio.Semaphore made the value public. I know it's probably to prevent people from doing stupid
            # things, but sometimes it's nice to be dumb. Doing this so we can die when all of our captures have died.
            # noinspection PyProtectedMember
            while not self.shutdown_event.is_set() or self.semaphore._value < self.host_count:
                if screen.has_resized():
                    screen.close(restore=False)
                    screen = Screen.open()
                self.size = screen.dimensions
                screen.print_at(self.file_names, 0, self.terminal_height - 3)
                screen.print_at(self.capture_file_sizes, 0, self.terminal_height - 2)
                screen.print_at(self.file_growth_rates, 0, self.terminal_height - 1)
                self.old_values = self.file_sizes.copy()
                screen.refresh()
                await asyncio.wait([self.shutdown_event.wait()], timeout=self.refresh_interval)
        finally:
            screen.close()
            print("\n")
            print(self.file_names)
            print(self.capture_file_sizes)
            print(self.file_growth_rates)
            print("\n")


async def main():
    home_directory = Path("~").expanduser()

    parser = argparse.ArgumentParser(prog="remotecap", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    help_string = (
        "File to write to if performing the capture on a single host. Folder to put captures in if "
        "capturing from multiple hosts. Required."
    )
    parser.add_argument("-w", "--filename", type=Path, help=help_string, required=True)
    help_string = """Hosts to perform the capture on. Required."""
    parser.add_argument("hosts", nargs="+", type=str, help=help_string)
    help_string = """Filter to pass to tcpdump on the remote host(s)."""
    parser.add_argument("-f", "--filter", default="not port 22", type=str, help=help_string)
    default_key_location = home_directory / ".ssh" / "id_rsa"
    help_string = """Location of SSH private keys to use. Can be specified multiple times."""
    parser.add_argument("-k", "--key", action="append", help=help_string, type=Path)
    help_string = """Interface to perform the capture with on the remote host(s)."""
    parser.add_argument("-i", "--interface", default="any", type=str, help=help_string)
    help_string = "Prompt for password to use for SSH. SSH keys are recommended instead."
    parser.add_argument("-p", "--password-prompt", default=False, action="store_true", help=help_string)
    help_string = "Length of packets to capture."
    parser.add_argument("-s", "--packet-length", type=int, help=help_string, default=0)
    help_string = "User to SSH as. The user must have sufficient rights."
    parser.add_argument("-u", "--user", type=str, help=help_string, default="root")
    help_string = "Interval to refresh file size and growth rates at."
    parser.add_argument("-r", "--refresh-interval", type=int, help=help_string, default=5)
    help_string = 'Known hosts file to use. Specify "None" if you want to disable known hosts.'
    default_known_hosts_location = home_directory / ".ssh" / "known_hosts"
    parser.add_argument("-n", "--known-hosts", default=default_known_hosts_location, help=help_string)
    help_string = "Escalate privileges (sudo) and prompt for password"
    parser.add_argument("-e", "--sudo", action="store_true", default=False, help=help_string)
    help_string = "Path to tcpdump on the system. Needed if tcpdump isn't in your path."
    parser.add_argument("-c", "--command-path", default="tcpdump", type=str, help=help_string)
    help_string = "Do not take over the screen."
    parser.add_argument("-q", "--quiet", action="store_true", default=False, help=help_string)
    parser.add_argument("-d", "--debugger", action="store_true", default=False)

    args = parser.parse_args()
    if args.debugger:
        breakpoint()
    # Janky hack to override this issue: https://bugs.python.org/issue16399
    # Basically, if you have a default option and append action, your default will be included instead of being
    # clobbered. Gyar!
    if args.key is None:
        keys: List[Path] = [default_key_location]
    else:
        keys: List[Path] = [key for key in args.key if key is not default_key_location]

    if not any(key.exists() for key in keys):
        print("One of the specified private keys doesn't exist!")
        print(*keys)
        sys.exit(1)
    hosts: List[str] = args.hosts
    # Using shlex.quote to prevent anyone from injecting random shell commands.
    # No ; rm -rf --no-preserve-root / ; for us here!
    interface: str = quote(args.interface)
    capture_filter: str = quote(args.filter)
    command_path: str = args.command_path
    if command_path != "tcpdump":
        command_path = quote(command_path)
    # No need to quote this as argparse is already enforcing int type
    packet_length: int = args.packet_length
    user: str = args.user
    refresh_interval: int = args.refresh_interval
    known_hosts: Optional[Union[str, Path]] = args.known_hosts
    should_sudo: bool = args.sudo
    be_quiet: bool = args.quiet

    if known_hosts == "None":
        known_hosts = None
    elif isinstance(known_hosts, str):
        known_hosts = Path(known_hosts)
        if not known_hosts.exists():
            print(f"Known hosts file {known_hosts} does not exist.")
            sys.exit(1)

    password: Optional[str] = None
    if args.password_prompt:
        password = getpass(prompt="SSH password: ")

    file_path: Path = args.filename
    file_path = file_path.expanduser().resolve()
    # If we're capturing from more than one host, we want to create a folder containing our capture files.
    if len(hosts) > 1:
        file_path.mkdir(exist_ok=True)
        capture_files = {host: file_path / f"{host}.cap" for host in hosts}
    else:
        capture_files = {hosts[0]: file_path}

    # Appending to existing capture files makes for invalid capture files.
    for capture_file in capture_files.values():
        if capture_file.exists():
            capture_file.unlink()

    sudo = ""
    sudo_password: bytes = b""
    if should_sudo:
        sudo = "sudo -S "
        sudo_password = getpass(prompt="Sudo password: ").encode() + b"\n"
    command = f"{sudo}{command_path} -i {interface} -s {packet_length} -U -w - '{capture_filter}'"
    shutdown_event = asyncio.Event()
    semaphore = asyncio.Semaphore(len(capture_files))
    task_list = []
    for host, file in capture_files.items():
        task_list.append(
            asyncio.create_task(
                run_client(
                    user,
                    host,
                    command,
                    file,
                    keys,
                    semaphore=semaphore,
                    password=password,
                    known_hosts=known_hosts,
                    sudo_password=sudo_password,
                    shutdown_event=shutdown_event,
                )
            )
        )

    # To let one of the tasks above increment the semaphore. Janky, but eh.
    await asyncio.sleep(0)

    file_size = FileSize(
        len(capture_files),
        semaphore,
        *capture_files.values(),
        refresh_interval=refresh_interval,
        shutdown_event=shutdown_event,
    )

    if not be_quiet:
        task_list.append(file_size.file_size_worker())

    tasks = asyncio.gather(*task_list)

    def shutdown_signal_handler(_, __):
        shutdown_event.set()

    for shutdown_signal in (signal.SIGINT, signal.SIGTERM):
        signal.signal(shutdown_signal, shutdown_signal_handler)

    try:
        await tasks
    except Exception:
        print("Hit an unexpected exception!")
        traceback.print_exc()
        raise
    finally:
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
