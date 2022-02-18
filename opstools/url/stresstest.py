#!/usr/bin/env python3

"""
Sends requests to [url] for [timeout] seconds. Can be used to test how long an HTTP session
can be used to send requests for, since it will re-use the same connection for [timeout]
seconds.

N.B. The number of requests per connection on your webserver will also have effect
here. Setting --server-max-connections (-s) will allow the script to work out a rate to send
requests so that that number will not be exceeded
"""

import argparse
import time
import urllib3
import requests
from multiprocessing import Process
import sys
import os


def refresh_line(output):
    """
    Refreshes the output line to show the stress testing working
    """

    sys.stdout.flush()
    sys.stdout.write(f"\r{output}")

def write_log(output):
    """
    Log output (of failed connections, but can be anything) to errors.log
    """

    with open("errors.log", "a", encoding="UTF-8") as log_file:
        log_file.write(output)

def send_requests(url, rate, codes, session=None):
    """
    Send requests to [url] with a new session per request, or the same session if [session]
    is supplied
    """

    this_session = session
    these_headers = {}
    error_counter = 0
    last_error_time = "None"

    while True:
        time.time()

        if not session:
            this_session = requests.session()
            this_session.keep_alive = False
            these_headers={"Connection": "close"}

        try:
            this_request = this_session.get(url, verify=False, headers=these_headers)
        except requests.exceptions.ConnectionError as e:
            print(f"Could not make initial connection: {e}")
            sys.exit(0)
        status = this_request.status_code

        if status not in codes:
            error_counter += 1
            os.system("say 'Non-accepted HTTP code' received")
            last_error_time = time.ctime()
            write_log(f"""
Time: {last_error_time}
Error Number: {error_counter}
Connection Type: {this_request.headers['Connection']}
Full Headers: {this_request.headers}

            """)

        refresh_line(f"Last Error: {last_error_time} — Total Errors: {error_counter}")
        time.sleep(rate)

def main(subc_args=None):
    """ Start the threads """

    class MyParser(argparse.ArgumentParser): # pylint: disable=missing-docstring
        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)

    timeout_parser = MyParser(description=
        """
        Sends requests to [url] for [--timeout] seconds (defaults to 200). Can be used to test
        how long an HTTP session can be used to send requests for, since it will re-use the
        same connection for [--timeout] seconds.

        N.B. The number of requests per connection on your webserver will also have effect
        here. Setting --server-max-connections (-s) will allow the script to work out a rate to send
        requests so that that number will not be exceeded
        """
    )

    timeout_parser.add_argument("url", help="Where we're going to send requests")
    timeout_parser.add_argument("-t", "--timeout", default=200, help="How long the webservers keep alive setting is set to")
    timeout_parser.add_argument("-s", "--server-max-connections", default=100, help="Maximum number of requests the server will accept per connection")
    timeout_parser.add_argument("-p", "--processes", default=1, help="Spawn this many threads to send more requests at a time")
    timeout_parser.add_argument("-c", "--codes", help="Additionally acceptable response codes aside from 200")
    args = timeout_parser.parse_known_args(subc_args)[0]
    if not args.url.find('http://'[0:8]) or not args.url.find('https://'[0:8]):
        url = args.url
    else:
        url = f"https://{args.url}"

    urllib3.disable_warnings()
    end_time = time.time() + int(args.timeout) # pylint: disable=unused-variable
    rate = int(args.server_max_connections) / int(args.timeout)
    if args.codes is not None:
        codes = [int(this_code) for this_code in args.codes.split(',')]
        codes.append(200)
    else:
        codes = [200]

    print(f"Requests will be sent every {rate} seconds. Kill me with CTRL+C when you're done\n")
    for i in range(int(args.processes)):
        new_sessions_thread = Process(target=send_requests, args=(url, rate, codes,))
        new_sessions_thread.start()
        print(f"Started new_session thread {i + 1}")

        reused_sessions_thread = Process(target=send_requests, args=(url, rate, codes, requests.session(),))
        reused_sessions_thread.start()
        print(f"Started reused_session thread {i + 1}")


if __name__ == "__main__":
    main()
