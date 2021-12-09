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
import threading
import sys

def send_requests(url, rate, codes, session=None):
    """
    Send requests to [url] with a new session per request, or the same session if [session]
    is supplied
    """

    fresh_sessions = False
    this_session = session
    these_headers = {}

    while True:
        time.time()

        if not session:
            fresh_sessions = True
            this_session = requests.session()
            this_session.keep_alive = False
            these_headers={"Connection": "close"}

        this_request = this_session.get(url, verify=False, headers=these_headers)
        status = this_request.status_code

        if status not in codes:
            print(f"ERROR: {status}, Fresh sessions: {fresh_sessions}\nHEADERS: {this_request.headers}")
        time.sleep(rate)

def main(subc_args=None):
    """ Start the threads """

    class MyParser(argparse.ArgumentParser):
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

    print(f"Requests will be sent every {rate} seconds. There will only be output if the status is not 200. Kill me with CTRL+C when you're done\n")
    for i in range(int(args.processes)):
        new_sessions_thread = threading.Thread(target=send_requests, args=(url, rate, codes,))
        new_sessions_thread.start()

        reused_sessions_thread = threading.Thread(target=send_requests, args=(url, rate, codes, requests.session(),))
        reused_sessions_thread.start()

if __name__ == "__main__":
    main()
