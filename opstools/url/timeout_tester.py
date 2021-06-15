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

def send_requests(url, rate, session=None):
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

        if status != 200:
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
        Sends requests to [url] for [timeout] seconds. Can be used to test how long an HTTP session
        can be used to send requests for, since it will re-use the same connection for [timeout]
        seconds.

        N.B. The number of requests per connection on your webserver will also have effect
        here. Setting --server-max-connections (-s) will allow the script to work out a rate to send
        requests so that that number will not be exceeded
        """
    )

    timeout_parser.add_argument("url", help="Where we're going to send requests")
    timeout_parser.add_argument("timeout", help="How long the webservers keep alive setting is set to")
    timeout_parser.add_argument("-s", "--server-max-connections", default=100, help="Maximum number of requests the server will accept per connection")
    args = timeout_parser.parse_known_args(subc_args)[0]

    urllib3.disable_warnings()
    end_time = time.time() + int(args.timeout) # pylint: disable=unused-variable
    rate = int(args.server_max_connections) / int(args.timeout)

    print(f"Requests will be sent every {rate} seconds. There will only be output if the status is not 200. Kill me with CTRL+C when you're done")
    new_sessions_thread = threading.Thread(target=send_requests, args=(args.url, rate,))
    reused_sessions_thread = threading.Thread(target=send_requests, args=(args.url, rate, requests.session(),))

    new_sessions_thread.start()
    reused_sessions_thread.start()

if __name__ == "__main__":
    main()
