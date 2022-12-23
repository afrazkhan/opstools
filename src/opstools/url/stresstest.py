"""
Sends requests to [url] for [timeout] seconds. Can be used to test how long an HTTP session
can be used to send requests for, since it will re-use the same connection for [timeout]
seconds.

N.B. The number of requests per connection on your webserver will also have effect
here. Setting --server-max-connections (-s) will allow the script to work out a rate to send
requests so that that number will not be exceeded
"""

import time
import urllib3
import requests
from multiprocessing import Process
import sys

def main(url, timeout, server_max_connections, processes, codes):
    """ Start the threads """

    urllib3.disable_warnings()
    end_time = time.time() + int(timeout) # pylint: disable=unused-variable
    rate = int(server_max_connections) / int(timeout)
    if codes is not None:
        codes = [int(this_code) for this_code in codes.split(',')]
        codes.append(200)
    else:
        codes = [200]

    print(f"Requests will be sent every {rate} seconds. Kill me with CTRL+C when you're done\n")
    for i in range(int(processes)):
        new_sessions_thread = Process(target=send_requests, args=(url, rate, codes,))
        new_sessions_thread.start()
        print(f"Started new_session thread {i + 1}")

        reused_sessions_thread = Process(target=send_requests, args=(url, rate, codes, requests.session(),))
        reused_sessions_thread.start()
        print(f"Started reused_session thread {i + 1}")

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
            last_error_time = time.ctime()
            write_log(f"""
Time: {last_error_time}
Error Number: {error_counter}
Connection Type: {this_request.headers['Connection']}
Full Headers: {this_request.headers}

            """)

        refresh_line(f"Last Error: {last_error_time} — Total Errors: {error_counter}")
        time.sleep(rate)
