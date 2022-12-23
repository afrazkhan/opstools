"""
Parse arbitrarily headered log files for searching
"""

import click

@click.group
@click.pass_context
def url(ctx): # pylint: disable=unused-argument
    """ Scripts which act on URLs """
    pass # pylint: disable=unnecessary-pass

@url.command()
@click.argument("url")
@click.option("--timeout", "-t",default=200, help="How long the webservers keep alive setting is set to")
@click.option("--server-max-connections", "-s", default=100, help="Maximum number of requests the server will accept per connection")
@click.option("--processes", "-p", default=1, help="Spawn this many threads to send more requests at a time")
@click.option("--codes", "-c", help="Additionally acceptable response codes aside from 200")
@click.pass_context
def stresstest(ctx, url, timeout, server_max_connections, processes, codes): # pylint: disable=unused-argument
    """
    Sends requests to [url] for [--timeout] seconds (defaults to 200). Can be used to test
    how long an HTTP session can be used to send requests for, since it will re-use the
    same connection for [--timeout] seconds.

    N.B. The number of requests per connection on your webserver will also have effect
    here. Setting --server-max-connections (-s) will allow the script to work out a rate to send
    requests so that that number will not be exceeded
    """

    if not url.find('http://'[0:8]) or not url.find('https://'[0:8]):
        pass
    else:
        url = f"https://{url}"

    from opstools.url import stresstest as this_stresstest
    this_stresstest.main(url, timeout, server_max_connections, processes, codes)
