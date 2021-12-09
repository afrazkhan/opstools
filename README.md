# opstools

Silly ops things you do repeatedly, but can't be bothered to script :)

## Installation

`pip3 install opstools`

## Usage

The `--help` should suffice in most cases, but searching with `lblogs` command could use some explanation.

To get a list of loadbalancers, run the command without options:

```sh
opstools lblogs
```

Prints out the logs from the last 2 logfiles by default, but you can go further back with the `--last` option:

```sh
opstools lblogs --lb mylb --last 5
```

Search functionality is greedy `AND` — i.e. the string "foo" will also match "foobar", and if multiple search items are given, then all must match. Items are space separated, and must be formatted like this: `key=value`:

```sh
opstools lblogs --lb mylb -s 'target_port=10.43.12.4 request_verb=GET'
```

The above example will only return results that match both target_port with the substring "10.43.12.4" _and_ request_verb with the substring "GET".

## TODO

* Add time of any events to output
* Catch this:

      Traceback (most recent call last):
      File "/Users/afraz/.pyenv/versions/3.7.2/lib/python3.7/threading.py", line 917, in _bootstrap_inner
        self.run()
      File "/Users/afraz/.pyenv/versions/3.7.2/lib/python3.7/threading.py", line 865, in run
        self._target(*self._args, **self._kwargs)
      File "/Users/afraz/repos/github.com/afrazkhan/opstools/opstools/url/timeout_tester.py", line 39, in send_requests
        this_request = this_session.get(url, verify=False, headers=these_headers)
      File "/Users/afraz/.pyenv/versions/3.7.2/lib/python3.7/site-packages/requests/sessions.py", line    543, in get
        return self.request('GET', url, **kwargs)
      File "/Users/afraz/.pyenv/versions/3.7.2/lib/python3.7/site-packages/requests/sessions.py", line    530, in request
        resp = self.send(prep, **send_kwargs)
      File "/Users/afraz/.pyenv/versions/3.7.2/lib/python3.7/site-packages/requests/sessions.py", line    643, in send
        r = adapter.send(request, **kwargs)
      File "/Users/afraz/.pyenv/versions/3.7.2/lib/python3.7/site-packages/requests/adapters.py", line    498, in send
        raise ConnectionError(err, request=request)
      requests.exceptions.ConnectionError: ('Connection aborted.', OSError("(60, 'ETIMEDOUT')"))
