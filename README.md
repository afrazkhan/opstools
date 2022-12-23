<!-- These are examples of badges you might want to add to your README:
     please update the URLs accordingly

[![Built Status](https://api.cirrus-ci.com/github/<USER>/opstools.svg?branch=main)](https://cirrus-ci.com/github/<USER>/opstools)
[![ReadTheDocs](https://readthedocs.org/projects/opstools/badge/?version=latest)](https://opstools.readthedocs.io/en/stable/)
[![Coveralls](https://img.shields.io/coveralls/github/<USER>/opstools/main.svg)](https://coveralls.io/r/<USER>/opstools)
[![PyPI-Server](https://img.shields.io/pypi/v/opstools.svg)](https://pypi.org/project/opstools/)
[![Conda-Forge](https://img.shields.io/conda/vn/conda-forge/opstools.svg)](https://anaconda.org/conda-forge/opstools)
[![Monthly Downloads](https://pepy.tech/badge/opstools/month)](https://pepy.tech/project/opstools)
[![Twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social&label=Twitter)](https://twitter.com/opstools)
-->

[![Project generated with PyScaffold](https://img.shields.io/badge/-PyScaffold-005CA0?logo=pyscaffold)](https://pyscaffold.org/)

# opstools

> Silly ops things that you've had to write more than once

Stuff that I've had to write more than once, and now I keep as a collection in a Python package, called "opstools".

It's split up into sub-command groups, which are (currently):

* aws — Scripts to make working with AWS easier
* file — Scripts which act on local files
* url — Scripts which act on URLs

Sub-commands are self-documented, so hit the `--help` for information. For example, there is a sub-command in the `aws` group called `allow-me`, which adds your current IP address to the security group for a public (AWS controlled) IP address you supply:

```text
$ opstools aws allow-me --help
Usage: opstools aws allow-me [OPTIONS] HOSTNAME

  Look up security groups associated with [hostname], and add port allowances
  for this machine's IP

Options:
  -s, --ssh        Add port 22 to the first security group found
  --https          Add ports 443 and 80 to the first security group found
  -p, --port TEXT  Add a custom port to the first security group found
  --help           Show this message and exit.
```

Or hit enter (or `--help`) at each group level to see a list of available sub-commands (and sub-groups, if any):

```text
$ opstools file
Usage: opstools file [OPTIONS] COMMAND [ARGS]...

  Scripts which act on files

Options:
  --help  Show this message and exit.

Commands:
  hosts       Add / remove entries to /etc/hosts, with (MacOS) reminder...
  log-search  Parse arbitrarily headered log files for searching
```
