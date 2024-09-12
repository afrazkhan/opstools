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

## AWS Nuker

Can be used to find and delete resources matching inclusion and exclusion filters. It only works on resources with tags, since not specifying qualifiers is too dangerous (with the exception of explicit inclusions, which you can see in the last example below).

Will not act without confirmation, or the `--auto-confirm` option.

Example usage:

```sh
# Only include resources with a tag key matching "application" with a value of "foobar"
opstools aws nuke --include-tag application=foobar

# Only include resources _without_ a tag key matching "application" with a value of "foobar"
opstools aws nuke --exclude-tag application=foobar

# Only include resources with a tag key matching "Sandbox".
# Note that only including the tag name implies that you only want to check for the presence of the tag name, not its value
opstools aws nuke --include-tag Sandbox

# Include all resources with tags, and exclude ones that have a tag key
# matching "Terraform"
opstools aws nuke --exclude-tag Terraform

# Include only resources with a tag key matching "Sandbox", then exclude ones
# with a tag key matching "Terraform"
opstools aws nuke --include-tag Sandbox --exclude-tag Terraform

# Include all Lambda functions with the tag key "Sandbox"
opstools aws nuke --include-tag Sandbox --include-service AWS::Lambda::Function

# Include all resources with the tag key "Sandbox", but not Lambda functions
opstools aws nuke --include-tag Sandbox --exclude-service AWS::Lambda::Function

# Include only arn:aws:lambda:eu-central-1:107947530158:function:circle-ci-queue-trigger
opstools aws nuke --include-arn arn:aws:lambda:eu-central-1:000000000000:function:something

# Exclude the "Terraform" tag key and the resource "arn:aws:s3:::foobar" from results
opstools aws nuke -d --et Terraform --ea 'arn:aws:s3:::foobar'
```

Service types can be found [here](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-resource-specification.html) (click on your region).

Bear in mind that specifying only `--include-service` by itself will not work, since tags must be provided in order to filter resources. You can however combine it with the `--explore` flag like this:

```sh
opstools aws nuke --explore --include-service AWS::Lambda::Function
```

`--explore` is a special flag which can be used to find resources even if they are not tagged. It does not link directly to the delete function, but could be used to find a list of resources that could be fed in for deletion with `--include-arn`. It is more strict in it's use of `--include-service` in that services must be correctly capitalised (for example 'AWS::Lambda::Function').

```sh
opstools aws nuke --explore --include-resource 'AWS::Lambda::Function'
```

> :warning: Not supplying `--include-resource` will result in trying to fetch resources for _all_ services, which is a very costly operation

See `opstools aws nuke --help` for full usage.
