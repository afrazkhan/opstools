# Changelog

## Version v1.0.0

* Switched to Click()
* Switched to PyScaffold generated template
* Added `aws sg-report` sub-command

## Version v1.0.1

* Re-wrote list of dicts printer as helper for `aws sg-report` and `aws ec2-list`

## Version v1.0.2

* Added `aws nuke` sub-command for controlled deletion of AWS resources
* Implemented filtering of resources by tags, services, and ARNs in `aws nuke`
* Added safety checks and confirmation prompts for resource deletion in `aws nuke`
* Improved error handling and logging for AWS credential issues
* Enhanced documentation for new `aws nuke` functionality
