"""
Top level command for opstools
"""

import logging
import click
import os
import sys

from terraform_cloud_deployer import __version__

__author__ = "Afraz Ahmadzadeh"
__copyright__ = "Afraz Ahmadzadeh"
__license__ = "MIT"

_logger = logging.getLogger(__name__)


@click.group()
@click.pass_context
def run(ctx):
    """
    Useful scripts you couldn't be bothred to write
    """

from opstools.aws.commands import aws as aws_commands
from opstools.file.commands import file as file_commands
from opstools.url.commands import url as url_commands
run.add_command(aws_commands)
run.add_command(file_commands)
run.add_command(url_commands)
