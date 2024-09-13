"""
Top level command for opstools
"""

import logging
import click

from terraform_cloud_deployer import __version__

__author__ = "Afraz Ahmadzadeh"
__copyright__ = "Afraz Ahmadzadeh"
__license__ = "MIT"


@click.group()
@click.pass_context
@click.option('--log-level', '-l', default='INFO', help='Set the logging level')
def run(ctx, log_level):
    """
    Useful scripts you couldn't be bothred to write
    """
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=log_level.upper())
    ctx.obj = {'logger': logger}
    # Suppress boto3 logging (at least to 'CRITICAL')
    for name in ['boto', 'urllib3', 's3transfer', 'boto3', 'botocore', 'nose']:
        logging.getLogger(name).setLevel(logging.CRITICAL)


from opstools.aws.commands import aws as aws_commands
from opstools.file.commands import file as file_commands
from opstools.url.commands import url as url_commands
run.add_command(aws_commands)
run.add_command(file_commands)
run.add_command(url_commands)
