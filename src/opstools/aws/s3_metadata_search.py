import boto3
from typing import Dict
from threading import Thread
import logging
from botocore.exceptions import ClientError
import sys

def search_objects_metadata(page, bucket_name: str, metadata_key: str, metadata_value: str | None = None) ->Dict[str, str]:
    s3 = boto3.client('s3')
    objects = {}

    for obj in page.get('Contents', []):
        try:
            object_info = s3.head_object(Bucket=bucket_name, Key=obj['Key'])
        except ClientError as e:
            logging.critical(f"Unrecoverable problem whilst trying to retrieve object info: {e.response['Error']['Code']}")
            sys.exit(1)

        try:
            if (metadata_value is None and metadata_key in object_info['Metadata']) or (object_info['Metadata'][metadata_key] == metadata_value):
               objects[obj['Key']] = {
                   'key_name': metadata_key,
                   'value_found': object_info['Metadata'][metadata_key],
                   'last_modified': object_info['ResponseMetadata']['HTTPHeaders']['last-modified'],
                   'version_id': object_info['VersionId']
               }
        except KeyError as e:
            logging.warning(f"Key access failed: {e}")
            continue

    return objects

def iterate_pages(bucket_name: str, prefix: str, metadata_key: str, metadata_value: str | None = None) -> Dict[str, str]:
    s3 = boto3.client('s3')
    objects = {}
    threads = []
    paginator = s3.get_paginator("list_objects")

    page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)
    thread_number = 1

    # Create a thread-safe dictionary to store results from all threads
    from threading import Lock
    objects_lock = Lock()

    def process_page(page):
        nonlocal objects
        page_results = search_objects_metadata(page, bucket_name, metadata_key, metadata_value)
        with objects_lock:
            objects.update(page_results)

    try:
        for page in page_iterator:
            thread = Thread(target=process_page, args=(page,))
            thread.start()
            logging.info(f"Starting thread number {thread_number}")
            thread_number += 1
            threads.append(thread)
    except ClientError as e:
        logging.critical(e.response['Error']['Code'])
        sys.exit(1)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    return objects
