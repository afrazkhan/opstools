import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from typing import Dict
from threading import Thread, Lock
import logging
import sys
from datetime import datetime

class S3MetadataSearch():
    def __init__(self, max_threads: int, max_retries_per_thread: int, retry_mode: str, bucket_name: str, prefix: str, metadata_key: str, metadata_value: str | None = None):
        boto_config = BotoConfig(
           retries = {
              'max_attempts': max_retries_per_thread,
              'mode': retry_mode # pyright: ignore
           }
        )

        self.s3 = boto3.client('s3', config=boto_config)

        self.max_threads = max_threads
        self.max_retries_per_thread = max_retries_per_thread
        self.bucket_name = bucket_name
        self.prefix = prefix
        self.metadata_key = metadata_key
        self.metadata_value = metadata_value


    def search_objects_metadata(self, page) -> Dict[str, str]:
        objects = {}

        for obj in page.get('Contents', []):
            try:
                object_info = self.s3.head_object(Bucket=self.bucket_name, Key=obj['Key'])

            except ClientError as e:
                logging.critical(f"Unrecoverable problem whilst trying to retrieve object info: {e.response}")
                sys.exit(1)

            try:
                if (self.metadata_value is None and self.metadata_key in object_info['Metadata']) or (self.metadata_key in object_info['Metadata'] and object_info['Metadata'][self.metadata_key] == self.metadata_value):
                   objects[obj['Key']] = {
                       'key_name': self.metadata_key,
                       'value_found': object_info['Metadata'][self.metadata_key],
                       'last_modified': object_info['ResponseMetadata']['HTTPHeaders']['last-modified'],
                       'version_id': object_info['VersionId']
                   }
            except KeyError as e:
                logging.warning(f"Key lookup failed whilst processing {self.metadata_key}")
                logging.debug(f"Full object info for failed object:\n{object_info}")
                continue

        return objects

    def iterate_pages(self) -> Dict[str, str]:
        objects = {}
        threads = []
        paginator = self.s3.get_paginator("list_objects")

        page_iterator = paginator.paginate(Bucket=self.bucket_name, Prefix=self.prefix)
        thread_number = 1

        # Create a thread-safe dictionary to store results from all threads
        objects_lock = Lock()

        def process_page(page):
            nonlocal objects
            page_results = self.search_objects_metadata(page)
            with objects_lock:
                objects.update(page_results)

        try:
            for page in page_iterator:
                thread = Thread(target=process_page, args=(page,))
                thread.start()
                logging.info(f"Starting thread number {thread_number}")
                threads.append(thread)
                thread_number += 1

                if thread_number > self.max_threads:
                    print(f"Max threads reached, waiting for threads to complete")
                    break
        except ClientError as e:
            logging.critical(e.response['Error']['Code'])
            sys.exit(1)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        return objects
