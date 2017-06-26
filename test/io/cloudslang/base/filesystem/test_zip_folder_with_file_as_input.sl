#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
namespace: io.cloudslang.base.filesystem

imports:
  files: io.cloudslang.base.filesystem
  strings: io.cloudslang.base.strings

flow:
  name: test_zip_folder_with_file_as_input
  inputs:
    - archive_name
    - folder_path
  workflow:
    -  create_file_to_be_zipped:
        do:
          files.write_to_file:
            - file_path: ${folder_path}
            - text: 'text-to-be-copied'
        navigate:
          - SUCCESS: test_zip_folder_operation
          - FAILURE: CREATEFAILURE

    - test_zip_folder_operation:
        do:
          files.zip_folder:
            - archive_name
            - folder_path
        navigate:
          - SUCCESS: delete_archive
          - FAILURE: delete_created_file_from_zip_failure
    - delete_archive:
        do:
          files.delete:
            - source: ${'./' + folder_path + '/' + archive_name + '.zip'}
        navigate:
          - SUCCESS: delete_created_file_from_zip_success
          - FAILURE: DELETEFAILURE
    - delete_created_file_from_zip_failure:
        do:
          files.delete:
            - source: ${folder_path}
        navigate:
          - SUCCESS: ZIPFAILURE
          - FAILURE: DELETEFAILURE
    - delete_created_file_from_zip_success:
        do:
          files.delete:
            - source: ${folder_path}
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: DELETEFAILURE
  results:
    - SUCCESS
    - CREATEFAILURE
    - ZIPFAILURE
    - DELETEFAILURE
