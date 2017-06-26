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

flow:
  name: test_copy_folder
  inputs:
    - copy_source
    - copy_destination
  workflow:
    - create_folder_to_be_copied:
        do:
          files.create_folder:
            - folder_name: ${copy_source}
        navigate:
          - SUCCESS: test_copy_operation
          - FAILURE: CREATEFAILURE
    - test_copy_operation:
        do:
          files.copy:
            - source: ${copy_source}
            - destination: ${copy_destination}
        navigate:
          - SUCCESS: delete_copied_folder
          - FAILURE: delete_created_folder_after_copy_failure
        publish:
          - message
    - delete_created_folder_after_copy_failure:
        do:
          files.delete:
            - source: ${copy_source}
        navigate:
          - SUCCESS: COPYFAILURE
          - FAILURE: DELETEFAILURE
    - delete_copied_folder:
        do:
          files.delete:
            - source: ${copy_destination}
        navigate:
          - SUCCESS: delete_created_folder
          - FAILURE: DELETEFAILURE
    - delete_created_folder:
        do:
          files.delete:
            - source: ${copy_source}
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: DELETEFAILURE

  outputs:
    - message

  results:
    - SUCCESS
    - CREATEFAILURE
    - COPYFAILURE
    - DELETEFAILURE
