#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
####################################################

namespace: io.cloudslang.vmware.vcenter.utils

imports:
  utils: io.cloudslang.vmware.vcenter.utils
  lists: io.cloudslang.base.lists
  strings: io.cloudslang.base.strings

flow:
  name: test_get_os_descriptors

  inputs:
    - host
    - port:
        default: '443'
        required: false
    - protocol:
        default: 'https'
        required: false
    - username:
        required: false
    - password
    - trust_everyone:
        default: 'true'
        required: false
    - data_center_name
    - hostname
    - delimiter:
        default: ','
        required: false

  workflow:
    - get_os_descriptors:
        do:
          utils.get_os_descriptors:
            - host
            - port
            - protocol
            - username
            - password
            - trust_everyone
            - data_center_name
            - hostname
            - delimiter
        publish:
          - return_result
          - return_code
          - exception : ${exception if exception != None else ''}
        navigate:
          - SUCCESS: check_result
          - FAILURE: GET_OS_DESCRIPTORS_FAILURE

    - check_result:
        do:
          lists.compare_lists:
            - list_1: ${str(exception) + "," + return_code}
            - list_2: ",0"
        navigate:
          - SUCCESS: get_text_occurrence
          - FAILURE: CHECK_RESPONSES_FAILURE

    - get_text_occurrence:
        do:
          strings.string_occurrence_counter:
            - string_in_which_to_search: ${str(return_result)}
            - string_to_find: ${'windows'}
            - ignore_case: 'true'
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: GET_TEXT_OCCURRENCE_FAILURE

  outputs:
    - return_result
    - return_code
    - exception

  results:
    - SUCCESS
    - GET_OS_DESCRIPTORS_FAILURE
    - CHECK_RESPONSES_FAILURE
    - GET_TEXT_OCCURRENCE_FAILURE
