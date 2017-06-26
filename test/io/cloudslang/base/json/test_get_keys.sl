#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
namespace: io.cloudslang.base.json

imports:
  json: io.cloudslang.base.json
  strings: io.cloudslang.base.strings
  print: io.cloudslang.base.print

flow:
  name: test_get_keys

  inputs:
    - json_input
    - json_path:
        required: false
    - expected_keys

  workflow:
    - get_keys:
        do:
          json.get_keys:
            - json_input
            - json_path

        publish:
          - json_keys: ${return_result}
          - return_code

        navigate:
          - SUCCESS: verify_keys
          - FAILURE: GET_FAILURE

    - verify_keys:
        loop:
          for: current_key in expected_keys
          do:
            strings.string_occurrence_counter:
              - string_in_which_to_search: ${json_keys}
              - string_to_find: ${current_key}

        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: KEY_MISSING_FAILURE

  results:
    - SUCCESS
    - GET_FAILURE
    - KEY_MISSING_FAILURE
