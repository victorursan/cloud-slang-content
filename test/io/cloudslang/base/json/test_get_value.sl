#   (c) Copyright 2015-2017 Hewlett-Packard Enterprise Development Company, L.P.
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
  comp: io.cloudslang.base.comparisons

flow:
  name: test_get_value

  inputs:
    - json_before
    - json_path:
        required: false
    - found_value

  workflow:
    - get_value:
        do:
          json.get_value:
            - json_input: ${ json_before }
            - json_path
        publish:
          - return_result
        navigate:
          - SUCCESS: test_equality
          - FAILURE: CREATEFAILURE
    - test_equality:
        do:
          comp.equals:
            - first: ${ return_result }
            - second: ${ found_value }

        navigate:
          - 'TRUE': SUCCESS
          - 'FALSE': EQUALITY_FAILURE

  results:
    - SUCCESS
    - EQUALITY_FAILURE
    - CREATEFAILURE
