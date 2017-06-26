#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
namespace: io.cloudslang.base.os

imports:
  os: io.cloudslang.base.os
  strings: io.cloudslang.base.strings

flow:
  name: test_get_os

  inputs:
    - expected_output:
        required: false

  workflow:
    - test_get_os_operation:
        do:
          os.get_os:
        publish:
          - message
        navigate:
          - LINUX: verify_returned_output
          - WINDOWS: verify_returned_output
    - verify_returned_output:
        do:
          strings.string_equals:
            - first_string: ${ expected_output }
            - second_string: ${ '' if message == None else message }
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: DIFFERENT_OUTPUTS

  results:
    - SUCCESS
    - DIFFERENT_OUTPUTS
