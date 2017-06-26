#   (c) Copyright 2015-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Appends text to string.
#!
#! @input origin_string: String.
#!                       Example: 'good'
#! @input text: Optional - Text which need to be appended.
#!              Example: ' morning'
#!
#! @output new_string: String after appending.
#!                     Example: 'good morning'
#!
#! @result SUCCESS: Always.
#!!#
########################################################################################################################

namespace: io.cloudslang.base.strings

operation:
  name: append

  inputs:
    - origin_string:
        required: false
    - text:
        required: false

  python_action:
    script: |
      origin_string+=text

  outputs:
    - new_string: ${origin_string}

  results:
    - SUCCESS
