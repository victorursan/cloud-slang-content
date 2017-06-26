#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Converts each item in a list to a string and concatenates them.
#!
#! @input list: List of items that will be converted to string and concatenated
#!              Example: [123, 'xyz']
#! @input double_quotes: Optional - If true, list items will be double quoted
#!                       Default: False
#! @input result_delimiter: Optional - If true, will be appended after every list item (except the last one)
#!                          Default: "'
#! @input result_to_lowercase: Optional - If true, list items will be lower cased
#!                             Default: False
#!
#! @output result: String that results from concatenation of list elements
#!
#! @result SUCCESS: List converted to string successfully
#!!#
########################################################################################################################

namespace: io.cloudslang.base.lists

operation:
  name: convert_list_to_string

  inputs:
    - list
    - double_quotes:
        default: "False"
        required: false
    - result_delimiter:
        default: ''
        required: false
    - result_to_lowercase:
        default: "False"
        required: false

  python_action:
    script: |
      result = ''
      list_length = len(list)
      for item in list:
        result += '\"' + str(item) + '\"' if bool(double_quotes) else str(item)
        list_length -= 1
        if (list_length > 0 and result_delimiter != ''):
          result += str(result_delimiter)
      result = result.lower() if bool(result_to_lowercase) else result

  outputs:
    - result

  results:
    - SUCCESS
