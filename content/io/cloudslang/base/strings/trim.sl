#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
########################################################################################################################
#!!
#! @description: Trims string.
#!
#! @input origin_string: String.
#!                       Example: " good "
#!
#! @output new_string: String in which all whitespace characters have been stripped of both sides of the string.
#!
#! @result SUCCESS: String trimmed successfully.
#!!#
########################################################################################################################

 namespace: io.cloudslang.base.strings

 operation:
   name: trim

   inputs:
     - origin_string

   python_action:
     script: |
       new_string=origin_string.strip()

   outputs:
     - new_string

   results:
     - SUCCESS
