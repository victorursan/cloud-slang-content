#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Prints text to the screen.
#!
#! @input text: Text to print.
#!
#! @result SUCCESS: Text printed successfully.
#!!#
########################################################################################################################

namespace: io.cloudslang.base.print

operation:
  name: print_text

  inputs:
    - text

  python_action:
    script: print text

  results:
    - SUCCESS
