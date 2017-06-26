#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Moves a file or folder.
#!
#! @input source: Path of source file or folder to be moved.
#! @input destination: Path to move file or folder to.
#!
#! @output message: Error message in case of error.
#!
#! @result SUCCESS: File or folder was successfully moved.
#! @result FAILURE: File or folder was not moved due to an error.
#!!#
########################################################################################################################

namespace: io.cloudslang.base.filesystem

operation:
  name: move
  
  inputs:
    - source
    - destination

  python_action:
    script: |
        import shutil, sys
        try:
          shutil.move(source,destination)
          message = ("moving done successfully")
          result = True
        except Exception as e:
          message = e
          result = False

  outputs:
    - message: ${ str(message) }

  results:
    - SUCCESS: ${result}
    - FAILURE
