#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Copies a file or folder.
#!               If a folder is copied, the destination directory must not already exist.
#!
#! @input source: Path of source file or folder to be copied.
#! @input destination: Path of destination for file or folder to be copied to. If copying a folder, destination path must
#!                     include folder name. If copying a file, destination path must include file name.
#!
#! @output message: Error message in case of error.
#!
#! @result SUCCESS: File or folder was successfully copied.
#! @result FAILURE: File or folder was not copied due to an error.
#!!#
########################################################################################################################

namespace: io.cloudslang.base.filesystem

operation:
  name: copy
  inputs:
    - source
    - destination

  python_action:
    script: |
      import os, shutil;
      try:
        if os.path.isfile(source):
          shutil.copy(source, destination)
          message = ("copying done successfully")
          result = True
        elif os.path.isdir(source):
          shutil.copytree(source, destination)
          message = ("copying done successfully")
          result = True
        else:
          message = ("no such file or folder")
          result = False
      except Exception as exception:
        if ('win' in os.environ.get('OS','').lower() and 'Operation not permitted' in str(exception)):
          message = ''
          result = True
        else:
          message = exception
          result = False
          print message

  outputs:
    - message: ${ str(message) }

  results:
    - SUCCESS: ${result}
    - FAILURE
