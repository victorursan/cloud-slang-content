#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Creates a folder tree.
#!
#! @input folder_name: Name of folder to be created.
#!                     Example:
#!                     'c:/path1/path2/folder_name' will create the folder in the full path provided
#!                     '%AppData%/folder_name' will create the folder in the environment variable provided
#!                     'folder_name' will create the folder in %CENTRAL_HOME%/bin, %CLI_HOME%/bin
#!
#! @output message: Error message in case of error.
#!
#! @result SUCCESS: Folder was successfully created.
#! @result FAILURE: Folder was not created due to error.
#!!#
########################################################################################################################

namespace: io.cloudslang.base.filesystem

operation:
  name: create_folder_tree

  inputs:
    - folder_name

  python_action:
    script: |
        import os
        message = None
        result = None
        try:
          if os.path.isdir(os.path.expandvars(folder_name)):
            message = ("folder already exists")
            result = False
          else:
            os.makedirs(os.path.expandvars(folder_name))
            message = ("folder created")
            result = True
        except Exception as e:
          message = e
          result = False

  outputs:
    - message

  results:
    - SUCCESS: ${result}
    - FAILURE
