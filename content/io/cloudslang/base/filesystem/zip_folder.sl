#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Creates a zip archive.
#!
#! @input archive_name: Name of archive to be created (without the .zip extension).
#! @input folder_path: Path to folder to be zipped (zipped file will be created in this folder).
#!
#! @output message: Error message in case of error.
#!
#! @result SUCCESS: Archive was successfully created.
#! @result FAILURE: Archive was not created due to an error.
#!!#
########################################################################################################################

namespace: io.cloudslang.base.filesystem

operation:
  name: zip_folder

  inputs:
    - archive_name
    - folder_path

  python_action:
    script: |
        import sys, os, shutil
        try:
          shutil.make_archive(archive_name, "zip", folder_path)
          filename = archive_name + '.zip'
          shutil.move(filename, folder_path)
          result = True
        except Exception as e:
          message = e
          result = False

  outputs:
    - message: ${ str(message) }

  results:
    - SUCCESS: ${result}
    - FAILURE
