#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: This operation runs an SQL script from a file or from the <sql_commands> input.
#!
#! @input db_server_name: The hostname or ip address of the database server.
#! @input db_type: The type of database to connect to.
#!                 Valid values: 'Oracle', 'MSSQL', 'Sybase', 'Netcool', 'DB2', 'PostgreSQL' and 'Custom'.
#! @input username: The username to use when connecting to the database.
#! @input password: The password to use when connecting to the database.
#! @input instance: The name instance (fo r MSSQL Server). Leave it blank for default instance.
#! @input db_port: The port to connect to.
#!                 Default values: Oracle: '1521', MSSQL: '1433', Sybase: '5000', Netcool: '4100', DB2: '50000', PostgreSQL: '5432'.
#! @input database_name: The name of the database.
#! @input authentication_type: The type of authentication used to access the database (applicable only to MSSQL type).
#!                             Default: 'sql'
#!                             Values: 'sql'
#!                             Note: currently, the only valid value is sql, more are planed
#! @input db_class: The classname of the JDBC driver to use.
#! @input db_url: The url required to load up the driver and make your connection.
#! @input delimiter: The delimiter to use <sql_command>
#!                   Default: ';'
#! @input sql_commands: All the SQL commands that you want to run using the <delimiter>
#! @input script_file_name: SQL script file name. The command in the file need to have ';' to indicate the end of the command
#!                          Note: this is mutual exclusive with <sqlCommands>
#! @input database_pooling_properties: Properties for database pooling configuration. Pooling is disabled by default.
#!                                     Default: 'db.pooling.enable=false'
#!                                     Example: 'db.pooling.enable=true'
#! @input result_set_type: The result set type. See JDBC folder description for more details.
#!                         Valid values: 'TYPE_FORWARD_ONLY', 'TYPE_SCROLL_INSENSITIVE', 'TYPE_SCROLL_SENSITIVE'.
#!                         Default value: 'TYPE_SCROLL_INSENSITIVE' except DB2 which is overridden to 'TYPE_FORWARD_ONLY'
#! @input result_set_concurrency: The result set concurrency. See JDBC folder description for more details.
#!                                Valid values: 'CONCUR_READ_ONLY', 'CONCUR_UPDATABLE'
#!                                Default value: 'CONCUR_READ_ONLY'
#!
#! @output return_code: -1 if an error occurred while running the script, 0 otherwise.
#! @output return_result: The result of the script.
#! @output exception: The error message if something went wrong while executing the script.
#! @output update_count: How many rows were affected by the script.
#!
#! @result SUCCESS: If the script executed successfully.
#! @result FAILURE: If there was an error while executing the script.
#!!#
########################################################################################################################

namespace: io.cloudslang.base.database

operation:
  name: sql_script

  inputs:
    - db_server_name
    - dbServerName:
        default: ${get('db_server_name', '')}
        required: false
        private: true
    - db_type:
        required: false
    - dbType:
        default: ${get('db_type', '')}
        required: false
        private: true
    - username
    - password:
        sensitive: true
    - instance:
        required: false
    - db_port:
        required: false
    - DBPort:
        default: ${get('db_port', '')}
        required: false
        private: true
    - database_name
    - databaseName:
        default: ${get('database_name', '')}
        required: false
        private: true
    - authentication_type:
        default: 'sql'
        required: false
    - authenticationType:
        default: ${get('authentication_type', '')}
        required: false
        private: true
    - db_class:
        required: false
    - dbClass:
        default: ${get('db_class', '')}
        required: false
        private: true
    - db_url:
        required: false
    - dbURL:
        default: ${get('db_url', '')}
        required: false
        private: true
    - delimiter:
        default: ';'
        required: false
    - sql_commands:
        required: false
    - sqlCommands:
        default: ${get('sql_commands', '')}
        required: false
        private: true
    - script_file_name:
        required: false
    - scriptFileName:
        default: ${get('script_file_name', '')}
        required: false
        private: true
    - database_pooling_properties:
        required: false
    - databasePoolingProperties:
        default: ${get('database_pooling_properties', '')}
        required: false
        private: true
    - result_set_type:
        required: false
    - resultSetType:
        default: ${get('result_set_type', '')}
        required: false
        private: true
    - result_set_concurrency:
        default: 'CONCUR_READ_ONLY'
        required: false
    - resultSetConcurrency:
        default: ${get('result_set_concurrency', '')}
        required: false
        private: true

  java_action:
    gav: 'io.cloudslang.content:cs-database:0.0.1'
    class_name: io.cloudslang.content.database.actions.SQLScript
    method_name: execute

  outputs:
    - return_code: ${returnCode}
    - return_result: ${returnResult}
    - exception: ${exception}
    - update_count: ${updateCount}

  results:
    - SUCCESS: ${returnCode=='0'}
    - FAILURE
