# Decrypt-OrchestratorVariables

In Orchestrator, it is possible to create variables that can be used in runbooks. One of the possibilities is to store credentials in these variables. These variables can then be used to authenticate with other systems. Runbooks can use these variables to create an authenticated session towards the target system and run all the steps that are defined in the runbook in the context of the credentials that are specified in the variable.
Information, such as passwords, that is of a sensitive nature can be encrypted by using encrypted variables. The contents of these variables are stored encrypted in the database when they are created and are decrypted when they are used in the runbooks. 

For the encryption process, Orchestrator uses the internal encryption functionality of Microsoft SQL server. The decryption keys are stored in the SYS database and have to be loaded in to the SQL session in order to decrypt data. If a user account has access to the SYS database as well as the Orchestrator database the data can be decrypted. More information can be found in the following blogpost: <https://blog.fox-it.com/2018/05/09/introducing-orchestrator-decryption-tool/>

To automate this process, Decrypt-OrchestratorVariables was created.
Usage:

```
    Required parameters:
        DatabaseServer  : DatabaseServer. <localhost\SQLEXPRESS>
        database        : Name of the database. Defaults to Orchestrator
  
    Optional parameters:
        dbaUsername     : DBA Username
        dbaPassword     : DBA Password


    The tool will use integrated authentication, unless dbaUsername and dbaPassword are specified. 
    MSSQL integrated login will then be used.

    Usage: ./Decrypt-OrchestratorVariables.ps1 -databaseServer <location>`r`n   
```
