# MSSQL

Some of the queries in the table below can only be run by an admin. These are marked with **\(PRIV\)** at the description.

### Version

```sql
SELECT @@version;
```

### Comments

```sql
SELECT 1 -- comment
SELECT /*comment*/1
```

### Current User

```sql
SELECT user_name();
SELECT system_user;
SELECT user;
SELECT loginame FROM master..sysprocesses WHERE spid == @@SPID
```

### List Users

```sql
SELECT name FROM master..syslogins
```

### List Password Hashes \(PRIV\)

```sql
#MSSQL 2000
SELECT name, password FROM master..sysxlogins;

#MSSQL 2000. Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer.
SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins;

#MSSQL 2005
SELECT name, password_hash FROM master.sys.sql_logins;

#MSSQL 2005
SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins;
```

### List Privileges

```sql
#Current privs on a particular object in 2005, 2008
##Current database
SELECT permission_name FROM master..fn_my_permissions(null, 'DATABASE');
##Current server
SELECT permission_name FROM master..fn_my_permissions(null, 'SERVER');
##Permissions on a table
SELECT permission_name FROM master..fn_my_permissions('master..syslogins', 'OBJECT');
SELECT permission_name FROM master..fn_my_permissions('sa', 'USER');

#Permissions on a user-current privs in 2005, 2008
SELECT is_srvrolemember('sysadmin');
SELECT is_srvrolemember('dbcreator');
SELECT is_srvrolemember('bulkadmin');
SELECT is_srvrolemember('diskadmin');
SELECT is_srvrolemember('processadmin');
SELECT is_srvrolemember('serveradmin');
SELECT is_srvrolemember('setupadmin');
SELECT is_srvrolemember('securityadmin');

#Who has a particular priv? 2005, 2008
SELECT name FROM master..syslogins WHERE denylogin = 0;
SELECT name FROM master..syslogins WHERE hasaccess = 1;
SELECT name FROM master..syslogins WHERE isntname = 0;
SELECT name FROM master..syslogins WHERE isntgroup = 0;
SELECT name FROM master..syslogins WHERE sysadmin = 1;
SELECT name FROM master..syslogins WHERE securityadmin = 1;
SELECT name FROM master..syslogins WHERE serveradmin = 1;
SELECT name FROM master..syslogins WHERE setupadmin = 1;
SELECT name FROM master..syslogins WHERE processadmin = 1;
SELECT name FROM master..syslogins WHERE diskadmin = 1;
SELECT name FROM master..syslogins WHERE dbcreator = 1;
SELECT name FROM master..syslogins WHERE bulkadmin = 1;
```

### List DBA Accounts

```sql
#Is your account a sysadmin?  returns 1 for true, 0 for false, NULL for invalid role.  Also try ‘bulkadmin’, ‘systemadmin’.
SELECT is_srvrolemember('sysadmin');

#Is sa a sysadmin? return 1 for true, 0 for false, NULL for invalid role/username.
SELECT is_srvrolemember('sysadmin', 'sa');

#MSSQL 2005
SELECT name FROM master..syslogins WHERE sysadmin = '1';
```

### Current Database

```sql
SELECT DB_NAME();
```

### List Databases

```sql
SELECT name FROM master..sysdatabases;
SELECT DB_NAME(N);
```

### List Tables

```sql
#Use xtype = 'V' for views
SELECT name FROM master..sysobjects WHERE xtype = 'U';
SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U';

#List colum names and types for master..sometable
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';
```

### List Columns

```sql
#For current DB only
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');

#List colum names and types for master..sometableFind Tables from Column Name
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable'; 
```

### Find Tables from Column Name

```sql
#This lists table, column for each column containing the word 'password'
SELECT sysobjects.name as tablename, syscolumns.name as columnname FROM sysobjects JOIN syscolumns ON sysobjects.id = syscolumns.id WHERE sysobjects.xtype = 'U' AND syscolumns.name LIKE '%PASSWORD%';
```

### Hostname, IP Address

```sql
SELECT HOST_NAME();
```

### Create Users \(PRIV\)

```sql
EXEC sp_addlogin 'user', 'pass';
```

### Delete Users \(PRIV\)

```sql
EXEC sp_droplogin 'user';
```

### Make User DBA \(PRIV\)

```sql
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin';
```

### Location of DB Files

```sql
#Location of master.mdf
EXEC sp_helpdb master;

#Location of pubs.mdf
EXEC sp_helpdb pubs; 
```

### Command Execution \(PRIV\)

```sql
#On MSSQL 2005 you may need to reactivate xp_cmdshell first as it’s disabled by default
EXEC xp_cmdshell 'net user';
--
EXEC sp_configure 'show advanced options', 1; 
RECONFIGURE;

EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

