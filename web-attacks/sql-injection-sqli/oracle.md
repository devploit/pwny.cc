# Oracle

Some of the queries in the table below can only be run by an admin. These are marked with **\(PRIV\)** at the description.

### Version

```sql
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';
SELECT banner FROM v$version WHERE banner LIKE 'TNS%';
SELECT version FROM v$instance;
```

### Comments

```sql
SELECT 1; -- comment
```

### Current User

```sql
SELECT user FROM dual;
```

### List Users

```sql
SELECT username FROM all_users ORDER BY username;
SELECT name FROM sys.user$;
```

### List Password Hashes \(PRIV\)

```sql
#Oracle version <= 10g
SELECT name, password, astatus FROM sys.user$. astatus tells you if acct is locked

#Oracle version 11g
SELECT name,spare4 FROM sys.user$
```

### List Privileges \(PRIV\)

```sql
SELECT FROM session_privs;
SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS;

#List a user's privs
SELECT FROM dba_sys_privs WHERE grantee = 'DBSNMP';

#Find users with a particular priv
SELECT grantee FROM dba_sys_privs WHERE privilege = 'SELECT ANY DICTIONARY'; 
```

### List DBA Accounts \(PRIV\)

```sql
SELECT DISTINCT grantee FROM dba_sys_privs WHERE ADMIN_OPTION = 'YES';
```

### Current Database

```sql
SELECT global_name FROM global_name;
SELECT name FROM v$database;
SELECT instance_name FROM v$instance;
SELECT SYS.DATABASE_NAME FROM DUAL;
```

### List Databases

```sql
#List schemas (one per user)
SELECT DISTINCT owner FROM all_tables;
```

### List Tables

```sql
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;
```

### List Columns

```sql
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah' and owner = 'foo';
```

### Find Tables from Column Name

```sql
#NB: table names are upper case
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';
```

### Hostname, IP Address

```sql
SELECT UTL_INADDR.get_host_name FROM dual;
SELECT host_name FROM v$instance;

#Gets IP address
SELECT UTL_INADDR.get_host_address FROM dual;

#Gets hostnames
SELECT UTL_INADDR.get_host_name(’10.0.0.1′) FROM dual;
```

### Location of DB Files

```sql
SELECT name FROM V$DATAFILE;
```

### Get all tablenames in One String

```sql
#When using union based SQLi with only one row
SELECT rtrim(xmlagg(xmlelement(e, table_name || ',')).extract('//text()').extract('//text()') ,',') from all_tables 
```

