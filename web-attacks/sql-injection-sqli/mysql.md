# MySQL

Some of the queries in the table below can only be run by an admin. These are marked with **\(PRIV\)** at the description.

### Version

```sql
SELECT @@version;
```

### Comments

```sql
SELECT 1; #comment
SELECT /*comment*/1;
```

### Current User

```sql
SELECT user();
SELECT system_user;
```

### List Users \(PRIV\)

```sql
SELECT user FROM mysql.user;
```

### List Password Hashes \(PRIV\)

```sql
SELECT host, user, password FROM mysql.user;
```

### List Privileges \(PRIV\)

```sql
#List user privileges
SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges

#List privs on databases (schemas)
SELECT grantee, table_schema, privilege_type FROM information_schema.schema_privileges;

#List privs on columns
SELECT table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges;
```

### List DBA Accounts \(PRIV\)

```sql
SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'SUPER';
SELECT host, user FROM mysql.user WHERE Super_priv = 'Y';
```

### Current Database

```sql
SELECT database();
```

### List Databases

```sql
SELECT schema_name FROM information_schema.schemata;
SELECT distinct(db) FROM mysql.db
```

### List Tables

```sql
SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema'
```

### List Columns

```sql
SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE table_schema != 'mysql' AND table_schema != 'information_schema'
```

### Find Tables from Column Name

```sql
#If you want to list all the table names that contain a column LIKE '%password%':
SELECT table_schema, table_name FROM information_schema.columns WHERE column_name = 'password';
```

### Hostname, IP Address

```sql
SELECT @@hostname;
```

### Create Users \(PRIV\)

```sql
CREATE USER test1 IDENTIFIED BY 'pass1';
```

### Delete Users \(PRIV\)

```sql
DROP USER test1;
```

### Make User DBA \(PRIV\)

```sql
GRANT ALL PRIVILEGES ON *.* TO test1@'%';
```

### Location of DB Files

```sql
SELECT @@datadir;
```

### Read Files \(PRIV\)

```sql
SELECT LOAD_FILE('/etc/passwd');
```

### Write Files \(PRIV\)

```sql
SELECT * FROM mytable INTO dumpfile '/tmp/somefile';
```

