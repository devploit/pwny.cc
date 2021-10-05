# PostgreSQL

Some of the queries in the table below can only be run by an admin. These are marked with **\(PRIV\)** at the description.

### Version

```sql
SELECT version();
```

### Comments

```sql
SELECT 1; --comment
SELECT /*comment*/1;
```

### Current User

```sql
SELECT user;
SELECT current_user;
SELECT session_user;
SELECT getpgusername();
```

### List Users

```sql
SELECT usename FROM pg_user;
```

### List Password Hashes \(PRIV\)

```sql
SELECT usename, passwd FROM pg_shadow;
```

### List Privileges

```sql
SELECT usename, usecreatedb, usesuper, usecatupd FROM pg_user;
```

### List DBA Accounts

```sql
SELECT usename FROM pg_user WHERE usesuper IS TRUE;
```

### Check if Current User is Superuser

```sql
SELECT current_setting('is_superuser')='on';
```

### Current Database

```sql
SELECT current_database();
```

### List Databases

```sql
SELECT datname FROM pg_database;
```

### List Tables

```sql
SELECT c.relname FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r','') AND n.nspname NOT IN ('pg_catalog', 'pg_toast') AND pg_catalog.pg_table_is_visible(c.oid);
```

### List Columns

```sql
SELECT relname, A.attname FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE (C.relkind='r') AND (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE 'public');
```

### Find Tables from Column Name

```sql
#If you want to list all the table names that contain a column LIKE '%password%':
SELECT DISTINCT relname FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE (C.relkind='r') AND (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE 'public') AND attname LIKE '%password%';
```

### Hostname, IP Address

```sql
#Returns db server IP address (or null if using local connection) 
SELECT inet_server_addr();

#Returns db server port
SELECT inet_server_port();
```

### Create Users \(PRIV\)

```sql
CREATE USER test1 PASSWORD 'pass1';

#Grant some privs at the same time
CREATE USER test1 PASSWORD 'pass1' CREATEUSER;
```

### Delete Users \(PRIV\)

```sql
DROP USER test1;
```

### Make User DBA \(PRIV\)

```sql
ALTER USER test1 CREATEUSER CREATEDB;
```

### Location of DB Files \(PRIV\)

```sql
SELECT current_setting('data_directory');
SELECT current_setting('hba_file');
```

### Read Files \(PRIV\)

```sql
COPY passwords from $$c:\passwords.txt$$;
SELECT content from passwords;
```

### Write Files \(PRIV\)

```sql
CREATE temp table passwords (content text);
COPY (SELECT $$passwords$$) to $$c:\passwords.txt$$;
```

