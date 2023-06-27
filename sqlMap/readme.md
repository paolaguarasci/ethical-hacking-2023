SQLMap supporta le injection di tipo

B: Boolean-based blind
E: Error-based
U: Union query-based
S: Stacked queries
T: Time-based blind
Q: Inline queries

automatic mode
--batch --dump

injection mask 
--cookie="id=1*"

display error db
--parse-errors

store traffic
-t /tmp/traffic.txt

verbose output
-v 6

prefissi e sufissi
--prefix="%'))" --suffix="-- -"

level
--level (1-5, default 1)

risk
--risk (1-3, default 1) 

no cast content
--no-cast


enumerate databases
--dbs 

enumetare tables in specific db
-D <database_name> --tables

enumerate columns in specifica table in specific db
-D <database_name> -T <table_name> --columns
