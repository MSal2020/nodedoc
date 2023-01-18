const fs = require('fs');
const mysql = require('mysql2');
const connection = mysql.createConnection({ //TODO: env vars OR store credentials within Azure Key Vault
    host: '20.198.203.106',
    user: 'MPadmin1',
    database: 'testdb',
    password: '$$admin1',
    ssl:{
        ca: fs.readFileSync(__dirname + '/certificates/DigiCertGlobalRootCA.crt.pem')
    }
});

connection.query(
    'SELECT id,userID,bpm FROM `testdb`.`heartrate`;',
    function(err, results) {
        if (err) throw err;
        // connected!
        console.log(results); // results contains rows returned by server
    }
);

//prepared statements
connection.execute(
    'SELECT * FROM `testdb`.`heartrate` WHERE `userID` = ?',
    [2],
    function(err, results) {
        if (err) throw err;
        console.log(results); // results contains rows returned by server
    }
);