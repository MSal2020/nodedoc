const fs = require('fs');
const express = require('express')
const session = require('express-session');
const app = express()
const path = require('path')
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
var { randomBytes } = require('crypto');
/*const connection = mysql.createConnection({ //TODO: env vars OR store credentials within Azure Key Vault
    host: '20.198.203.106',
    user: 'MPadmin1',
    database: 'testdb',
    password: '$$admin1',
    ssl:{
        ca: fs.readFileSync(__dirname + '/certificates/DigiCertGlobalRootCA.crt.pem')
    }
});*/
var Connection = require('tedious').Connection;	//TODO: Azure Key Vault
var config = {
    server: 'mpserver2.database.windows.net', 
    authentication: {
        type: 'default',
        options: {
            userName: 'mplogin123', 
            password: 'majorp123#' 
        }
    },
    options: {
        encrypt: true,
        database: 'testdb' 
    }
};
//var connection = new Connection(config);
const getDBConnection = async () => {
    if(connection) return connection;
       connection = new Connection(config);
};



//NIST SP 800-63B Session Management https://pages.nist.gov/800-63-3/sp800-63b.html
const expiryMSec = 60 * 60 * 1000
app.use(session({ //TODO: Azure Key Vault
	secret: 'd20A(WUI#@DM^129uid^J',
	name: 'id1',
	resave: false,
	saveUninitialized: false,
	cookie: { //TODO: Implement https
		//secure: true
		httpOnly: true,
		maxAge: expiryMSec,
		sameSite: 'lax'
	}
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('views'))

app.get('/', function (request, response) {
	response.sendFile(path.join(__dirname + '/welcome.html'));
	response.cookie("id1", "", { expires: new Date() });
	if (request.session.csrf === undefined) {
		request.session.csrf = randomBytes(100).toString('base64'); // convert random data to a string
	}
	//response.render('index', { title: 'Express', token: request.session.csrf });
})

app.get('/signup', function (request, response) {
	response.sendFile(path.join(__dirname + '/signup.html'));
	response.cookie("id1", "", { expires: new Date() });
	if (request.session.csrf === undefined) {
		request.session.csrf = randomBytes(100).toString('base64'); // convert random data to a string
	}
})
app.post('/auth', function(request, response) {
  	let email = request.body.email;
	let password = request.body.password;
	//TODO: regex
	if (email && password) {
		var connection = new Connection(config);
		connection.on('connect', function (err) 
		{var Request = require('tedious').Request;var TYPES = require('tedious').TYPES;    
			var sql = 'select * from dbo.users where email = @email';
			var dbrequest = new Request(sql, function (err,rowCount) 
			{
				if (err) {console.log(err);} 
				else {
					if (rowCount == 0) {
						response.send('Incorrect email and/or Password!');
					}
				}
			});
			var resultArray = []
			dbrequest.on('row', function(columns) {
				columns.forEach(function(column){
					if (column.value === null) {response.send('Incorrect email and/or Password!');}
					else{
						resultArray.push(column.value);
					}
				})
			});

			dbrequest.addParameter('email', TYPES.VarChar, email);

			dbrequest.on("requestCompleted", function (rowCount, more) {
				if (bcrypt.compareSync(password, resultArray[2]))
				{
					request.session.loggedin = true;
					request.session.email = resultArray[1];
					request.session.deviceID = resultArray[0];
					request.session.age = resultArray[3]
					response.redirect('/userdashboard');
				}
				else{
					response.send('Incorrect email and/or Password!');
				}
		connection.close();
			});
			connection.execSql(dbrequest);
		});
		connection.connect();

	} else {
		response.send('Please enter Email and Password!');
		response.end();
	}
});
app.post('/createUser', function(request, response){
	let email = request.body.email;
	let password = request.body.password;
	let age = request.body.age;
	//TODO: regex

	if (email && password && age){
		var connection = new Connection(config);
		connection.on('connect', function (err) 
		{var Request = require('tedious').Request;var TYPES = require('tedious').TYPES;    
			var sql = 'select email from dbo.users where email = @email';
			var dbrequest = new Request(sql, function (err,rowCount) 
			{
				if (err) {console.log(err);} 
				else {
					if (rowCount > 0) {
						response.send('Email already exists!');
					}
					else{
						const hashedPassword = bcrypt.hashSync(password, 10);

						var connection2 = new Connection(config);
						connection2.on('connect', function (err) 
						{var Request = require('tedious').Request;var TYPES = require('tedious').TYPES;    
							var sql2 = 'INSERT INTO dbo.users (email, password, age) VALUES (@emailparam,@passwordparam,@ageparam);';
							var dbrequest2 = new Request (sql2, function (err,rowCount){
								if (err) {console.log(err);} 
							});
							dbrequest2.addParameter('emailparam', TYPES.VarChar, email);
							dbrequest2.addParameter('passwordparam', TYPES.VarChar, hashedPassword);
							dbrequest2.addParameter('ageparam', TYPES.Int, age);

							dbrequest2.on("requestCompleted", function (rowCount, more) {
								connection2.close();
								request.session.loggedin = true;
								request.session.email = email;
								request.session.age = age
								response.redirect('/userdashboard');	
								response.end();
							});
    						connection2.execSql(dbrequest2);
						});
						connection2.connect();
					}
				}
			});

			dbrequest.addParameter('email', TYPES.VarChar, email);

			dbrequest.on("requestCompleted", function (rowCount, more) {
				console.log(rowCount)
				
				connection.close();
			});
			connection.execSql(dbrequest);
		});
		connection.connect();
		
		
		/*connection.execute('SELECT * FROM `testdb`.`users` WHERE email=?', [email], function(error, results){
			if (error) throw error;
			if (results.length > 0) {
				response.send('Email already exists!');
			}
			else{
				const hashedPassword = bcrypt.hashSync(password, 10);
				connection.execute('INSERT INTO `testdb`.`users` (`email`,`password`,`age`) VALUES (?,?,?);', [email, hashedPassword, age], function(error, results) {
					// If there is an issue with the query, output the error
					if (error) throw error;
					request.session.loggedin = true;
					request.session.email = email;
					response.redirect('/home');	
					response.end();
				});
			}
		})*/
	}
})
/*
app.get('/home', function(request, response) {
	if (request.session.loggedin) {
		//regen sid

		
		response.send('Welcome back, ' + request.session.email + '!');
	} else {
		response.send('Please login to view this page!');
	}
	response.end();
});
*/


//Straight after logging in, ask user to select date
app.get('/userdashboard', function (request, response) 
{
    response.render("afterLogin.ejs")
    if (request.session.loggedin) {
		console.log(request.session)
	}
    else{
        response.send('please login to view dashboard')
        response.end()
    }

})

//After selecting date
app.post('/userdashboard', function (req, response) 
{
    var id = req.session.deviceID;
    var date = (req.body).date
    if (!date)
    {
        response.render("afterLogin.ejs")
    }
    var date1 = req.body

    var startDate = date + "T00:00:00.0000000"
    var endDate = date + "T23:59:59.9999999"

    var connection = new Connection(config);
    connection.on('connect', function (err) 
    {
        // If no error, then good to proceed.  

        var Request = require('tedious').Request;
        var TYPES = require('tedious').TYPES;

     
        var request = new Request("SELECT * FROM [dbo].[t1] WHERE enqueuedTime BETWEEN @startDate AND @endDate AND deviceId = @id ORDER BY enqueuedTime;", function (err) 
        {
            if (err) {
                console.log(err);
            }
        });
    
        request.addParameter('startDate', TYPES.VarChar, startDate);
        request.addParameter('endDate', TYPES.VarChar, endDate);
        request.addParameter('id', TYPES.VarChar, id);
        var result = [];
        var row = []
        var columnnumber = 1


        request.on('row', function (columns) 
        {
            columns.forEach(function (column) {
                if (column.value === null) {
                    console.log('NULL');
                } else {

                    if (columnnumber == 3) {
                        row.push(column.value);
                        result.push(row)
                        row = []
                        columnnumber = 0

                    }
                    else {
                        row.push(column.value);
                    }
                    columnnumber++

                }
            });

        });
        

        
        request.on("requestCompleted", function (rowCount, more) 
        {
            if (result.length <= 0)
            {

                response.render("afterLogin.ejs")
            }           
            
            var data = []
            var heartratetotal = 0 
            var heartratevariabilitytotal = 0 
            var respiratoryRatetotal = 0 
            var diastolictotal = 0 
            var systolictotal = 0 
            var temperaturetotal = 0 
    
            var heartratemax = 0 
            var heartratevariabilitymax = 0 
            var respiratoryRatemax = 0 
            var diastolicmax = 0 
            var systolicmax = 0 
            var temperaturemax = 0 
            
            var heartratemin = 1000 
            var heartratevariabilitymin= 1000 
            var respiratoryRatemin= 1000
            var diastolicmin = 1000 
            var systolicmin = 1000 
            var temperaturemin = 1000 
            for (let index = 0; index < result.length; index++) 
            {
                
                row = result[index]
                var date = row[1]
                var readings = JSON.parse(row[2])
                var heartrate = readings.HeartRate
                var heartratevariability = readings.HeartRateVariability
                var respiratoryRate = readings.RespiratoryRate
                var diastolic = (readings.BloodPressure).Diastolic
                var systolic = (readings.BloodPressure).Systolic
                var temperature = (5/9) * (readings.BodyTemperature - 32)
                var reading = {heartrate: heartrate, heartratevariability: heartratevariability, respiratoryRate: respiratoryRate, diastolic: diastolic, systolic: systolic, temperature: temperature, date: date}
                data.push(reading)

                if (heartrate > heartratemax)
                {
                    heartratemax = heartrate
                }
                else if (heartrate < heartratemin)
                {
                    heartratemin = heartrate
                }
                if (heartratevariability > heartratevariabilitymax)
                {
                    heartratevariabilitymax = heartratevariability
                }
                else if (heartratevariability < heartratevariabilitymin)
                {
                    heartratevariabilitymin = heartratevariability
                }
                if (respiratoryRate > respiratoryRatemax)
                {
                    respiratoryRatemax = respiratoryRate
                }
                else if (respiratoryRate < respiratoryRatemin)
                {
                    respiratoryRatemin = respiratoryRate
                }
                if (diastolic > diastolicmax)
                {
                    diastolicmax = diastolic
                }
                else if (diastolic < diastolicmin)
                {
                    diastolicmin = diastolic
                }
                if (systolic > systolicmax)
                {
                    systolicmax = systolic
                }
                else if (systolic < systolicmin)
                {
                    systolicmin = systolic
                }
                if (temperature > temperaturemax)
                {
                    temperaturemax = temperature
                }
                else if (temperature < temperaturemin)
                {
                    temperaturemin = temperature
                }
                
                heartratetotal += heartrate
                heartratevariabilitytotal += heartratevariability
                respiratoryRatetotal += respiratoryRate
                diastolictotal += diastolic
                systolictotal += systolic
                temperaturetotal += temperature 

            }
            heartrateavg = heartratetotal / result.length
            heartratevariabilityavg = heartratevariabilitytotal / result.length
            respiratoryRateavg = respiratoryRatetotal / result.length
            diastolicavg = diastolictotal / result.length
            systolicavg = systolictotal / result.length
            temperatureavg = temperaturetotal / result.length


            averages = [{ heartratemin: heartratemin, heartratevariabilitymin: heartratevariabilitymin,respiratoryRatemin: respiratoryRatemin,respiratoryRatemin: respiratoryRatemin,diastolicmin: diastolicmin,systolicmin: systolicmin, temperaturemin, temperaturemin, heartratemax: heartratemax, heartratevariabilitymax: heartratevariabilitymax, respiratoryRatemax: respiratoryRatemax, diastolicmax: diastolicmax, systolicmax: systolicmax, temperaturemax: temperaturemax, heartrateavg: heartrateavg, heartratevariabilityavg: heartratevariabilityavg, respiratoryRateavg: respiratoryRateavg, systolicavg: systolicavg, diastolicavg: diastolicavg, temperatureavg: temperatureavg, }]

            response.render("billboard.ejs", { data: data, averages: averages, date1: date1 })

            connection.close();
        });
     
        connection.execSql(request);

    });

    connection.connect();
    

})
var port = process.env.PORT || 3000;
app.listen(port)  
