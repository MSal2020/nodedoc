const fs = require('fs');
const express = require('express')
const session = require('express-session');
const app = express()
const path = require('path')
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
var { randomBytes } = require('crypto');
const connection = mysql.createConnection({ //TODO: env vars OR store credentials within Azure Key Vault
    host: '20.198.203.106',
    user: 'MPadmin1',
    database: 'testdb',
    password: '$$admin1',
    ssl:{
        ca: fs.readFileSync(__dirname + '/certificates/DigiCertGlobalRootCA.crt.pem')
    }
});

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
app.use(express.static(path.join(__dirname, 'static')));

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
		connection.execute('SELECT `password` FROM `testdb`.`users` WHERE email = ?', [email], function(error, results) {
			if (error) throw error;
			if (results.length > 0) {
				if (bcrypt.compareSync(password, results[0].password))
				{
					request.session.loggedin = true;
					request.session.email = email;
					// Redirect to home page
					response.redirect('/home');
				}
				else{
					response.send('Incorrect email and/or Password!');
				}
			} else {
				response.send('Incorrect email and/or Password!');
			}			
			response.end();
		});
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
		connection.execute('SELECT * FROM `testdb`.`users` WHERE email=?', [email], function(error, results){
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
		})
	}
})

app.get('/home', function(request, response) {
	if (request.session.loggedin) {
		//regen sid

		
		response.send('Welcome back, ' + request.session.email + '!');
	} else {
		response.send('Please login to view this page!');
	}
	response.end();
});


// use port 3000 unless there exists a preconfigured port
var port = process.env.PORT || 3000;

app.listen(port);
