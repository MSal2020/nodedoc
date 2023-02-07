(async function() {
const fs = require('fs');
const express = require('express')
const session = require('express-session');
const MemoryStore = require('memorystore')(session)
const app = express()
const path = require('path')
const bcrypt = require('bcrypt');
var { randomBytes } = require('crypto');
const {verify} = require('hcaptcha');
const cheerio = require("cheerio");
const OTPAuth = require('otpauth')
var QRCode = require('qrcode')
var parser = require('ua-parser-js');
var _ = require('lodash');
let server = require( 'http' ).Server( app );
let io = require( 'socket.io' )( server );
let stream = require( './ws/stream' );
const { SecretClient } = require("@azure/keyvault-secrets");
const { DefaultAzureCredential, EnvironmentCredential } = require("@azure/identity");
const sleep = require('util').promisify(setTimeout)
const cors = require('cors');
require('dotenv').config()
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('views'))
app.use(express.static('template'))


//Azure Key Vault
async function KVRetrieve(secretName) {
    const credential = new DefaultAzureCredential();
  
    const keyVaultName = process.env.KEY_VAULT_NAME;
    const url = "https://" + keyVaultName + ".vault.azure.net";
  
    const client = new SecretClient(url, credential);
    const secret = await client.getSecret(secretName);
    return secret.value
}

//CORS
app.use(
    cors({
      origin: ["https://aidochealth.azurewebsites.net"],
      methods: ["GET", "POST"],
      credentials: true,
    })
);
app.use(function (request,response,next){
    response.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
})

//Session Management
//NIST SP 800-63B Session Management https://pages.nist.gov/800-63-3/sp800-63b.html
app.set('trust proxy', true)
const expiryMSec = 60 * 60 * 1000 * 3;
const sessionKVSecret = await KVRetrieve('sessionSecret')
app.use(session({
    secret: sessionKVSecret,
    store: new MemoryStore({
        checkPeriod: 86400000 // prune expired entries every 24h
    }),
    name: 'id1',
    resave: false,
    saveUninitialized: false,
    cookie: {
        domain: 'aidochealth.azurewebsites.net',
        secure: true,
        httpOnly: true,
        maxAge: expiryMSec,
        sameSite: 'lax'
    },
    proxy:true
}));

//OpenAI Configuration
const { Configuration, OpenAIApi } = require("openai");
const openAPIKEYKVSecret = await KVRetrieve('OPENAI-API-KEY');
const configuration = new Configuration({
    apiKey: openAPIKEYKVSecret,
});
const openai = new OpenAIApi(configuration);

//Database Connection
var Connection = require('tedious').Connection;	
const dbserverURL= process.env.DB_URL;
const dbUsernameKVSecret = await KVRetrieve('SQLdbUsername');
const dbPasswordKVSecret = await KVRetrieve('SQLdbPassword');
var config = {
    server: dbserverURL, 
    authentication: {
        type: 'default',
        options: {
            userName: dbUsernameKVSecret, 
            password: dbPasswordKVSecret 
        }
    },
    options: {
        encrypt: true,
        database: 'testdb' 
    }
};

//HCaptcha Secret
const hcaptchaSecret = await KVRetrieve('hCaptchaAPI');

//2FA
function totpSecretGenerate(){
    var secretSeed = new OTPAuth.Secret({
        size: 10
    })
    return secretSeed.base32
}
function totpURIGenerate(){
    var secretSeed = totpSecretGenerate()
    var totp = new OTPAuth.TOTP({
        issuer: "TP Health Website",
        label: "TP",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        secret: secretSeed
    });
    return [totp.toString(), secretSeed]
}
function totpSeedtoGenerateToken(arg1){
    var totp = new OTPAuth.TOTP({
        issuer: "TP Health Website",
        label: "TP",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        secret: arg1
    });
    return totp.generate()
}
function totpURItoQRCode(){
    var [totpURI, secretSeed] = totpURIGenerate()
    return [QRCode.toString(totpURI,{type: 'svg'},  function (err, string) {
        if (err) throw err
        return(string)
    }), secretSeed]
}
app.post('/checkTOTP', function(request,response){
    var secretSeed = request.body.seed
    var totp = new OTPAuth.TOTP({
        issuer: "TP Health Website",
        label: "TP",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        secret: secretSeed
    });
    response.json({'bean': totp.generate()})
})

//redos-safe regex, checked by https://devina.io/redos-checker
//also, password policy: at least 1 uppercase, 1 lowercase, 1 number and 1 symbol, between 8 to 50 chars
const reEmail = /^([a-z0-9\+_\-]+)(\.[a-z0-9\+_\-]+)*@([a-z0-9\-]+\.)+[a-z]{2,6}$/i;
const reEmail2 = /^.{1,50}$/
const rePassword = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,50}$/
const reCsrf = /^[a-z0-9+/=]{136,136}$/i
const reCaptcha = /^[a-z0-9-_.]{1,5000}$/i
const reTFAToken = /^[0-9]{6,6}$/i
const reDeviceID = /^[0-9a-z]{11,11}$/i
const reFirstName = /^[a-z]{1,100}$/i
const reAge = /^([1-9]|[1-9][0-9]|[1][0-9][0-9]|20[0-0])$/i
const reTFASeed = /^[A-Z0-9]{16,16}$/
function regexTest(arg1, arg2){
    var pattern = arg1
    return pattern.test(arg2)
}

//SessionArray Promise
const waitForSession = (sessionCheck, timeout = 5000) => {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        clearInterval(intervalId);
        reject(new Error('Timeout reached without session array being populated'));
      }, timeout);
  
      const intervalId = setInterval(() => {
        if (sessionCheck == true) {
          clearTimeout(timer);
          clearInterval(intervalId);
          resolve(sessionCheck);
        }
      }, 100);
    });
};

//Routes
app.get('/', async function (request, response) {
    if(request.session.loggedin == true){
        response.redirect('./userdashboard')
    }
    else{
        if (request.session.csrf === undefined) {
            request.session.sessionCheck = true
            request.session.csrf = randomBytes(100).toString('base64'); // convert random data to a string
            fs.readFile('home_guest.html', "utf8", function(err, data) {
                if (err) throw err;
            
                var $ = cheerio.load(data);
            
                $(".csrftoken").attr('value', request.session.csrf)
                response.send($.html());
            });
        }
        else {
            request.session.sessionCheck = true
            fs.readFile('home_guest.html', "utf8", function(err, data) {
                if (err) throw err;
            
                var $ = cheerio.load(data);
            
                $(".csrftoken").attr('value', request.session.csrf)
                response.send($.html());
            });
        }
    }
})
	
app.get('/welcome', function (request, response) {
	
	if(request.session.loggedin == true){
        response.redirect('./userdashboard')
    }
    else{
        if (request.session.csrf === undefined) {
            request.session.sessionCheck = true
            request.session.csrf = randomBytes(100).toString('base64'); // convert random data to a string
            fs.readFile('welcome.html', "utf8", function(err, data) {
                if (err) throw err;
            
                var $ = cheerio.load(data);
            
                $(".csrftoken").attr('value', request.session.csrf)
                response.send($.html());
            });
        }
        else {
            request.session.sessionCheck = true
            fs.readFile('welcome.html', "utf8", function(err, data) {
                if (err) throw err;
            
                var $ = cheerio.load(data);
            
                $(".csrftoken").attr('value', request.session.csrf)
                response.send($.html());
            });
        }
    }
})
	

app.get('/home_guest', function (request, response) {
	
	if(request.session.loggedin == true){
        response.redirect('./userdashboard')
    }
    else{
        if (request.session.csrf === undefined) {
            request.session.sessionCheck = true
            request.session.csrf = randomBytes(100).toString('base64'); // convert random data to a string
            fs.readFile('home_guest.html', "utf8", function(err, data) {
                if (err) throw err;
            
                var $ = cheerio.load(data);
            
                $(".csrftoken").attr('value', request.session.csrf)
                response.send($.html());
            });
        }
        else {
            request.session.sessionCheck = true
            fs.readFile('home_guest.html', "utf8", function(err, data) {
                if (err) throw err;
            
                var $ = cheerio.load(data);
            
                $(".csrftoken").attr('value', request.session.csrf)
                response.send($.html());
            });
        }
    }
	
	
})

app.get('/signup', function (request, response) {
	if (request.session.csrf === undefined) {
        request.session.sessionCheck = true
		request.session.csrf = randomBytes(100).toString('base64'); // convert random data to a string
        fs.readFile('signup.html', "utf8", async function(err, data) {
            if (err) throw err;
        
            var $ = cheerio.load(data);
            $(".csrftoken").attr('value', request.session.csrf)

            var [totpQRsvg, secretSeed] = totpURItoQRCode()
            await $(".2fa-qr").html(totpQRsvg)
            await $(".2fa-secret").html(secretSeed)
            await $(".2fa-hidden-Id").attr('value', secretSeed)
        
            
            await response.send($.html());
        });
	}
	else {
        request.session.sessionCheck = true
        fs.readFile('signup.html', "utf8", async function(err, data) {
            if (err) throw err;
        
            var $ = cheerio.load(data);
            $(".csrftoken").attr('value', request.session.csrf)

            var [totpQRsvg, secretSeed] = totpURItoQRCode()
            await $(".2fa-qr").html(totpQRsvg)
            await $(".2fa-secret").html(secretSeed)
            await $(".2fa-hidden-Id").attr('value', secretSeed)

            await response.send($.html());
        });
    }
})
app.post('/auth', async function(request, response) {
    waitForSession(request.session.sessionCheck, 5000)
    .then((sessionCheck) => {
        let email = request.body.email;
        let password = request.body.password;
        let csrf = request.body.csrf;
        let captchaToken = request['body']['h-captcha-response'];
        let tfaTokenInput = request['body']['2faOTP']
        
    
        if(!(regexTest(reEmail,email)) || !(regexTest(reEmail2,email))){
            response.send('Unrecognized Email Format')
        }
        else if(!(regexTest(rePassword,password))){
            response.send('Invalid Password Format')
        }
        else if(!(regexTest(reCsrf,csrf))){
            response.send('Invalid CSRF Token')
        }
        else if(!(regexTest(reCaptcha,captchaToken))){
            response.send('Invalid Captcha')
        }
        else if(!(regexTest(reTFAToken,tfaTokenInput))){
            response.send('OTP Code must be in 6 digit numbers')
        }
        else{
            verify(hcaptchaSecret, captchaToken)
            .then((data) => {
            if (data.success === true) {
                if (email && password && csrf && tfaTokenInput) {
                    if (csrf != request.session.csrf){
                        response.send('Token validation failed!');
                        response.end();
                    }
                    else{
                        var connection = new Connection(config);
                        connection.on('connect', function (err) 
                        {var Request = require('tedious').Request;var TYPES = require('tedious').TYPES;    
                            var sql = 'select * from dbo.users where email = @email';
                            var aFlag
                            var dbrequest = new Request(sql, function (err,rowCount) 
                            {
                                if (err) {console.log(err);console.log('Database Unreachable!'); aFlag = 'Unreachable'} 
                            });
                            var resultArray = []
                            dbrequest.on('row', function(columns) {
                                columns.forEach(function(column){
                                    if (column.value === null) {console.log('Incorrect email and/or Password!');}
                                    else{
                                        resultArray.push(column.value);
                                    }
                                })
                            });
            
                            dbrequest.addParameter('email', TYPES.VarChar, email);
            
                            dbrequest.on("requestCompleted", function (rowCount, more) {
                                if(aFlag == 'Unreachable'){
                                    response.status(400).send('Database Unreachable')
                                }
                                else if(resultArray[2] == undefined){
                                    response.send('Incorrect email and/or Password!');
                                }
                                else if(tfaTokenInput != totpSeedtoGenerateToken(resultArray[4])){
                                    response.send('Wrong OTP Code')
                                }
                                else{
                                    if (bcrypt.compareSync(password, resultArray[2]))
                                    {
                                        var ua = parser(request.headers['user-agent']);
                                        delete ua.device
                                        request.session.sessionCheck = true
                                        request.session.fingerprint = ua
                                        request.session.loggedin = true;
                                        request.session.email = resultArray[1];
                                        request.session.deviceID = resultArray[0];
                                        request.session.age = resultArray[3];
                                        request.session.firstName = resultArray[5];
                                        request.session.role = resultArray[6];
                                        response.redirect('/userdashboard');
                                    }
                                    else{
                                        response.send('Incorrect email and/or Password!');
                                    }
                                }
                                
                        connection.close();
                            });
                            connection.execSql(dbrequest);
                        });
                        connection.connect();
                    }
                } 
                else{
                    response.send('Please enter Email and Password!');
                    response.end();
                }
            } else {
                response.send('Token validation failed!')
                response.end()
            }
            })
            .catch(console.error);
        }
    })
    .catch((error) => {
        console.log(error)
        response.send('sorry session timed out')
        response.end()
    });
});

app.post('/createUser', function(request, response){
    let userdeviceid = request.body.userdeviceid
    let firstName = request.body.firstName
    let email = request.body.email;
	let password = request.body.password;
	let age = request.body.age;
    let csrf = request.body.csrf;
    let captchaToken = request['body']['h-captcha-response'];
    let tfaSeed = request['body']['2faSeed']

    if(!(regexTest(reEmail,email))  || !(regexTest(reEmail2,email))){
        response.send('Unrecognized Email Format')
    }
    else if(!(regexTest(reDeviceID,userdeviceid))){
        response.send('Unrecognized Device ID Format')
    }
    else if(!(regexTest(reFirstName,firstName))){
        response.send('First Name is not recognized')
    }
    else if(!(regexTest(rePassword,password))){
        response.send('Password does not meet Password Policy')
    }
    else if(!(regexTest(reAge,age))){
        response.send('Invalid Age')
    }
    else if(!(regexTest(reCsrf,csrf))){
        response.send('Invalid CSRF Token')
    }
    else if(!(regexTest(reCaptcha,captchaToken))){
        response.send('Invalid Captcha')
    }
    else if(!(regexTest(reTFASeed,tfaSeed))){
        response.send('Invalid TFA Seed')
    }
    else{
        verify(hcaptchaSecret, captchaToken)
        .then((data) => {
            if (data.success === true) {
                if (userdeviceid && firstName && email && password && age && csrf && tfaSeed){
                    if (csrf != request.session.csrf){
                        response.send('Token validation failed!');
                        response.end();
                    }
                    else{
                        var connection = new Connection(config);
                        connection.on('connect', function (err) 
                        {var Request = require('tedious').Request;var TYPES = require('tedious').TYPES;    
                            var sql = 'select email from dbo.users where email = @email';
                            var dbrequest = new Request(sql, function (err,rowCount) 
                            {
                                if (err) {console.log(err); console.log('Database Unreachable!'); response.status(400).send('Database Unreachable')} 
                                else {
                                    if (rowCount > 0) {
                                        response.send('Email already exists!');
                                    }
                                    else{
                                        const hashedPassword = bcrypt.hashSync(password, 10);
        
                                        var connection2 = new Connection(config);
                                        connection2.on('connect', function (err) 
                                        {var Request = require('tedious').Request;var TYPES = require('tedious').TYPES;    
                                            var sql2 = 'INSERT INTO dbo.users (userdeviceid, firstName, email, password, age, tfaSeed, role) VALUES (@userdeviceidparam, @firstNameparam, @emailparam,@passwordparam,@ageparam,@tfaparam, @roleparam);';
                                            var dbrequest2 = new Request (sql2, function (err,rowCount){
                                                if (err) {console.log(err); console.log('Database Unreachable!');} 
                                            });
                                            dbrequest2.addParameter('userdeviceidparam', TYPES.VarChar, userdeviceid)
                                            dbrequest2.addParameter('firstNameparam', TYPES.VarChar, firstName);
                                            dbrequest2.addParameter('emailparam', TYPES.VarChar, email);
                                            dbrequest2.addParameter('passwordparam', TYPES.VarChar, hashedPassword);
                                            dbrequest2.addParameter('ageparam', TYPES.Int, age);
                                            dbrequest2.addParameter('tfaparam', TYPES.VarChar, tfaSeed)
                                            dbrequest2.addParameter('roleparam', TYPES.VarChar, "user")

                                            dbrequest2.on("requestCompleted", function (rowCount, more) {
                                                connection2.close();
                                                var ua = parser(request.headers['user-agent']);
                                                delete ua.device
                                                request.session.sessionCheck = true
                                                request.session.fingerprint = ua
                                                request.session.loggedin = true;
                                                request.session.firstName = firstName;
                                                request.session.email = email;
                                                request.session.age = age
					                        	request.session.firstName = "user";

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
                                //console.log(rowCount)
                                
                                connection.close();
                            });
                            connection.execSql(dbrequest);
                        });
                        connection.connect();
                    }
                }
            } else {
                response.send('Captcha Failed')
                response.end()
            }
        })
        .catch(console.error);
    }    
})


app.get('/logout', async function (req, response) 
{
    if (req.session) {
        req.session.destroy(err => {
                if (err) {
                    response.status(400).send('Unable to log out')
                } else {
                    response.cookie("id1", "", { expires: new Date() });
                    response.redirect("/")
                }
            }
        );
    }
    else {
        response.end()
    }
})


app.get('/userdashboard', async function (req, response) 
{
    waitForSession(req.session.sessionCheck, 10000)
        .then((sessionCheck) => {
            var ua = parser(req.headers['user-agent']);
            delete ua.device
            if (!req.session.loggedin) {
                response.send('please login to view dashboard')
                response.end()
            }
            else if(!(_.isEqual(ua, req.session.fingerprint))){
                response.send('fingerprint change detected')
                response.end()
            }
            else if(req.session.role == 'user'){

                response.sendFile(path.join(__dirname + '/home_user.html'));
            }
            else if(req.session.role == 'doctor')
            {

                var connection = new Connection(config);
                connection.on('connect', function (err) 
                {
                    // If no error, then good to proceed.  
            
                    var Request = require('tedious').Request;
                    var TYPES = require('tedious').TYPES;
            
                    var id = req.session.deviceID;
            
                    var request = new Request("SELECT email, userdeviceid FROM [dbo].[users] WHERE role = 'user'", function (err) 
                    {
                        if (err) {
                            console.log(err);
                        }
                    });
                

                    var result = [];
                    var row = []
                    var columnnumber = 1
            
                    request.on('row', function (columns) 
                    {
                        columns.forEach(function (column) {
            
                            if (column.value === null) {
                                console.log('NULL');
                            } else {
            
                                if (columnnumber == 2) {
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
                        var userdetails = []
                        for (let index = 0; index < result.length; index++)
                        {
                            let row = result[index];
                            userdetails.push({email: row[0], deviceid: row[1]})
                            
                        }
                            response.render("doctorPage.ejs", {userdetails: userdetails})
                                
                        
                        connection.close();
                    });
                
                    connection.execSql(request);
            
                });
            
                connection.connect();
            }

        })
        .catch((error) => {
            console.log(error)
            response.send('sorry session timed out')
            response.end()
        });

	


})

app.get('/userDashboardSelect', function (req, response) {

	    var ua = parser(req.headers['user-agent']);
            delete ua.device
            if (!req.session.loggedin) {
                response.send('please login to view dashboard')
                response.end()
            }
            else if(!(_.isEqual(ua, req.session.fingerprint))){
                response.send('fingerprint change detected')
                response.end()
            }
            else if(req.session.role == 'user'){

                response.render("afterLogin.ejs")
            }
            else if(req.session.role == 'doctor')
            {
		response.redirect("/userdashboard")
	    }
})
	
//After selecting date (only for user acc)
app.post('/userDashboardSelect', function (req, response) 
{
    console.log(req.session.loggedin)

    var ua = parser(req.headers['user-agent']);
    delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user'){

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
    
            var id = req.session.deviceID;
    
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
                else
                {
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
			temperature = Math.round(temperature * 10) / 10
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
                    heartrateavg = Math.round(heartrateavg * 10) / 10
                    heartratevariabilityavg = heartratevariabilitytotal / result.length
                    heartratevariabilityavg = Math.round(heartratevariabilityavg * 10) / 10
                    respiratoryRateavg = respiratoryRatetotal / result.length
                    respiratoryRateavg = Math.round(respiratoryRateavg * 10) / 10
                    diastolicavg = diastolictotal / result.length
                    diastolicavg = Math.round(diastolicavg * 10) / 10
                    systolicavg = systolictotal / result.length
                    systolicavg = Math.round(systolicavg * 10) / 10
                    temperatureavg = temperaturetotal / result.length
                    temperatureavg = Math.round(temperatureavg * 10) / 10
                    let outp;

                    async function runCompletion () {
                        const completion = await openai.createCompletion({
                        model: "text-davinci-003",
                        prompt: "Pretend you are doctor. Based on the following information, you will give medical advice to the patient. You will give recommended treatments as well. If heart rate is over 90 beats per minute, it is too high. If heart rate variability is over 50 milliseconds, it is too high. If respiratory rate is over 13 breaths per minute, it is too high. If diastolic pressure is below 60mmHg, it is too low. If systolic pressure is below 90mmHg, it is too low.\nPatient details:\nHeart rate is " + heartrateavg + " beats per minute.\nBody temperature is " + temperatureavg + " degrees celsius.\nHeart rate variability is  " + heartratevariabilityavg + " milliseconds.\nRespiratory rate is  " + heartratevariabilityavg + " breaths per minute.\nDiastolic pressure is  " + diastolicavg + "mmHg.\nSystolic pressure is  " + systolicavg + "mmHg.\nDoctor:",
                        max_tokens: 1024,
                        temperature: 0,
                        });
                        
                        outp =  completion.data.choices[0].text;
                        
                        
                    }

                    runCompletion().then(() => {
    
    
                        averages = [{ heartratemin: heartratemin, outp: outp, heartratevariabilitymin: heartratevariabilitymin,respiratoryRatemin: respiratoryRatemin,respiratoryRatemin: respiratoryRatemin,diastolicmin: diastolicmin,systolicmin: systolicmin, temperaturemin, temperaturemin, heartratemax: heartratemax, heartratevariabilitymax: heartratevariabilitymax, respiratoryRatemax: respiratoryRatemax, diastolicmax: diastolicmax, systolicmax: systolicmax, temperaturemax: temperaturemax, heartrateavg: heartrateavg, heartratevariabilityavg: heartratevariabilityavg, respiratoryRateavg: respiratoryRateavg, systolicavg: systolicavg, diastolicavg: diastolicavg, temperatureavg: temperatureavg, }]
                       
                        response.render("billboard.ejs", { data: data, averages: averages, date1: date1 })
                    })
        
                    
                }
                
    
                connection.close();
            });
         
            connection.execSql(request);
    
        });
    
        connection.connect();
    }
    else if(req.session.role == 'doctor')
    {

        response.redirect("/userdashboard")
    }

    

        
    
	
   

})
//video call
app.use( '/assets', express.static( path.join( __dirname, 'assets' ) ) );
app.use( '/public', express.static( path.join( __dirname, 'public' ) ) );
app.get( '/call', ( req, res ) => {
    res.sendFile( __dirname + '/call.html' );
} );


io.of( '/stream' ).on( 'connection', stream );

//chatbot
app.get('/bot', (req, res) => {
    
    res.sendFile(path.join(__dirname, '/public/index.html'));
  })

app.get('/chatbot', async (req, res) => {
    res.status(200).send({
      message: 'Hello from DocAI !!'
    })
  })
var convo = ("Pretend you are doctor named DocAI. You are helpful, creative, clever, and very friendly. You are talking to a patient. Answer with medical advice.\nThis is an example of how you should respond as DocAI.\nDocAI: How can I help you today?\nPatient: I’m having a fever\nDocAI: Could you please take a reading of your temperature and tell me?\nPatient: My temperature is 37 degrees celsius\nDocAI: It's possible that you have a fever if your temperature is above 37.5 degrees Celsius. Are you experiencing any other symptoms?\nPatient: Yes, I feel a bit cold when I sit under a fan\nDocAI:  I recommend that you take some over-the-counter medication to reduce your fever and drink plenty of fluids. If your symptoms persist, please make an appointment with your doctor.\nThis is the real conversation.\nDocAI: Hi there, how can I help you today?\n");
  app.post('/chatbot', async (req, res) => {
    try {

      
      const userinput = req.body.prompt;
        convo +="Patient:" + userinput;
  
      const response = await openai.createCompletion({
        model: "text-davinci-003",
        prompt: `${convo}`, // The prompt is the text that the model will use to generate a response.
        temperature: 0, // Higher values means the model will take more risks.
        max_tokens: 1024, // The maximum number of tokens to generate in the completion. Most models have a context length of 2048 tokens (except for the newest models, which support 4096).
        top_p: 1, // alternative to sampling with temperature, called nucleus sampling
        frequency_penalty: 0.5, // Number between -2.0 and 2.0. Positive values penalize new tokens based on their existing frequency in the text so far, decreasing the model's likelihood to repeat the same line verbatim.
        presence_penalty: 0, // Number between -2.0 and 2.0. Positive values penalize new tokens based on whether they appear in the text so far, increasing the model's likelihood to talk about new topics.
      });
      convo +=response.data.choices[0].text + "\n";
      
      res.status(200).send({
        bot: response.data.choices[0].text
      });
    } catch (error) {
      console.error(error)
      res.status(500).send(error || 'Sorry, something went wrong. Please try again later.');
    }
  })
//end of chatbot

app.get('/usersdashboard', function (req, response) 
{
	console.log(req.session.loggedin)
    	var ua = parser(req.headers['user-agent']);
        delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {

        response.redirect("/")

    }
    else if(req.session.role == 'doctor')
    {

        response.redirect("/userdashboard")
    }

   

})
app.get('/doctorUserDetails', function (req, response) 
{
    	var ua = parser(req.headers['user-agent']);
        delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {

        response.redirect("/")

    }
    else if(req.session.role == 'doctor')
    {
        response.redirect("/userdashboard")
    }

})


//user dashboard in doctors page
app.post('/usersdashboard', function (req, response) 
{
    	var ua = parser(req.headers['user-agent']);
        delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {

        response.redirect("/")

    }
    else if(req.session.role == 'doctor')
    {

        var date = (req.body).date
        var id = (req.body).deviceid;
        var firstname = (req.body).firstname;

        if (!date)
        {
            response.end()
        }
        var date1 = {date: date}
        var userdetails = {deviceid: id, firstname: firstname}

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
                    response.send("Please enter correct date")
                }         
                else
                {
                
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
		    temperature = Math.round(temperature * 10) / 10
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
                    heartrateavg = Math.round(heartrateavg * 10) / 10
                    heartratevariabilityavg = heartratevariabilitytotal / result.length
                    heartratevariabilityavg = Math.round(heartratevariabilityavg * 10) / 10
                    respiratoryRateavg = respiratoryRatetotal / result.length
                    respiratoryRateavg = Math.round(respiratoryRateavg * 10) / 10
                    diastolicavg = diastolictotal / result.length
                    diastolicavg = Math.round(diastolicavg * 10) / 10
                    systolicavg = systolictotal / result.length
                    systolicavg = Math.round(systolicavg * 10) / 10
                    temperatureavg = temperaturetotal / result.length
                    temperatureavg = Math.round(temperatureavg * 10) / 10
    
    
                averages = [{ heartratemin: heartratemin, heartratevariabilitymin: heartratevariabilitymin,respiratoryRatemin: respiratoryRatemin,respiratoryRatemin: respiratoryRatemin,diastolicmin: diastolicmin,systolicmin: systolicmin, temperaturemin, temperaturemin, heartratemax: heartratemax, heartratevariabilitymax: heartratevariabilitymax, respiratoryRatemax: respiratoryRatemax, diastolicmax: diastolicmax, systolicmax: systolicmax, temperaturemax: temperaturemax, heartrateavg: heartrateavg, heartratevariabilityavg: heartratevariabilityavg, respiratoryRateavg: respiratoryRateavg, systolicavg: systolicavg, diastolicavg: diastolicavg, temperatureavg: temperatureavg, }]
    
                response.render("doctorUserDashboard.ejs", { data: data, averages: averages, date1: date1, userdetails: userdetails})
                }
    
                connection.close();
            });
         
            connection.execSql(request);
    
        });
    
        connection.connect();

        }


   

})
app.post('/doctorUserDetails', function (req, response) 
{
    var ua = parser(req.headers['user-agent']);
    delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {

        response.redirect("/")

    }
    else if(req.session.role == 'doctor')
    {

	    
        var email = (req.body).email
        var deviceid = (req.body).deviceid

        var connection = new Connection(config);
            connection.on('connect', function (err) 
            {
                // If no error, then good to proceed.  
        
                var Request = require('tedious').Request;
                var TYPES = require('tedious').TYPES;
        
        
                var request = new Request("SELECT * FROM [dbo].[users] WHERE email = @email", function (err) 
                {
                    if (err) {
                        console.log(err);
                    }
                });
    
                request.addParameter('email', TYPES.VarChar, email);

                var request2 = new Request("SELECT (SELECT TOP (1) enqueuedTime FROM [dbo].[t1] WHERE deviceId = @deviceid1 ORDER BY enqueuedTime) AS earliest, (SELECT TOP (1) enqueuedTime FROM [dbo].[t1] WHERE deviceId =  @deviceid ORDER BY enqueuedTime DESC) AS latest", function (err) 
                {
                    if (err) {
                        console.log(err);
                    }
                });
    
                request2.addParameter('deviceid', TYPES.VarChar, deviceid);
                request2.addParameter('deviceid1', TYPES.VarChar, deviceid);

                var result = [];
                var row = []
                var columnnumber = 1
        
                request.on('row', function (columns) 
                {
                    columns.forEach(function (column) {
        
                        if (column.value === null) {
                            console.log('NULL');
                        } else {
        
                            if (columnnumber == 7) {
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
                var dates = []
                var date = []
        
                var columnnumber2 = 1
                request2.on('row', function (columns) 
                {
                    columns.forEach(function (column) {
        
                        if (column.value === null) {
                            console.log('NULL');
                        } else {
                            if (columnnumber2 == 2)
                            {
                                date.push(column.value)
                                dates.push({start: date[0], end: date[1]})

                            }      
                            else
                            {
                                date.push(column.value)
                                columnnumber2++
                            }                     
                            
        
                        }
                    });
        
                });
                
        
                
                request2.on("requestCompleted", function (rowCount, more) 
                {
                    

                    response.render("doctorUserDetails.ejs", {userdetails: userdetails, dates: dates})
                            
                    
                    connection.close();
                });
                
        
                var userdetails = []

                request.on("requestCompleted", function (rowCount, more) 
                {
                    for (let index = 0; index < result.length; index++)
                    {
                        let row = result[index];

                        userdetails.push({firstname: row[5], deviceid: row[0], age: row[3], email: row[1]})
                        
                    }
                            
                    connection.execSql(request2);
                });



             
                connection.execSql(request);

        
            });
        
            connection.connect();
    }
    
    
})

app.get('/userProfile', function (req, response) 
{
    console.log(req.session.loggedin)

    var ua = parser(req.headers['user-agent']);
    delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {

        var success = {success : "no"}
        response.render("userProfile.ejs",{success: success})

    }
    else if(req.session.role == 'doctor')
    {

        response.render("/")
    }




   
})

app.post('/userProfile', function (req, response) 
{
    console.log(req.session.loggedin)

    var ua = parser(req.headers['user-agent']);
    delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {

        var password = (req.body).password
        var success = {success : "yes"}
    
        var connection = new Connection(config);
        connection.on('connect', function (err) 
        {
            // If no error, then good to proceed.  
        
            var Request = require('tedious').Request;
            var TYPES = require('tedious').TYPES;
        
        
            var request = new Request("SELECT * FROM [dbo].[users] WHERE email = @email", function (err) 
            {
                if (err) {
                    console.log(err);
                }
            });
            var email = req.session.email
            request.addParameter('email', TYPES.VarChar, email);
        
            var result = [];
            var row = []
            var columnnumber = 1
        
            request.on('row', function (columns) 
            {
                columns.forEach(function (column) {
        
                    if (column.value === null) {
                        console.log('NULL');
                    } else {
        
                        if (columnnumber == 7) {
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
        
           
            var userdetails = []
        
            request.on("requestCompleted", function (rowCount, more) 
            {
                for (let index = 0; index < result.length; index++)
                {
                    let row = result[index];
        
                    userdetails.push({firstname: row[5], deviceid: row[0], age: row[3], email: row[1], seed: row[4]})
                    
                }
    
                if (bcrypt.compareSync(password, result[0][2]))
                {
                    response.render("userProfile.ejs",{success: success, userdetails, userdetails})
    
                }
                else
                {
                    response.send("Wrong password")
                }
    
    
                        
            });
        
         
            connection.execSql(request);
        
        
        });
        
        connection.connect();

    }
    else if(req.session.role == 'doctor')
    {

        response.redirect("/")

    }

   
   
})

app.get('/doctorProfile', function (req, response) 
{
    var ua = parser(req.headers['user-agent']);
    delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {

        response.redirect("/")

    }
    else if(req.session.role == 'doctor')
    {

        var success = {success : "no"}
        response.render("doctorProfile.ejs",{success: success})
    }



   
})

app.post('/doctorProfile', function (req, response) 
{
    var ua = parser(req.headers['user-agent']);
    delete ua.device
    if (!req.session.loggedin) {
		response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {

        response.redirect("/")

    }
    else if(req.session.role == 'doctor')
    {
    var password = (req.body).password
    var success = {success : "yes"}

    var connection = new Connection(config);
    connection.on('connect', function (err) 
    {
        // If no error, then good to proceed.  
    
        var Request = require('tedious').Request;
        var TYPES = require('tedious').TYPES;
    
    
        var request = new Request("SELECT * FROM [dbo].[users] WHERE email = @email", function (err) 
        {
            if (err) {
                console.log(err);
            }
        });
        var email = req.session.email
        request.addParameter('email', TYPES.VarChar, email);
    
        var result = [];
        var row = []
        var columnnumber = 1
    
        request.on('row', function (columns) 
        {
            columns.forEach(function (column) {
    
                if (column.value === null) {
                    console.log('NULL');
                } else {
    
                    if (columnnumber == 7) {
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
    
       
        var userdetails = []
    
        request.on("requestCompleted", function (rowCount, more) 
        {
            for (let index = 0; index < result.length; index++)
            {
                let row = result[index];
    
                userdetails.push({firstname: row[5], deviceid: row[0], age: row[3], email: row[1], seed: row[4]})
                
            }
            
            if (bcrypt.compareSync(password, result[0][2]))
            {
                response.render("doctorProfile.ejs",{success: success, userdetails, userdetails})

            }
            else
            {
                response.send("Wrong password")
            }

            
                    
        });
    
     
        connection.execSql(request);
    
    
    });
    
    connection.connect();
    }
    
   
})
	
function editDetails(field1, field2, req, response) {

    
            
        if (field1 && field2) {
            if (field1 == field2) {
		if(!(regexTest(rePassword,field1)))
		{
                       response.send('Invalid Password Format')
                }
		else
		{
			
                    field1 = bcrypt.hashSync(field2, 10);
                
            
                console.log("Changing password")
                var connection = new Connection(config);
                connection.on('connect', function (err) {
                    // If no error, then good to proceed.  

                    var Request = require('tedious').Request;
                    var TYPES = require('tedious').TYPES;

                    var request = new Request(`UPDATE [dbo].[users] SET password = @field1 WHERE email = @email`, function (err) {
                        if (err) {
                            console.log(err);
                        }

                    });
                    var email = req.session.email
                    request.addParameter('email', TYPES.VarChar, email);
                    request.addParameter('field1', TYPES.VarChar, field1);



                    request.on("requestCompleted", function (rowCount, more) {

                       
                        response.redirect("/userProfile")

                    });


                    connection.execSql(request);


                });

                connection.connect();
		}


            }
            else {
                response.send("Fields don't match")
            }
        }
        else {
            response.send("Please fill up all fields")
        }
		

                

    


}




app.post('/editUserProfile', function (req, response) {
    var ua = parser(req.headers['user-agent']);
    delete ua.device
    if (!req.session.loggedin) {
	response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {
    var field1 = req.body.field1
    var field2 = req.body.field2
    editDetails(field1, field2, req, response)
    }
    else if(req.session.role == 'doctor')
    {
	    response.redirect('/usersdashboard')
    }
    

})

app.post('/editDoctorProfile', function (req, response) {
 var ua = parser(req.headers['user-agent']);
    delete ua.device
    if (!req.session.loggedin) {
	response.send('please login to view dashboard')
        response.end()
	}
    else if(!(_.isEqual(ua, req.session.fingerprint))){
        response.send('fingerprint change detected')
        response.end()
    }
    else if(req.session.role == 'user')
    {
      	response.redirect('/usersdashboard')
    }
    else if(req.session.role == 'doctor')
    {
	var field1 = req.body.field1
    	var field2 = req.body.field2
    	editDetails(field1, field2, req, response)
	    
    }
})
	
var port = process.env.PORT || 3000;
server.listen(port)  
})()
