const fs = require('fs');
const express = require('express')
const session = require('express-session');
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


//hcaptcha secret TODO: Azure Key Vault
const hcaptchaSecret = '0x76433E082876747e710Af00aa1FB8a8685a81e4e';

//NIST SP 800-63B Session Management https://pages.nist.gov/800-63-3/sp800-63b.html
const expiryMSec = 60 * 60 * 1000
function iniSession(){
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
}
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
app.use(function (request,response,next){
    response.header("Access-Control-Allow-Origin", "*");
    response.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
})
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


function regexTest(arg1, arg2){
    var pattern = arg1
    return pattern.test(arg2)
}
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



app.get('/', function (request, response) {
    if(request.session.loggedin == true){
        response.redirect('./userdashboard')
    }
    else{
        if (request.session.csrf === undefined) {
            request.session.csrf = randomBytes(100).toString('base64'); // convert random data to a string
            fs.readFile('welcome.html', "utf8", function(err, data) {
                if (err) throw err;
            
                var $ = cheerio.load(data);
            
                $(".csrftoken").attr('value', request.session.csrf)
                response.send($.html());
            });
        }
        else {
            fs.readFile('welcome.html', "utf8", function(err, data) {
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
app.post('/auth', function(request, response) {
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
                        var dbrequest = new Request(sql, function (err,rowCount) 
                        {
                            if (err) {console.log(err);} 
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
                            if(resultArray[2] == undefined){
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
                                            var sql2 = 'INSERT INTO dbo.users (userdeviceid, firstName, email, password, age, tfaSeed, role) VALUES (@userdeviceidparam, @firstNameparam, @emailparam,@passwordparam,@ageparam,@tfaparam, @roleparam);';
                                            var dbrequest2 = new Request (sql2, function (err,rowCount){
                                                if (err) {console.log(err);} 
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


app.get('/logout', function (req, response) 
{
    response.cookie("id1", "", { expires: new Date() });
    response.redirect("/")
})

//Straight after logging in, ask user to select date
app.get('/userdashboard', function (req, response) 
{

	//if doctor acc show doctor home page
    if (req.session.role == 'doctor' && req.session.loggedin)
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
    else if(req.session.loggedin)
    {
        response.render("afterLogin.ejs")

    }
    else
    {
        response.redirect("/")
    }


})

//After selecting date (only for user acc)
app.post('/userdashboard', function (req, response) 
{
    if(req.session.loggedin)
    {
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
                }
                
    
                connection.close();
            });
         
            connection.execSql(request);
    
        });
    
        connection.connect();
        
    }
    else
    {
        response.redirect("/")
    }
	
   

})

app.get('/usersdashboard', function (req, response) 
{
    if (req.session.role == 'doctor' && req.session.loggedin)
    {
        response.redirect("/userdashboard")
    }
    else
    {
        response.redirect("/")
    }

})
app.get('/doctorUserDetails', function (req, response) 
{
    if (req.session.role == 'doctor' && req.session.loggedin)
    {
        response.redirect("/userdashboard")
    }
    else
    {
        response.redirect("/")
    }
})


//user dashboard in doctors page
app.post('/usersdashboard', function (req, response) 
{
    if (req.session.role == 'doctor' && req.session.loggedin)
    {

    
		//regen sid
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
    
                response.render("doctorUserDashboard.ejs", { data: data, averages: averages, date1: date1, userdetails: userdetails})
                }
    
                connection.close();
            });
         
            connection.execSql(request);
    
        });
    
        connection.connect();
        
    }
    else
    {
        response.redirect("/")
    }	
   

})
app.post('/doctorUserDetails', function (req, response) 
{
    if (req.session.role == 'doctor' && req.session.loggedin)
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
        
                            if (columnnumber == 6) {
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
    else
    {
        response.render('/')
    }
    
    
    
    
})
var port = process.env.PORT || 3000;
app.listen(port)  
