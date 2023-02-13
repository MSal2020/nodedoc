/* eslint no-unused-vars: 0, no-undef: "off", no-useless-escape: "off", no-inner-declarations: 1, no-dupe-keys: 1, no-redeclare: 1*/
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
const helmet = require('helmet')
const {RateLimiterMemory} = require('rate-limiter-flexible');
var hpp = require('hpp');
require('dotenv').config()
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('views'))
app.use(express.static('template'))
app.use(express.static('template/js'))
app.use(express.static('template/js/jquery'))
app.use(express.static('template/img'))
app.use(express.static('template/fonts'))
app.use(express.static('template/css'))
	
//Azure Key Vault
async function KVRetrieve(secretName) {
    const credential = new DefaultAzureCredential();
  
    const keyVaultName = process.env.KEY_VAULT_NAME;
    const url = "https://" + keyVaultName + ".vault.azure.net";
  
    const client = new SecretClient(url, credential);
    const secret = await client.getSecret(secretName);
    return secret.value
}

//HelmetJS
app.use(helmet.hsts());
app.use(
    helmet.frameguard({
      action: "deny",
    })
);
app.use(helmet.noSniff());
app.use(helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' }));
app.use(helmet.xssFilter());

//CORS
app.use(
    cors({
      origin: ["https://aidochealth.azurewebsites.net"],
      methods: ["GET", "POST"],
      credentials: true,
    })
);

app.disable('x-powered-by');
app.use(function (request,response,next){

    response.header("X-Frame-Options", "DENY");
    response.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    response.header("X-Content-Type-Options", "nosniff");
    response.header("Content-Security-Policy", "default-src 'self'; script-src 'report-sample' 'self' https://ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js https://cdn.jsdelivr.net/npm/jquery@3.6.3/dist/jquery.min.js https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js https://cdn.jsdelivr.net/npm/billboard.js/dist/billboard.min.js https://cdn.rawgit.com/yahoo/xss-filters/master/dist/xss-filters.js https://cdnjs.cloudflare.com/ajax/libs/fomantic-ui/2.9.1/semantic.min.js https://d3js.org/d3.v6.min.js https://js.hcaptcha.com/1/api.js https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js https://cdnjs.cloudflare.com/ajax/libs/webrtc-adapter/7.3.0/adapter.min.js https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment.min.js https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/1.3.8/FileSaver.min.js https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.slim.min.js https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/js/bootstrap.bundle.min.js 'sha256-bw05y0zyeSd5jRlbyqGLntl9WwV3/yWs2HUGbKIHEhs=' 'sha256-/VijZ2wN6Kjm26aVcKtRp3IPAUrCs8LNlHHRd5hBRes=' 'sha256-1YRVENZq/SKZ9JsV1byhdT4vBd4+/fB2Xuz7wxTHhME=' 'sha256-lEsliGGgrydK7dVovRSSd+WPDM+8lagKBoWEpJz/Cd8='  'sha256-Wl5F9VxPkJYeAbwU/N5SvqgaTjGCm+4qVF3r2axeA5I=' 'sha256-gShiWDzR7fwYubdtKJH7zpTKSxn/MnMuL/E/vVCGq5E=' 'sha256-vnNncvBZxM0PW4zE8ODt/zjYdDUbBm0IOgvzjygRYvc=' 'sha256-srNkjMdJWxxav/2NcIn61PAzeMEiv/cODfhqrb37c8U=';  style-src 'report-sample' 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://stackpath.bootstrapcdn.com https://use.fontawesome.com https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css 'sha256-ioYHo0ab7vp2Fwl0xb6TH3I7cpGP1zOQ+h6hNKE5Vok=' 'sha256-ncCubXbAnjGtVKt3rIYQS0f/qiZNlO44ayOP7Nh0CjY=' 'sha256-8Aq/4u095fOwU5jFCxfcRHEQyAZTA1bYK1Jg4Z4c0as=' 'sha256-1/p/WHg3OuE5Xk4qn/pE84dAjlfClPYNkAh2nC2zZ7c=' 'sha256-5RoeMppAz7zOD+dP81W3gDJucMfr9jGEuSijrn/BLlA=' 'sha256-KCWmVczoYJKZRHilo/0RlVMkpbaIwIt5RntvtxET+h4=' 'sha256-RzT6TL2rZ3eEL4w6JRWbjfrEKHyhByWPGY7quYXzQ8k=' 'sha256-A1Mq/soPBz/VnX6Krv+YwmToBATIgC8L3f4oRLrKpfs=' 'sha256-a3IkG7mlk1ZAraVqVeEtII4Yizqp/YJEmpmFOyryL7k=' 'sha256-m/iZjaAuaTiv+iJPCtiu8+J74OuDeVZxtFGCvf9bbU8=' 'sha256-pRozmfihq/ezoo5GRzCzFhml5uq1v+K5zUMa0kyK9AY=' 'sha256-a+6g99vfj7u6i3qk6e3a1OKTatauPaaM0ugTa4hRFV0=' 'sha256-zcW2/JShNGFR0XVYi2Kwi+JQjn5dSY8vu7kFhSDIx4Q=' 'sha256-6WJwev1QA6Ct/03EOR6lOuYCm0fd74++htvqmZpd/DQ='  'sha256-Gydt0iYx8tWsKsvzYjAP9QkQaA7uQdwk6s/tldb4VpA=' 'sha256-d0RcaebhpZjvi/Kp254cZyEjpU4D9efsVHJE+Ru9COA=' 'sha256-oj3Ktiorzo1c1M7bv8fEu3M4W2QMbltyCc2A/goSUes='    ; object-src 'none';base-uri 'self';connect-src 'self'; font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com https://use.fontawesome.com;frame-src 'self' https://newassets.hcaptcha.com;img-src 'self' https://fdroid.gitlab.io https://play.google.com https://tools.applemediaservices.com;manifest-src 'self';media-src 'self';report-uri https://63e911791110c9e871bfe10c.endpoint.csper.io/?v=2;worker-src 'none';")
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

//Rate Limiter (Deny over 20 requests every 3 seconds)
const limiterFlexible = new RateLimiterMemory({
    points: 20,
    duration: 3,
  });
const rateLimiterMiddleware = (req, res, next) => {
    limiterFlexible.consume(req.ip)
    .then(() => {
        next();
    })
    .catch(() => {
        console.log('Rate Limit imposed on ' + req.ip)
        res.status(429).send('Too Many Requests to the website! Try Again Later.');
    });
};
app.use(rateLimiterMiddleware);


//calendar
const gcal = require('./Utility/gcal.js');

const days = require('./ReqHandlers/GET-Handlers/days.js');
const timeslots = require('./ReqHandlers/GET-Handlers/timeslots.js');
const book = require('./ReqHandlers/POST-Handlers/book.js');

const auth = {};

// Get the OAuth2 client for making Google Calendar API requests.
gcal.initAuthorize(setAuth);

function setAuth(auth) {
    this.auth = auth;

}

/**
 * Handles 'days' GET requests.
 * @param {object} req  The requests object provided by Express. See Express doc.
 * @param {object} res  The results object provided by Express. See Express doc.
 */
function handleGetDays(req, res) {

    const year = req.query.year;
    const month = req.query.month;
    days.getBookableDays(this.auth, year, month)
        .then(function (data) {
            res.send(data);
        })
        .catch(function (data) {
            res.send(data);
        });

}

/**
 * Handles 'timeslots' GET requests.
 * @param {object} req  The requests object provided by Express. See Express doc.
 * @param {object} res  The results object provided by Express. See Express doc.
 */
function handleGetTimeslots(req, res) {

    const year = req.query.year;
    const month = req.query.month;
    const day = req.query.day;
    timeslots.getAvailTimeslots(this.auth, year, month, day)
        .then(function (data) {
            res.send(data);
        })
        .catch(function (data) {
            res.send(data);
        });

}

/**
 * Handles 'book' POST requests.
 * @param {object} req  The requests object provided by Express. See Express doc.
 * @param {object} res  The results object provided by Express. See Express doc.
 */
function handleBookAppointment(req, res) {
    const year = req.query.year;
    const month = req.query.month;
    const day = req.query.day;
    const hour = req.query.hour;
    const minute = req.query.minute;
    book.bookAppointment(this.auth, year, month, day, hour, minute)
        .then(function (data) {
            res.send(data);
        })
        .catch(function (data) {
            res.send(data);
        });
}

// Routes.
app.get('/days', handleGetDays);
app.get('/timeslots', handleGetTimeslots);
app.post('/book', handleBookAppointment);

//end calendar

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

//Parameter Pollution Prevention
app.use(hpp());

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
	

/* app.get('/home_guest', function (request, response) {
	
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
*/
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
                else {
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
                    var heartratevariabilitymin = 1000
                    var respiratoryRatemin = 1000
                    var diastolicmin = 1000
                    var systolicmin = 1000
                    var temperaturemin = 1000

                    var warningHeartRateHigh = []
                    var warningRespiratoryRateHigh = []
                    var warningDiastolicHigh = []
                    var warningSystolicHigh = []
                    var warningTemperatureHigh = []
                    var warningHeartRateLow = []
                    var warningRespiratoryRateLow = []
                    var warningDiastolicLow = []
                    var warningSystolicLow = []
                    var warningTemperatureLow = []

                    for (let index = 0; index < result.length; index++) {

                        row = result[index]

                        var date = row[1]
                        var readings = JSON.parse(row[2])
                        var heartrate = readings.HeartRate
                        var heartratevariability = readings.HeartRateVariability
                        var respiratoryRate = readings.RespiratoryRate
                        var diastolic = (readings.BloodPressure).Diastolic
                        var systolic = (readings.BloodPressure).Systolic
                        var temperature = (5 / 9) * (readings.BodyTemperature - 32)
                        temperature = Math.round(temperature * 10) / 10
                        var reading = { heartrate: heartrate, heartratevariability: heartratevariability, respiratoryRate: respiratoryRate, diastolic: diastolic, systolic: systolic, temperature: temperature, date: date }
                        data.push(reading)

                        if (heartrate > heartratemax) {
                            heartratemax = heartrate
                        }
                        else if (heartrate < heartratemin) {
                            heartratemin = heartrate
                        }
                        if (heartratevariability > heartratevariabilitymax) {
                            heartratevariabilitymax = heartratevariability
                        }
                        else if (heartratevariability < heartratevariabilitymin) {
                            heartratevariabilitymin = heartratevariability
                        }
                        if (respiratoryRate > respiratoryRatemax) {
                            respiratoryRatemax = respiratoryRate
                        }
                        else if (respiratoryRate < respiratoryRatemin) {
                            respiratoryRatemin = respiratoryRate
                        }
                        if (diastolic > diastolicmax) {
                            diastolicmax = diastolic
                        }
                        else if (diastolic < diastolicmin) {
                            diastolicmin = diastolic
                        }
                        if (systolic > systolicmax) {
                            systolicmax = systolic
                        }
                        else if (systolic < systolicmin) {
                            systolicmin = systolic
                        }
                        if (temperature > temperaturemax) {
                            temperaturemax = temperature
                        }
                        else if (temperature < temperaturemin) {
                            temperaturemin = temperature
                        }

                        if(heartrate > 100)
                        {
                            warningHeartRateHigh.push({high: heartrate, date: date})
                        }
                        else if(heartrate < 60)
                        {
                            warningHeartRateLow.push({low: heartrate, date: date})

                        }
                        if(respiratoryRate > 16)
                        {
                            warningRespiratoryRateHigh.push({high: respiratoryRate, date: date})
                        }
                        else if(respiratoryRate < 13)
                        {
                            warningRespiratoryRateLow.push({low: respiratoryRate, date: date})

                        }
                        if(diastolic > 85)
                        {
                            warningDiastolicHigh.push({high: diastolic, date: date})
                        }
                        else if(heartrate < 75)
                        {
                            warningDiastolicLow.push({low: diastolic, date: date})

                        }
                        if(systolic > 125)
                        {
                            warningSystolicHigh.push({high: systolic, date: date})
                        }
                        else if(systolic < 115)
                        {
                            warningSystolicLow.push({low: systolic, date: date})

                        }
                        if(temperature >= 37.2)
                        {
                            warningTemperatureHigh.push({high: temperature, date: date})
                        }
                        else if(temperature < 36.1)
                        {
                            warningTemperatureLow.push({low: temperature, date: date})

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
                        prompt: "Pretend you are doctor. Based on the following information, you will give medical advice to the patient. You will give recommended treatments as well. If heart rate is over 90 beats per minute, it is too high. If heart rate variability is over 50 milliseconds, it is too high. If respiratory rate is over 13 breaths per minute, it is too high. If diastolic pressure is below 60mmHg, it is too low. If systolic pressure is below 90mmHg, it is too low.\nPatient details:\nHeart rate is " + heartrateavg + " beats per minute.\nBody temperature is " + temperatureavg + " degrees celsius.\nHeart rate variability is  " + heartratevariabilityavg + " milliseconds.\nRespiratory rate is  " + respiratoryRateavg + " breaths per minute.\nDiastolic pressure is  " + diastolicavg + "mmHg.\nSystolic pressure is  " + systolicavg + "mmHg.\nDoctor:",
                        max_tokens: 1024,
                        temperature: 0,
                        });
                        
                        outp =  completion.data.choices[0].text;
                        
                    }

                    runCompletion().then(() => {
    
    
                        averages = [{ heartratemin: heartratemin, outp: outp, heartratevariabilitymin: heartratevariabilitymin,respiratoryRatemin: respiratoryRatemin,respiratoryRatemin: respiratoryRatemin,diastolicmin: diastolicmin,systolicmin: systolicmin, temperaturemin, temperaturemin, heartratemax: heartratemax, heartratevariabilitymax: heartratevariabilitymax, respiratoryRatemax: respiratoryRatemax, diastolicmax: diastolicmax, systolicmax: systolicmax, temperaturemax: temperaturemax, heartrateavg: heartrateavg, heartratevariabilityavg: heartratevariabilityavg, respiratoryRateavg: respiratoryRateavg, systolicavg: systolicavg, diastolicavg: diastolicavg, temperatureavg: temperatureavg}]
                        response.render("billboard.ejs", { data: data, averages: averages, date1: date1, warningDiastolicHigh: warningDiastolicHigh, warningDiastolicLow: warningDiastolicLow ,warningRespiratoryRateHigh: warningRespiratoryRateHigh,warningRespiratoryRateLow:warningRespiratoryRateLow,warningHeartRateHigh: warningHeartRateHigh,warningHeartRateLow:warningHeartRateLow, warningSystolicHigh: warningSystolicHigh,warningSystolicLow: warningSystolicLow ,warningTemperatureHigh, warningTemperatureHigh, warningTemperatureLow: warningTemperatureLow })
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
app.get( '/call', ( req, res ) => 
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
	res.sendFile( __dirname + '/calluser.html' );

    }	
     else if(req.session.role == 'doctor')
    {	
	res.sendFile( __dirname + '/calldoctor.html' );

    }

} );


io.of( '/stream' ).on( 'connection', stream );


app.get('/bot', (req, res) => {
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

//the rest of the code here
res.sendFile(path.join(__dirname, '/public/index.html'));
}

})

.catch((error) => {

console.log(error)

response.send('sorry session timed out')

response.end()

});
    
  })
//chatbot
app.get('/chatbot', async (req, res) => {
    res.status(200).send({
        message: 'Hello from DocAI !!'
    })
})
var convo = ('Pretend you are doctor named DocAI. You are helpful, creative, clever, and very friendly. You are talking to a patient. Answer with medical advice. If a patient asks you which day they can book an appointment, ask them what date and time they prefer for their appointment. After you book the appointment, always make sure your response includes "your appointment is booked for" and include the date in yyyy/mm/dd format and include the time in 24 hour format. It is the year 2023.\nThis is an example of how you should respond as DocAI.\nDocAI: How can I help you today?\nPatient: I am having a fever\nDocAI: Could you please take a reading of your temperature and tell me?\nPatient: My temperature is 37 degrees celsius\nDocAI: It is possible that you have a fever if your temperature is above 37.5 degrees Celsius. Are you experiencing any other symptoms?\nPatient: Yes, I feel a bit cold when I sit under a fan\nDocAI: I recommend that you take some over-the-counter medication to reduce your fever and drink plenty of fluids. If your symptoms persist, please make an appointment with your doctor\nPatient: When can I book an appointment?\nDocAI: Here are the available dates for your appointment in February. Which date would you like?\nPatient: 7 February \nDocAI: Here are the avaliable timeslots for your appointment on 7 February. Which slot would you like?\nPatient: 5.15pm\nDocAI: Done! Your appointment is booked for 17:15 on 2023/2/7\nThis is the real conversation\nDocAI: Hi there, how can I help you today?\n');
app.post('/chatbot', async (req, res) => {
    try {
        if (req.body.clear === true ) {

            convo = ('Pretend you are doctor named DocAI. You are helpful, creative, clever, and very friendly. You are talking to a patient. Answer with medical advice. If a patient asks you which day they can book an appointment, ask them what date and time they prefer for their appointment. After you book the appointment, always make sure your response includes "your appointment is booked for" and include the date in yyyy/mm/dd format and include the time in 24 hour format. It is the year 2023.\nThis is an example of how you should respond as DocAI.\nDocAI: How can I help you today?\nPatient: I am having a fever\nDocAI: Could you please take a reading of your temperature and tell me?\nPatient: My temperature is 37 degrees celsius\nDocAI: It is possible that you have a fever if your temperature is above 37.5 degrees Celsius. Are you experiencing any other symptoms?\nPatient: Yes, I feel a bit cold when I sit under a fan\nDocAI: I recommend that you take some over-the-counter medication to reduce your fever and drink plenty of fluids. If your symptoms persist, please make an appointment with your doctor\nPatient: When can I book an appointment?\nDocAI: Here are the available dates for your appointment in February. Which date would you like?\nPatient: 7 February \nDocAI: Here are the avaliable timeslots for your appointment on 7 February. Which slot would you like?\nPatient: 5.15pm\nDocAI: Done! Your appointment is booked for 17:15 on 2023/2/7\nThis is the real conversation\nDocAI: Hi there, how can I help you today?\n');
            res.status(200).send({
                bot: "Conversation cleared"	
            });
        }

        else {

        const userinput = req.body.prompt;
        convo += "Patient: " + userinput;
        const response = await openai.createCompletion({
            model: "text-davinci-003",
            prompt: `${convo}`, // The prompt is the text that the model will use to generate a response.
            temperature: 0, // Higher values means the model will take more risks.
            max_tokens: 1024, // The maximum number of tokens to generate in the completion. Most models have a context length of 2048 tokens (except for the newest models, which support 4096).
            top_p: 1, // alternative to sampling with temperature, called nucleus sampling
            frequency_penalty: 0, // Number between -2.0 and 2.0. Positive values penalize new tokens based on their existing frequency in the text so far, decreasing the model's likelihood to repeat the same line verbatim.
            presence_penalty: 0, // Number between -2.0 and 2.0. Positive values penalize new tokens based on whether they appear in the text so far, increasing the model's likelihood to talk about new topics.
        });
        


        let availslots;
        let bookslot;

        if (response.data.choices[0].text.includes("available timeslots for your appointment") === true) {
            availslots = true;

        }
        if (response.data.choices[0].text.toLowerCase().includes("your appointment is booked for") === true) {
            bookslot = true;
        }
        let url;
        let url2;






        if (availslots === true) {
            availslots = false;
            
            //extract date from string and split into day and month
            date = response.data.choices[0].text.match(/\s+\d{1,2}\s(Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|May|Jun(e)?|Jul(y)?|Aug(ust)?|Sep(tember)?|Oct(ober)?|Nov(ember)?|Dec(ember)?)/);
            var day = date[0].trim().split(" ")[0];
            var month = date[0].trim().split(" ")[1];
            //convert month to number
              switch (month) {
                case "Jan":
                case "January":
                    month = 1;
                    break;
                case "Feb":
                case "February":
                    month = 2;
                    break;
                case "Mar":
                case "March":
                    month = 3;
                    break;
                case "Apr":
                case "April":
                    month = 4;
                    break;
                case "May":
                    month = 5;
                    break;
                case "Jun":
                case "June":
                    month = 6;
                    break;
                case "Jul":
                case "July":
                    month = 7;
                    break;
                case "Aug":
                case "August":
                    month = 8;
                    break;
                case "Sep":
                case "September":
                    month = 9;
                    break;
                case "Oct":
                case "October":
                    month = 10;
                    break;
                case "Nov":
                case "November":
                    month = 11;
                    break;
                case "Dec":
                case "December":
                    month = 12;
                    break;
                default:
                    month = 0;
            }
            
            url = `https://aidochealth.azurewebsites.net/timeslots?year=2023&month=${month}&day=${day}`;
            url2 = `https://aidochealth.azurewebsites.net/days?year=2023&month=${month}`;

            const request = require('request');

            function doRequest(url) {
                return new Promise(function (resolve, reject) {
                    request(url, function (error, res, body) {
                        if (!error && res.statusCode === 200) {
                            resolve(body);
                        } else {
                            reject(error);
                        }
                    });
                });
            }

            // Usage:
            async function main() {
                try {
			let str = await doRequest(url);
			str = JSON.parse(str);
			let timeslots = str.timeslots;
			let formattedData = "";
			for (let i = 0; i < timeslots.length; i++) {
                let slot = timeslots[i];
                formattedData += `slot ${i + 1}: ${slot.startTime.substr(1, 8)} - ${slot.endTime.substr(1, 8)}\n`;
			}
			res.status(200).send({
				bot: response.data.choices[0].text + "\n" + formattedData
			});
                } catch (error) {
                    console.error(error); // `error` will be whatever you passed to `reject()` at the top
                }
            }
            convo += response.data.choices[0].text + "\n";
            main();


        }
        else if (bookslot === true) {
            bookslot = false;
            var time;
            var date;
            function getTime(d)
            {
                //extract time from string and split into hours and minutes
                time = d.match(/([01]?[0-9]|2[0-3]):[0-5][0-9]/);
                return time[0];


            }
            function getDate(d)
            {
                //extract date from string and split into day, month, year
                date = d.match(/[0-9]+\/[0-9]+\/[0-9]+/);
                return date[0];

                
                

            }
            getDate(response.data.choices[0].text);
            getTime(response.data.choices[0].text);
            var hours = time[0].split(":")[0];
                var minutes = time[0].split(":")[1];
            var year = date[0].split("/")[0];
                var month = date[0].split("/")[1];
                var day = date[0].split("/")[2];
            (async () => {
                const rawResponse = await fetch(`https://aidochealth.azurewebsites.net/book?year=${year}&month=${month}&day=${day}&hour=${hours}&minute=${minutes}`, {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'

                    },

                });
                const content = await rawResponse.json();

                console.log(content);
                
                if (content.message === "Invalid time slot") {
                    //if content message says invalid time slot, then send the user the available timeslots
                    url = `https://aidochealth.azurewebsites.net/timeslots?year=${year}&month=${month}&day=${day}`;
                    url2 = `https://aidochealth.azurewebsites.net/days?year=${year}&month=${month}`;

                    const request = require('request');

                    function doRequest(url) {
                        return new Promise(function (resolve, reject) {
                            request(url, function (error, res, body) {
                                if (!error && res.statusCode === 200) {
                                    resolve(body);
                                } else {
                                    reject(error);
                                }
                            });
                        });
                    }

                    // Usage:
                    async function main() {
                        try {
                            let str = await doRequest(url);
				str = JSON.parse(str);
				let timeslots = str.timeslots;
				let formattedData = "";
				for (let i = 0; i < timeslots.length; i++) {
                        let slot = timeslots[i];
                        formattedData += `slot ${i + 1}: ${slot.startTime.substr(1, 8)} - ${slot.endTime.substr(1, 8)}\n`;
				}
				let invalid = "Invalid time slot. Please choose from the following available timeslots: \n"
				convo += invalid + "\n";
				res.status(200).send({
					bot: invalid + formattedData
				});
                        } catch (error) {
                            console.error(error); // `error` will be whatever you passed to `reject()` at the top
                        }
                    }
                    
                    main();
                    

                }
                //if content message says cannot book outside bookable timeframe, then tell the user that timeslots are only available from Monday to Friday, 9am to 6pm
                else if (content.message === "Cannot book outside bookable timeframe") {
                    let invalid = "Cannot book outside bookable timeframe. Timeslots are only available from Monday to Friday, 9am to 6pm."
                    convo += invalid + "\n";
                    res.status(200).send({
                        bot: invalid
                    });
                }
                
        
                else {
                    res.status(200).send({
                        bot: response.data.choices[0].text
                    });
                    convo += response.data.choices[0].text + "\n";
                }
               
            })();
            
            
        }
        else {

            res.status(200).send({
                bot: response.data.choices[0].text
            });
            convo += response.data.choices[0].text + "\n";
        }


    }
    //Snyk: Information Exposure, removed sending of error object to client
    } catch (error) {
        console.error(error)
        res.status(500).send('Sorry, something went wrong. Please try again later.');
    }
})
//end chatbot


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
