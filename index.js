var jwt = require('jwt-simple');
var express = require('express');
var bodyParser = require('body-parser');
var path = require('path');
require('dotenv').config();

module.exports = (secret = false) => {

    var validateFunctionSync = null;

    var validateFunction = (next) => {
        next(false);
    }

    var successFunction = ({next}) => {
        return next();
    }

    var numDaysExpires = 7;

    var secretCode = (process.env.NODE_CUPCOFFEE_JWT_SECRET) ?
        process.env.NODE_CUPCOFFEE_JWT_SECRET : (process.env.NODE_JWT_SECRET) ?
        process.env.NODE_JWT_SECRET : null;

    if (!secretCode) {
        var env = (process.env.NODE_CUPCOFFEE_ENV) ?
            process.env.NODE_CUPCOFFEE_ENV : (process.env.NODE_ENV) ?
            process.env.NODE_ENV : 'development';

        var config = require(path.resolve('.') + '/cupcoffee.json');

        if(config.app){
            if(config.app[env]){
                if(config.app[env].auth){
                    secretCode = config.app[env].auth.secret || null;
                }
            }
        }

        if (!secretCode) {
            if(secret){
                secretCode = secret;
            }
            else{
                console.error("[cupcoffee-auth-jwt][ERROR]: Secret code for token does not exist. ")
                return false;
            }
        }
    }

    this.expires = (num) => {
        numDaysExpires = num;
        return this;
    }

    this.validateSync = (callback) => {
        validateFunctionSync = callback
        return this;
    };

    this.validate = (callback) => {
        validateFunction = callback
        return this;
    };

    this.login = function(req, res) {
        var username = req.body.username || '';
        var password = req.body.password || '';

        if (username == '' || password == '') {
            res.status(401);
            res.json({
                "status": 401,
                "message": "Invalid credentials"
            });
            return;
        }

        var dbUserObj = (result) => {
            if (result) {
                return res.json(genToken(result));
            } else {
                res.status(401);
                return res.json({
                    "status": 401,
                    "message": "Invalid credentials"
                });
            }
        }

        if(validateFunctionSync){
            return dbUserObj(validateFunctionSync(username, password))
        }

        validateFunction(username, password, dbUserObj);
    }

    this.middware = (path, success) => {
        if(success){
            successFunction = success;
        }

        var app = express();

        app.use(bodyParser.json());

        app.all('/*', function(req, res, next) {
            // CORS headers
            res.header("Access-Control-Allow-Origin", "*"); // restrict it to the required domain
            res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
            // Set custom headers for CORS
            res.header('Access-Control-Allow-Headers', 'Content-type,Accept,X-Access-Token,X-Key');
            if (req.method == 'OPTIONS') {
                res.status(200).end();
            } else {
                next();
            }
        });

        app.all(path, [validateRequest]);

        return app;
    }

    function validateRequest(req, res, next) {
        var token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
        var key = (req.body && req.body.x_key) || (req.query && req.query.x_key) || req.headers['x-key'];

        if (token || key) {
            try {

                var decoded = jwt.decode(token, secretCode);

                if (decoded.exp <= Date.now()) {
                    res.status(400);
                    res.json({
                        "status": 400,
                        "message": 'Token Expired'
                    });

                    return;
                }

                return successFunction({
                    token,
                    key,
                    req,
                    res,
                    next,
                    decoded
                });
            } catch (err) {
                res.status(500);
                res.json({
                    "status": 500,
                    "message": 'Oops, something went wrong',
                    "error": err
                });
            }
        }
        else {
            res.status(401);
            res.json({
                "status": 401,
                "message": 'Invalid Token or Key'
            });
            return;
        }
    }

    function genToken(data) {
        var expires = expiresIn();
        var token = jwt.encode({
            exp: expires
        }, secretCode);

        return { token, expires, data };
    }

    function expiresIn() {
        var dateObj = new Date();
        return dateObj.setDate(dateObj.getDate() + numDaysExpires);
    }

    return this;
}
