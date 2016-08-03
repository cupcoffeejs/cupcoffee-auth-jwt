var jwt = require('jwt-simple');
var express = require('express');
var bodyParser = require('body-parser');
var app = express();

module.exports = ({login, success, path, secret}) => {

    this.secret = secret;

    this.messages = {
        '400': 'Token Expired'
        '401': 'Invalid Token or Key',
        '500': 'Oops, something went wrong'
    }

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

        if (validate(username, password)) {
            return res.json(genToken(dbUserObj));
        } else {
            res.status(401);
            return res.json({
                "status": 401,
                "message": "Invalid credentials"
            });
        }

    }

    this.middware = () => {
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
    }

    var validateRequest = function(req, res, next) {
        var token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
        var key = (req.body && req.body.x_key) || (req.query && req.query.x_key) || req.headers['x-key'];

        if (token || key) {
            try {
                var decoded = jwt.decode(token, require('../../config/secret.js')());

                if (decoded.exp <= Date.now()) {
                    res.status(400);
                    res.json({
                        "status": 400,
                        "message": this.messages[400]
                    });
                    return;
                }

                // Authorize the user to see if s/he can access our resources
                success({
                    token,
                    key,
                    req,
                    res,
                    next,
                    decoded,
                    path
                })

            } catch (err) {
                res.status(500);
                res.json({
                    "status": 500,
                    "message": this.messages['500'],
                    "error": err
                });
            }
        } else {
            res.status(401);
            res.json({
                "status": 401,
                "message": this.messages['401']
            });
            return;
        }
    };

    return this;
}
