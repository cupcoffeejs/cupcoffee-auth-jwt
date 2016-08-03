# cupcoffee-auth-jwt
JWT authentication to CupcoffeeJs

## Install

Create environment variable: NODE_CUPCOFFEE_JWT_SECRET or NODE_JWT_SECRET with secret code to JWT.
Example:
`NODE_CUPCOFFEE_JWT_SECRET=MY.SCRET.CODE.TO.JWT`

Or manually add to `require('cupcoffee-auth-jwt')('MY.SCRET.CODE.TO.JWT')`

##Middware

middware/index.js
```javascript
var cupJwt = require('cupcoffee-auth-jwt')()

module.exports = () => {

    this.express = () => {
        return cupJwt.middware('/api/*', ({req, res, next}) => {
           //Success callback
            return next()
        })
    }

    return this;

}

```

## Routes
routes/index.js
```javascript
var cupJwt = require('cupcoffee-auth-jwt')()

module.exports = ({router, controller}) => {

    router.post('/login', cupJwt.validate((user, pass) => {
        //.. User authentication, return false or data user
    }).login);

    router.get('/api/*', (req, res) => {
        controller.http(req, res).find();
    })

    return router;
};
```

## Token
In the HTML header to send `x-access-token` with the token and `x-key` with the username;
