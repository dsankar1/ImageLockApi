const express = require('express');
const mysql = require('mysql');
const parser = require('body-parser');
const fs = require('fs');
const AWS = require("aws-sdk");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const shortid = require("shortid");
const config = require("./config");
const bucket = "imagelocks3";

// AWS
AWS.config.loadFromPath('./s3_config.json');
var s3 = new AWS.S3();

// Express
var app = express();
var apiRoutes = express.Router();
app.use(parser.json());
app.set('secret', config.secret);

// MySQL
var pool = mysql.createPool({
    connectionLimit: '100',
    host: config.host,
    user: config.user,
    password: config.password,
    database: config.database,
    port: config.port
});

// Error Codes
const userExists = 1;
const userNotFound = 2;
const incorrectPassword = 3;
const serverError = 4;
const missingFields = 5;
const fieldsTooLong = 6;

// Helper Functions
function executeQuery(sql, callback) {
    pool.getConnection(function(err, connection) {
        if (err) {
            return callback(err, null);
        } 
        else {
            connection.query(sql, function(err, result) {
                connection.release();
                if (err) {
                    return callback(err, null);
                }
                return callback(null, result);
            });
        }
    });
}

function hashPassword(password, salt) {
    var hash = crypto.createHash("sha256").update(salt + password).digest("hex");
    return crypto.createHash("sha256").update(hash).digest("hex");
}

// Routes
app.post('/api/register', function(req, res) {
    if (typeof req.body.username != 'undefined' 
        && typeof req.body.password != 'undefined' 
    ) {
        var salt = crypto.randomBytes(2).toString("hex");
        var username = req.body.username;
        var password = req.body.password;

        if (username.length > 30 || password.length > 30) {
            res.json({success: false, errorCode: fieldsTooLong});
        }

        password = hashPassword(password, salt);
        var prefix = shortid.generate() + '/';

        var sql = "insert into users(username, password, prefix, salt) values ('" 
            + username + "', '" + password + "', '" + prefix + "', '" + salt + "');";        

        executeQuery(sql, function(err, result) {
            if (err) {
                if (err.errno === 1062) {
                    console.log("User Already Exists");
                    return res.json({success: false, errorCode: userExists});
                }
                else {
                    console.log("Failed to Connect to Database");
                    return res.json({success: false, errorCode: serverError});
                }
            }
            else {
                console.log("Request Successful");
                const payload = {
                    prefix: prefix
                };
                var token = jwt.sign(payload, app.get('secret'), {
                    expiresIn: "300m" // expires in 5 hours
                });
                res.json({success: true, salt: salt, token: token});
            }
        });
    }
    else {
        console.log("Some Fields Undefined");
        res.json({success: false, errorCode: missingFields});
    }
});

// accepts username and password
// returns JWT
app.post("/api/authenticate", function (req, res) {
    console.log("Request received!");
    if (typeof req.body.username != 'undefined'
        && typeof req.body.password != 'undefined'
    ) {
        var username = req.body.username;
        var password = req.body.password;
        var sql = "select * from users where username='" + username + "';";

        executeQuery(sql, function (err, result) {
            if (err) {
                console.log("Database Server Error");
                res.json({ success: false, errorCode: serverError });
            }
            else if (result.length === 0) {
                console.log("User Not Found");
                res.json({ success: false, errorCode: userNotFound });
            }
            else {
                var user = result[0];
                password = hashPassword(password, user.salt);
                if (user.password === password) {
                    console.log("Request Successful");
                    var prefix = user.prefix;
                    const payload = {
                        username: username,
                        prefix: prefix
                    };
                    var token = jwt.sign(payload, app.get("secret"), {
                        expiresIn: "300m" // expires in 5 hours
                    });
                    res.json({ success: true, salt: user.salt, token: token });
                }
                else {
                    console.log("Incorrect Password");
                    res.json({ success: false, errorCode: incorrectPassword });
                }
            }
        });
    }
    else {
        console.log("Some Fields Undefined");
        res.json({ success: false, errorCode: missingFields });
    }
});

// secures routes that require token to access & decodes token
apiRoutes.use(function (req, res, next) {
    console.log("Checking token...");
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    if (token) {
        jwt.verify(token, app.get('secret'), function (err, decoded) {
            if (err) {
                console.log("Failed to authenticate token!");
                return res.json({ success: false, message: 'Failed to authenticate token.' });
            } else {
                console.log("Token successfully authenticated!");
                req.decoded = decoded;
                next();
            }
        });
    } else {
        console.log("No token was found!");
        return res.json({
            success: false,
            message: 'No token provided.'
        });
    }
});

// x-access-token header needs to be included in all /api requests beyond this point
app.use('/api', apiRoutes);

/*app.get("/api/images", function(req, res) {
    var prefix = req.decoded.prefix;
    var params = {
        Bucket: bucket,
        Prefix: "users/" + prefix
    };
    s3.listObjects(params, function(err, data) {
        if (err) {
            res.json({success: false, error: err});
        }
        else {
            var images = [];
            var keys = data.Contents;
            if (keys.length === 0) res.json({success: true, objects: []});
            for (i = 0; i < keys.length; i++) {
                var key = keys[i].Key;
                var params = {
                    Bucket: bucket,
                    Key: key
                }
                s3.getObject(params, function(err, data) {
                    if (err) {
                        console.log(err);
                        images.push(null);
                    }
                    else {
                        images.push(data);
                        if (images.length === keys.length) {
                            console.log(images.length);
                            res.json({success: true, objects: images});
                        }
                    }
                });
            }
        }
    });
});*/

// Get temporary url for uploading an image
app.post("/api/images", function(req, res) {
    if (typeof req.body.filename != 'undefined') {
        var full_key = "users/" + req.decoded.prefix + req.body.filename;
        var params = {Bucket: bucket, Key: full_key};
        res.json({url: s3.getSignedUrl("putObject", params)});
    }
    else {
        console.log("Some Fields Undefined");
        res.json({ valid: false, errorCode: missingFields });
    }
});

// Delete image with specified filename
app.delete("/api/images/:filename", function(req, res) {
    var key = "users/" + req.decoded.prefix + req.params.filename;
    console.log(key);
    var params = {
        Bucket: bucket,
        Key: key
    }
    s3.deleteObject(params, function(err, data) {
        if (err) {
            res.json({success: false, error: err});
        }
        else {
            res.json({success: true});
        }
    });
});

// Get temp urls for getting images
app.get("/api/images", function(req, res) {
    console.log("Get image urls request received!");
    var prefix = req.decoded.prefix;
    var params = {
        Bucket: bucket,
        Prefix: "users/" + prefix
    };
    s3.listObjects(params, function(err, data) {
        if (err) {
            console.log("Request failed!");
            res.json({success: false, error: err});
        }
        else {
            console.log("Request successful!");
            var objects = data.Contents;
            var urls = [];
            for (i = 0; i < objects.length; i++) {
                var key = objects[i].Key;
                var params = {Bucket: bucket, Key: key};
                urls.push(s3.getSignedUrl("getObject", params));
            }

            res.json({success: true, urls: urls});
        }
    });
});

// Run server on port 3000
app.listen(3002, function () {
    console.log('Image lock api listening on port 3002')
});