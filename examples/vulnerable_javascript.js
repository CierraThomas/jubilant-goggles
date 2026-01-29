/**
 * Example file with intentional security vulnerabilities for testing.
 * 
 * DO NOT use this code in production! These are examples of what NOT to do.
 */

const express = require('express');
const child_process = require('child_process');
const mysql = require('mysql');

const app = express();

// Hard-coded credentials (SEC-SEC-001, SEC-SEC-002)
const DB_PASSWORD = "super_secret_password_123";
const API_KEY = "api_key_example_1234567890abcdef";
const GITHUB_TOKEN = "example_token_not_real_1234567890abcd";
const STRIPE_API_EXAMPLE = "example_stripe_key_not_real_1234567890";

// Hard-coded Bearer token in header
const AUTH_HEADER = "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret";


// SQL Injection vulnerability (SEC-INJ-001)
function getUserById(userId) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: DB_PASSWORD,
        database: 'users'
    });
    
    // VULNERABLE: String concatenation in SQL query
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) reject(err);
            resolve(results);
        });
    });
}

function searchUsers(name) {
    // VULNERABLE: Template literal in SQL query
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}


// Command Injection vulnerability (SEC-INJ-002)
function pingHost(hostname) {
    // VULNERABLE: User input in exec
    child_process.exec("ping -c 4 " + hostname, (err, stdout) => {
        console.log(stdout);
    });
}

function runCommand(cmd) {
    // VULNERABLE: execSync with user input
    return child_process.execSync(cmd).toString();
}


// Code Injection vulnerability (SEC-INJ-004)
function calculate(expression) {
    // VULNERABLE: eval with user input
    return eval(expression);
}

function createFunction(code) {
    // VULNERABLE: Function constructor
    return new Function(code);
}

function scheduledCode(delay, code) {
    // VULNERABLE: setTimeout with string
    setTimeout(code, delay);
}


// DOM-based XSS vulnerabilities (SEC-XSS-001)
function displayUserInput(userInput) {
    // VULNERABLE: innerHTML with user input
    document.getElementById('output').innerHTML = userInput;
}

function showMessage(message) {
    // VULNERABLE: document.write
    document.write("<div>" + message + "</div>");
}

function insertContent(content) {
    const element = document.createElement('div');
    // VULNERABLE: outerHTML assignment
    element.outerHTML = content;
}


// Server-side XSS (SEC-XSS-002)
app.get('/greet', (req, res) => {
    const name = req.query.name;
    // VULNERABLE: Sending user input directly
    res.send("<h1>Hello, " + name + "!</h1>");
});

app.get('/profile', (req, res) => {
    // VULNERABLE: Response with request params
    res.write(req.params.bio);
    res.end();
});


// Unsafe jQuery usage (SEC-XSS-003)
function updateContent(data) {
    // VULNERABLE: jQuery .html() with variable
    $('#content').html(data);
    
    // VULNERABLE: jQuery .append() with concatenation
    $('#list').append('<li>' + data + '</li>');
}


// Insecure randomness (SEC-CRYPTO-003)
function generateToken() {
    // VULNERABLE: Math.random() for security token
    return Math.random().toString(36).substring(2);
}

function generateSessionId() {
    // VULNERABLE: Predictable random
    const token = Math.random() * 1000000;
    return Math.floor(token).toString();
}


// Empty catch block (QUAL-ERR-001)
function riskyOperation() {
    try {
        doSomethingDangerous();
    } catch (error) {}  // Silent failure!
}

function anotherRiskyOp() {
    try {
        doAnotherThing();
    } catch (e) {
        // Still empty, just with a comment
    }
}


// High complexity function (QUAL-CMPLX-001)
function processData(data, options, flags, config, settings) {  // Too many params
    let result = [];
    
    for (let item of data) {
        if (options.validate) {
            if (flags.strict) {
                if (item.type === 'A') {
                    if (item.status === 'active') {
                        if (config.filter) {
                            if (settings.transform) {
                                // Deep nesting (QUAL-CMPLX-003)
                                if (item.value > 0) {
                                    result.push(item);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if (options.sort) {
        if (flags.reverse) {
            result.sort((a, b) => b.value - a.value);
        } else {
            result.sort((a, b) => a.value - b.value);
        }
    }
    
    if (options.limit) {
        if (flags.fromEnd) {
            result = result.slice(-options.limit);
        } else {
            result = result.slice(0, options.limit);
        }
    }
    
    return result;
}


// Potential open redirect (SEC-XSS-002)
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // VULNERABLE: Direct redirect to user input
    res.redirect(url);
});


// Start the server
app.listen(3000, () => {
    console.log('Server running on port 3000');
});

module.exports = {
    getUserById,
    searchUsers,
    pingHost,
    generateToken
};
