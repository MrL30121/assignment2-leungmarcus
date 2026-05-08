require('dotenv').config();

console.log("Checking DB variables...");
console.log("Host:", process.env.MONGODB_HOST);
console.log("User:", process.env.MONGODB_USER);
console.log("Password defined?:", process.env.MONGODB_PASSWORD ? "Yes" : "No");
console.log("Database:", process.env.MONGODB_DATABASE);

require('./utils.js');

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const Joi = require("joi");
const mongoSanitizer = require('mongo-sanitizer').default;
//import mongoSanitizer from 'mongo-sanitizer';

const PORT = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000; //expires after 1h  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const { database } = include('databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('users');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(mongoSanitizer(
    { replaceWith: '_' }
));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/nosql-injection', (req, res) => {
    res.send(`
        noSQL injection example:
        <form action='/nosql-injection' method='post'>
            <input name='user' type='text' placeholder='user'>
            <button>Submit</button>
        </form>
        <div style='font-family:Helvetica, arial, sans-serif;'>
            You can use <a href="https://www.postman.com/">Postman <img src="Postman.png" style="height:45px;"/></a> to bypass this form page and perform a NoSQL injection attack.
            <br>
            <br>
            URL: <code>/nosql-injection</code> <br>
            Method: <code>POST</code> <br>
            Body (raw: JSON): <code> { "user": "name" } </code> <br>
            <em>(normal behaviour)</em> <br>
            <br>
            <strong>OR</strong> <br>
            <br>
            Body (raw: JSON): <code>{ "user": {"$ne": "name"} } </code><br>
            <em>(NoSQL injection attack)</em> <br>
            <img src="PostmanSS.png"/>
        </div>
        `)
});

app.post('/nosql-injection', async (req, res) => {
    var username = req.body.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});


// Routes
app.get('/', (req, res) => {
    // Check if the user session exists
    if (req.session.username) {
        // 1. Logged In View
        res.send(`
            <h1>Hello, ${req.session.username}!</h1>
            <a href="/members"><button>Go to Members Area</button></a><br>
            <a href="/logout"><button>Logout</button></a>
        `);
    } else {
        // 2. Not Logged In View
        res.send(`
            <a href="/createUser"><button>Sign up</button></a><br>
            <a href="/login"><button>Log in</button></a>
        `);
    }
});

app.get('/about', (req, res) => {
    var color = req.query.color;

    res.send("<h1 style='color:" + color + ";'>Patrick Guichon</h1>");
});

app.get('/cat/:id', (req, res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: " + cat);
    }
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});

app.get('/createUser', (req, res) => {
    var html = `
    Sign Up:
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'><br>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });

    if (validationResult.error != null) {
        var errorMessage = validationResult.error.details[0].message;

        res.send(`
            ${errorMessage} 
            <br> 
            <a href='/createUser'>Try again</a>
        `);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;

    var html = `<h1>Hello, ${req.session.username}.</h1><a href='/members'><button>Go to Members Area</button></a>
    <br><a href='/logout'><button>Sign out</button></a>`;
    res.send(html);
});

app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            res.redirect('/');
        } else {
            res.redirect('/'); // Redirects back to the Home page as per instructions
        }
    });
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    // Validate what the user actually typed in the login form
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    // Find the user in the database
    const result = await userCollection.find({ email: email }).project({ username: 1, password: 1, _id: 1 }).toArray();
    console.log(result);

    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/login");
        return;
    }

    // Check the password
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;

        // Set the session name using the database result
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        console.log("incorrect password");
        res.send(`
        <p>Invalid email/password combination.</p>
        <a href="/login">Try again</a>
    `);
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }

    // so would this be the jappjopjiate place to put the kode for the inage?j-----------------------------------------------------
    const randomImageNumber = Math.floor(Math.random() * 3) + 1;
    const imageName = `enjoy${randomImageNumber}.png`;
    //--------

    // a. Show "Hello" and the user's name
    // b. Provide a link to the members area (included below)
    // c. Link to logout
    var html = `
        <h1>Hello, ${req.session.username}.</h1>
        <img src='/${imageName}' style='width:250px;'><br>
        <a href="/logout"><button>Sign out</button></a>
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            res.redirect('/');
        } else {
            // This takes you back to the home page automatically
            res.redirect('/');
        }
    });
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});