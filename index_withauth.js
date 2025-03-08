// Import required modules
const express = require('express');                    // Express framework for building web applications
const routes = require('./routes/users.js');           // User routes module (handles endpoints under /user)
const jwt = require('jsonwebtoken');                   // Library to create and verify JSON Web Tokens (JWT)
const session = require('express-session');            // Middleware for managing user sessions

const app = express();                                 // Create an instance of the Express application
const PORT = 5000;                                     // Define the port on which the server will run

// Initialize session middleware with options
//   secret: A random unique string key used to authenticate a session.
//   resave: Boolean flag that forces the session to be saved back to the session store,
//           even if the session was never modified during the request.
//   saveUninitialized: Allows new but unmodified sessions (uninitialized) to be saved to the store.
app.use(session({ 
    secret: "fingerpint", 
    resave: true, 
    saveUninitialized: true 
}));

// Middleware for user authentication applied to all routes starting with "/user"
app.use("/user", (req, res, next) => {
    // Check if the session contains an authorization object with an access token
    if (req.session.authorization) {
        // Extract the access token from the session
        let token = req.session.authorization['accessToken'];
        
        // Verify the JWT token using the secret key "access"
        jwt.verify(token, "access", (err, user) => {
            if (!err) {
                // If token verification is successful, attach the decoded user data to the request object
                req.user = user;
                next(); // Proceed to the next middleware or route handler
            } else {
                // If token verification fails, respond with a 403 Forbidden status and error message
                return res.status(403).json({ message: "User not authenticated" });
            }
        });
    } else {
        // If no access token is found in the session, respond with a 403 Forbidden status and error message
        return res.status(403).json({ message: "User not logged in" });
    }
});

// Middleware to parse incoming JSON payloads in the request body
app.use(express.json());

// Mount user-related routes under the "/user" endpoint
app.use("/user", routes);

// Login endpoint to authenticate a user and start a session
app.post("/login", (req, res) => {
    // Extract user data from the request body
    const user = req.body.user;
    if (!user) {
        // If the user data is missing, respond with a 404 status and error message
        return res.status(404).json({ message: "Body Empty" });
    }
    
    // Generate a JWT access token for the user
    // The token includes user data and is signed with the secret key "access"
    // The token will expire in 1 hour (60 * 60 seconds)
    let accessToken = jwt.sign({
        data: user
    }, 'access', { expiresIn: 60 * 60 });

    // Store the generated access token in the session under the "authorization" property
    req.session.authorization = {
        accessToken
    };
    
    // Respond with a success message indicating the user is logged in
    return res.status(200).send("User successfully logged in");
});

// Start the Express server and listen on the defined PORT
app.listen(PORT, () => console.log("Server is running at port " + PORT));
