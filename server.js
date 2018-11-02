let fs = require('fs');
let uuid = require('uuid/v1');
let sha256 = require('sha256');
let bodyParser = require('body-parser');
let cookieParser = require('cookie-parser');// The Middleware for express to parse cookies
let cookieUtil = require('cookie');// The utility to directly parse cookie strings (used with socket.io)
let express = require('express');
let http = require('http');
let socketIO = require('socket.io');

const PORT = 4000;


// Configure the express app, the io server and the http server (make a soup!)
let app = express();
app.use(bodyParser.raw({type:'*/*'}));
app.use(cookieParser());

let server = http.createServer(app);

let io = socketIO(server);

/* *************************************
*   Server state (data persistence)    *
****************************************/
let serverState = {
    userCreds:{},
    salts:{},
    sessions:{}
};

try{
    serverState = JSON.parse(fs.readFileSync('serverState.txt'));
}catch (err){
    // let it ride, no file exists, we'll just console log that and move on
    console.log('error reading "serverData.txt" file or error JSON parsing its content to an object.');
}


/* ********************** 
*   Express app code    *
*************************/
app.post('/signup', function(req, res){
    // Just make sure the username doesn't already exist 
    let parsedObj = JSON.parse(req.body);

    if (serverState.userCreds[parsedObj.username] !== undefined)
    {
        res.send(JSON.stringify({success:false, msg:'Username already signed up.'}))
    }
    else
    {
        // Deal with the username and password (map, hash and salt)       
        let thisSalt = uuid();
        serverState.salts[parsedObj.username] = thisSalt;
        serverState.userCreds[parsedObj.username] = sha256(parsedObj.password + thisSalt);// storing the hashed/salted pwd
        
        // Deal with the session
        let sessionId = uuid();
        serverState.sessions[sessionId] = parsedObj.username;// mapping the session id to username for later

        let date = new Date();
        date.setMinutes(date.getMinutes() + 30);// cookie expires in an hour
        res.cookie("sessionId", sessionId, {expire:date.toUTCString(), httpOnly:true});

        // Write that to the hard disk
        fs.writeFileSync('serverState.txt', JSON.stringify(serverState));

        //The respond simply states that the operation was successful
        res.send(JSON.stringify({success:true}));
    } 
})

/* If the user is posting to /login, it's a classic login scenario with input boxes and submit */
app.post('/login', function(req, res){

    let parsedObj = JSON.parse(req.body.toString());

    if(serverState.userCreds[parsedObj.username] === sha256(parsedObj.password + serverState.salts[parsedObj.username]))
    {
        // We need to generate a sessionId for this login and use that later on instead of the username
        // Obviously, we'll have mapped that to the username, but we don't want to accumulate
        // huge collections of ids, so we check first that there isn't already a mapping
        for (var key in serverState.sessions)
        {
            if(serverState.sessions[key] === parsedObj.username)
            {
                delete serverState.sessions[key];
                break;
            }
        }

        // Sessions are clean, give a new one and set the cookie for future auto login
        let sessionId = uuid();
        serverState.sessions[sessionId] = parsedObj.username;

        let date = new Date();
        date.setMinutes(date.getMinutes() + 30);
        res.cookie('sessionId', sessionId, {expire:date.toUTCString(), httpOnly:true});


        // Store that to the disk and send response
        fs.writeFileSync('serverState.txt', JSON.stringify(serverState));

        res.send(JSON.stringify({success:true}));
    }
    else
    {
        res.send(JSON.stringify({success:false, msg:'Login failed, try again, but not too much!'}));
    }
})

/* If the user is GETting /login, it's the frontend app sending an automatic request with sessionId cookie presumably set */
app.get('/login', function(req, res){
    // Check to see if the 'sessionId' cookie is set and if it has been mapped by us
    // if so, send success:true
    let cookieId = req.cookies.sessionId;

    if (cookieId  && serverState.sessions[cookieId] !== undefined)
    {
        // This user has been here before and the cookie has been resent by the browser
        res.send(JSON.stringify({success:true}));
    }
    else
    {
        res.send(JSON.stringify({success:false}));
    }
})


/* For convenience, this could later be a logout type of thing  */
app.get('/clearcookie', function(req, res){
    res.clearCookie('sessionId', {httpOnly:true});

    res.send("cookie cleared.")
})

/* ********************* 
*   Socket.io code     *
************************/
// We'll keep track of connected users (users only stay connected when the server is running, once we
// shut down and restart, we loose all connections)
let connectedUsers = [];

io.on('connection', function(socket){
    // Find Out the user's name with the sessionId cookie and push to connectedUsers array
    // also name the socket, we'll use that later
    let sessionId = cookieUtil.parse(socket.handshake.headers.cookie).sessionId;
    let username = serverState.sessions[sessionId];
    connectedUsers.push(username);
    socket.username = username;

    // Send a message to all sockets that a user has joined
    io.emit('userJoined', {users: connectedUsers,
                           serverMsg: username + ' has joined...'});

    // Give this socket callbacks
    socket.on('disconnect', function(reason){
        // Take the user out of the connected users list
        connectedUsers.splice(connectedUsers.indexOf(this.username), 1);

        io.emit('userLeft', {
            users: connectedUsers,
            serverMsg: this.username + ' has left ...'
        })
    })

    socket.on('msg', function(data){
        // Send the message to everyone
        io.emit('msg', {msg: this.username + ": " + data.msg})
    })
})


/* ******************* 
*   Server listen    *
**********************/
server.listen(PORT, function(){ console.log('server listening on ' + PORT)});