const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
let toobusy = require("toobusy-js");
const morgan = require("morgan");
var cors = require("cors");
const { xss } = require("express-xss-sanitizer");
const bodyParser = require("body-parser");
const csrf = require("csurf");
var csrfProtection = csrf({ cookie: true });
var express_enforces_ssl = require("express-enforces-ssl");

const app = express();
app.use(morgan("combined"));
//Setup rate limit
const limiter = rateLimit({
  message: "Too many requests, please try again later.", //Message trả về khi vượt limit
  windowMs: 15 * 60 * 1000, // 15 phút
  limit: 3, // Limit mỗi IP 3 request mỗi 15 phút
  standardHeaders: "draft-7", // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
});

//Setup toobusy
toobusy.maxLag(10);
toobusy.interval(40);

//Apply rate limit cho tất cả các route
app.use(limiter)
//Dùng helmet ở đây:
app.use(helmet());


//Setup CORS
var corsOptions = {
  origin: "http://127.0.0.1:5500",
  optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
};
app.use(cors(corsOptions));

//Limit body size
app.use(bodyParser.json({ limit: "10kb" }));
app.use(bodyParser.urlencoded({ extended: true }));

//Parse request body
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

//Prevent XSS attack
app.use(xss());


// enforce https
app.use(express_enforces_ssl());

//CSRF protection
app.use(csrfProtection);


//Bcrypt
const bcrypt = require('bcrypt');

//Compression
const compression = require('compression')
app.use(compression())

//Test compression
app.get('/test', (req, res) => {
  const test = "Hello World"
  res.send(test.repeat(100000))
})

//Test hashing password 
app.post("/login", async (req, res) => {
  const password = req.body.password;
  const saltRounds = 10;
  await bcrypt.genSalt(saltRounds, function(err, salt) {
    bcrypt.hash(password, salt, function(err, hash) {
        res.send(hash);
    });
});
});

//Test XSS attack and ESlint
app.post("/data", (req, res) => {
  console.log("Data received", req.body);
  eval(req.body);
  res.json({ message: "Data received successfully", data: req.body });
});

//Test server too busy
app.get("", async (req, res, next) => {
  if (toobusy()) {
    res.send(503, "Server Too Busy");
  }
  
  res.send("Hello World");
});

app.listen(3000, () =>
  console.log("Server running on port http://localhost:3000")
);
