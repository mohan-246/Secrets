//jshint esversion:6
require("dotenv").config();
const express=require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session=require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require( 'passport-google-oauth20' ).Strategy;
const findOrCreate=require("mongoose-findorcreate");

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret:"thee",
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

const uri=`mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.t4yeixy.mongodb.net/?retryWrites=true&w=majority`;
mongoose.connect(uri);

const userschema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});
userschema.plugin(passportLocalMongoose);
userschema.plugin(findOrCreate);
const User=new mongoose.model("User",userschema);
passport.use(User.createStrategy());


passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
})


passport.use(new GoogleStrategy({
  clientID:     process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  passReqToCallback   : true
},
function(request, accessToken, refreshToken, profile, done) {
  
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return done(err, user);
  });
}
));

app.get("/",(req,res) =>{
    res.render("home");
})
app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));
app.get('/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/auth/google'
}));
app.get("/login",(req,res) =>{
    res.render("login");
})
app.get("/register",(req,res) =>{
    res.render("register");
})
app.post("/register",(req,res) =>{
    User.register({username:req.body.username},req.body.password,function(err,user){
   if(err){
    res.redirect("/register");
   }
   else{
    passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
    })
   }  
    })
   
});
app.get("/secrets",(req,res) =>{
  if(req.isAuthenticated()){
User.find({"secret":{$ne: null}})
.then((founduser)=>{
  res.render("secrets",{usersWithSecrets: founduser});
})
.catch((err)=>{console.log(err)}); }
else{
  res.redirect("/login");
}
}); 

app.get("/submit",(req,res) =>{
  
  if(req.isAuthenticated()){
    
  res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});
app.post("/submit",(req,res)=>{
const newsecret=req.body.secret;

User.findById(req.user.id)
.then((founduser) => {
  founduser.secret=newsecret;
  founduser.save().then(()=>{res.redirect("/secrets");});
})
.catch((err) => {console.log(err);});

});
app.post("/login", function(req, res){
    User.findOne({username: req.body.username})
        .then((foundUser)=>{
      if(foundUser){
      const user = new User({
        username: req.body.username,
        password: req.body.password
      });
        passport.authenticate("local", function(err, user){
          if(err){
            console.log(err);
          } else {
            if(user){
              req.login(user, function(err){
              res.redirect("/secrets");
              });
            } else {
              res.redirect("/login");
            }
          }
        })(req, res);
     
      } })
      .catch((err)=>{
        console.log(err);
        res.redirect("/login")
      });
    });
app.get('/logout',function(req, res){
req.logout((err)=>{
    if(err){
        console.log(err);
        res.redirect("/secrets")
    }
});
res.redirect("/");
});
app.listen(3000,() => {
    console.log("listening");
});