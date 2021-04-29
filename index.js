const MongoClient = require("mongodb").MongoClient;
const express = require('express');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
const crypto = require("crypto");
const cors = require('cors');

const app = express();
app.use(cors())
//app.use(bodyParser.urlencoded({extended:false}))
//app.use(bodyParser.json())
var jsonParser = bodyParser.json();
var urlencodedParser = bodyParser.urlencoded({extended:false});
app.listen(8000, function(req, res) {
  console.log("Server is running at port 8000");
});

const connection_string = "mongodb://localhost:27017/";
MongoClient.connect(connection_string,{ useUnifiedTopology: true },function(err,client){
    if(err)throw err;
    console.log("Connected to MongoDB");
    var db = client.db("blog"); 
    //get all the user
    app.get('/user',verifyToken,function(req, res) {
        db.collection("user").find({}).toArray(function(err,result){
            if(err)throw err;
            console.log(result);
            res.send(result);
            //client.close();
        })
    })

    // Get single user
app.get('/user/:id', urlencodedParser,verifyToken,function(req, res) {
    let id=parseInt(req.params.id, 10);
    console.log(id);
    db.collection("user").findOne({id:id},function(err,result){
        if(err)throw err;
        console.log(result);
        res.send(result);
    })
  })

  //Delete a new user
app.delete('/user/:id', urlencodedParser,verifyToken,function(req, res) {
    let id=parseInt(req.params.id, 10);
    console.log(id);
    db.collection("user").deleteOne({id:id},function(err,result){
        if(err)throw err;
        console.log("user deleted");
        res.send(result);
        //client.close();
    })
  })

  //Post a new user
app.post('/user',jsonParser, verifyToken,function(req, res) {
    let id = req.body.id;
    let username = req.body.username;
    let password = req.body.password;
    let fname = req.body.fname;
    console.log(id+" "+username+" "+password+" "+fname);
    const hashResult = hashSSHA(password);
    req.body.password = hashResult.encrypted;
    req.body.salt = hashResult.salt;
    db.collection("user").insertOne(req.body,function(err,result){
        if(err)throw err;
        console.log("user inserted");
        console.log(result);
        res.send(result);
        //client.close();
    })
  })


//Update a user
app.patch('/user', jsonParser,verifyToken,function(req, res) {
    let id=parseInt(req.body.id, 10);
    let username = req.body.username;
    let password = req.body.password;
    let fname = req.body.fname;
   
    console.log(id+" "+username+" "+password+" "+fname);
    const hashResult = hashSSHA(password);
    req.body.password = hashResult.encrypted;
    req.body.salt = hashResult.salt;
    db.collection("user").updateOne({id:id},{$set:req.body},function(err,result){
        if(err)throw err;
        console.log("user updated");
        console.log(result.result);
        res.send(result);
        //client.close();
    })
  })

  function verifyToken(req,res,next){
    let authHeader = req.headers.authorization;
    console.log("authHeader="+authHeader);
    if(authHeader==undefined){
      res.status(401).send({error:"no token provided"});
    }
    let token = authHeader.split(" ")[1];
    console.log("token="+token);
    jwt.verify(token,"secret",function(err,decoded){
      if(err){
        res.send(err);
        console.log(err);
        //res.status(500).send({error:"Authentication failed from token"});
      }else{
        console.log("Authentication success");
        next();
      }
    })
  }
  
  app.post('/login',jsonParser,function(req,res){
    if(req.body.id==undefined||req.body.password==undefined){
      res.status(500).send({error:"authentication failed from login"});
    }
    let id=parseInt(req.body.id, 10);
    let password = req.body.password;
    console.log("id="+id)
    console.log("password="+password)

     db.collection("user").findOne({id:id},function(err,result){
      if(err||result.length==0){
        res.status(500).send({error:"login failed"});
      }else{
        const salt = result.salt;
        const pwd = checkhashSSHA(salt, password);
        if(pwd==result.password){
        let resp = {
              id : result.id,
              username : result.username,
              password : password
        }
        let token = jwt.sign(resp,"secret",{});
        res.status(200).send({
          id : result.id,
              username : result.username,
              password : password,
              token:token
        });
      }else{
        res.status(500).send({error:"login failed"});
       }
      }
    })
  })
  function hashSSHA(password){
    let salt = crypto.createHash('sha1').update(crypto.randomBytes(8)).digest('base64');
    salt = salt.substring(0,10);
    const hash = crypto.createHash('sha1');
    hash.update(password + salt);
    return {
        salt: salt,
        encrypted: Buffer.concat([hash.digest(), Buffer.from(salt)]).toString('base64')
    };
  };
  
  function checkhashSSHA(salt, password) {
    const hash = crypto.createHash('sha1');
    hash.update(password + salt);
    return Buffer.concat([hash.digest(), Buffer.from(salt)]).toString('base64');
  }
})