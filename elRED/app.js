const express = require('express');
const bodyparser=require('body-parser');
const cors=require('cors');
const app=express();

const config=require('./config/db.config');
const UserRouter= require('./api/User');
const task=require('./api/task.controller');

const jwt= require("jsonwebtoken");

const db= require('./models');
db.mongoose.connect(db.url,{
    useNewUrlParser:true,
    useUnifiedTopology:true
}).then(()=>{
    console.log("Connected to the database!");
})
.catch(err => {
    console.log("Cannot connect to the database!", err);
    process.exit();
  });

  app.get("/", (req, res) => {
    res.json({ message: "Welcome to application." });
  });

  app.use(cors());    

  app.use(bodyparser.json());
  
  app.use(bodyparser.urlencoded({extended: false}));
  // app.use(task);

app.use('/user',UserRouter);

const PORT=process.env.PORT || 3000;
app.listen(PORT,()=>{
    console.log(`Server is running on port ${PORT}.`);
});