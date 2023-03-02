const express=require('express');
const router = express.Router();

const User=require('../models/User');
const Task=require('../models/task')
const UserVerification=require('../models/UserVerification');
const UserOTPVerification=require('../models/UserOTPVerification');
const PasswordReset=require("../models/PasswordReset");

const tasks=require('./task.controller');
const nodemailer=require('nodemailer');

const {v4:uuidv4}=require('uuid');
// const passport = require('passport');

// require("dotenv").config();
const bcrypt=require('bcrypt');

//path for static verified page
const path=require("path");
const { log } = require('console');
const { config } = require('../config/db.config');

const jwt=require('jsonwebtoken');
const secretOrKey= "secretkey";

let transporter=nodemailer.createTransport({
    service:"gmail",
    auth:{
        user:"kogilakumarasamy@gmail.com",
        pass:"qidahouiiletelco"
    }
})
//testing success
transporter.verify((error,success)=>{
    if(error){
        console.log(error);
    }else{
        console.log("Ready for messages");
        console.log(success);
    }
})


router.post('/signup',(req,res)=>{
    const {name,email,password} = req.body;

    if(name == "" || email == "" || password==""){
        res.json({
            status:"FAILED",
            message:"Empty Input Fields!"
        });
    }else if(password.length < 8){
        res.json({
            status:"CommandFailedEvent",
            message:"Password is too short!"
        })
    } else{
        //checking if user already exists
        User.find({email}).then(result=>{
            if(result.length){
                //A user already exists
                res.json({status:"FAILED",
                message:"User with the provided email already exists"
            })
            } else{
                //try to create a new user
                 
                //password handling
                const saltRounds=10;
                bcrypt.hash(password,saltRounds).then(hashedPassword=>{
                    const newUser = new User({
                        name,
                        email,
                        password:hashedPassword,
                        verified:false
                    });
                    newUser.save().then((result)=>{
                       //handle account verification
                    //    sendVerificationEmail(result,res)
                    sendOTPVerificationEmail(result,res);
                    })
                    .catch((err)=>{
                        res.json({
                            status:"FAILED",
                            message:"An error occured while saving user account!"
                        })
                    })
                })
                .catch((err)=>{
                    res.json({
                        status:"FAILED",
                        message:"An error occured while hashing password!"
                    })
                })
            }
        }).catch((err)=>{
            console.log(err);
            res.json({
                status:"FAILED",
                message:"An error occured while checking for existing user!"
            })
        })
    }
})

//send otp verification email
const sendOTPVerificationEmail=async({_id,email},res)=>{
    const currentUrl="http://127.0.0.1:3000/";
    const uniqueString=uuidv4() + _id;
    try{
        const otp = `${Math.floor(1000+Math.random() *9000)}`
        //mail options
        const mailOptions={
            from:"kogilakumarasamy@gmail.com",
            to:"kogilakumar1003@gmail.com",
            subject:"verify your email",
            html:`<p>Enter <b>${otp}</b>in the app to verify email address and complete signup</p><p>This code <b>expires in 1 hour</b></p>`
        };
        //hash the otp
        const saltRounds=10;
        const hashedOTP = await bcrypt.hash(otp,saltRounds);
        const newOTPVerification=await new UserOTPVerification({
            userId:_id,
            otp:hashedOTP,
            createdAt:Date.now(),
            expiresAt:Date.now() + 3600000,
        });

        //save otp record
        await newOTPVerification.save();
        await transporter.sendMail(mailOptions);
        res.json({
            status:"PENDING",
            message:"Verification otp email sent",
            data:{
                userId:_id,
                email,
            },
        });
    }catch(error){
        console.log(error);
        res.json({
            status:"FAILED",
            message:error.message,
        });
    }
};

//verify otp email
router.post("/verifyOTP",async(req,res)=>{
    try{
        let { userId, otp }=req.body;
        if(!userId || !otp){
            throw Error("Empty otp details are not allowed");
        } else {
            const UserOTPVerificationRecords=await UserOTPVerification.find({
                userId,
            });
            if(UserOTPVerificationRecords.length<=0){
                //no record found
                throw new Error(
                    "account record doesn't exist or has been verified already.Please signin"
                );
            }else{
                //user otp record exists
                const {expiresAt} = UserOTPVerificationRecords[0];
                const hashedOTP = UserOTPVerificationRecords[0].otp;
                if(expiresAt < Date.now()){
                    //user otp record has expired
                    await UserOTPVerification.deleteMany({ userId });
                    throw new Error("Code has expired. Please request again.")
                } else {
                    const validOTP = await bcrypt.compare(otp,hashedOTP);

                    if(!validOTP){
                        //supplied otp is wrong
                        throw new Error("Invalid code paased. Check your Inbox.")
                    } else {
                        //success
                        await User.updateOne({_id:userId},{verified:true});
                        await UserOTPVerification.deleteMany({userId});
                        res.json({
                            status:"Verified",
                            message:"User email verified successfully"
                        })
                    }
                }
            }
        }
    }catch(error){
        res.json({
            status:"FAILED",
            message:error.message
        })
    }
});


//resend verification

router.post("/resendOTPVerificationCode", async(req,res)=>{
    try{
        let {userId,email} = req.body;

        if(!userId || !email){
            throw Error("Empty user details are not allowed")
        } else {
            //delete existing records and resend
            await UserOTPVerification.deleteMany({userId});
            sendOTPVerificationEmail({_id:userId,email},res);
        }
    } catch(error){
        res.json({
            status:"failed",
            message:error.message
        })
    }
});


//signin
router.post('/signin',(req,res)=>{
    const {email,password}=req.body;
    if(email == "" || password==""){
        res.json({
            status:"FAILED",
            message:"Empty credentials supplied"
        })
    }else{
        //check if user exist
        User.find({email}).then(data=>{
            if(data.length){
                //user exists

                // check if user is verified

                if(!data[0].verified){
                    res.json({
                        status:"FAILED",
                        message:"Email hasn't been verified yet. Check your Inbox"
                    })
                } else {
                    const hashedPassword=data[0].password;
                    bcrypt.compare(password,hashedPassword).then(result =>{
                        
                        if(result){
                            //password match
                            jwt.sign({User},secretOrKey,{expiresIn:'300s'},(err,token)=>{
                                
                           
                            res.json({
                                status:"SUCCESS",
                                token:'JWT' +token,
                                message:"Signin Successfull",
                                data:data
                            })
                        })
                        } else {
                            res.json({
                                status:"FAILED",
                                message:"Invalid password entered!"
                            })                        
                        }
                    })
                    .catch(err=>{
                        console.log(err);
                        res.json({
                            status:"FAILED",
                            message:"An error occured while comparing passwords"
                        });
                    });
                }

                
            } else {
                res.json({
                    status:"FAILED",
                    message:"Invalid Credentials entered"
                })
            }
        })
        .catch(err=>{
            res.json({
                status:"FAILED",
                message:"An Error Occured while checking for existing User"
            })
        })
    }
})


//token-verify
router.post("/profile", verifyToken,(req,res)=>{
    jwt.verify(req.token,secretOrKey,(err,authData)=>{
        if(err){
            res.send({result:"Invalid token"})
        } else {
            res.json({
                message:"profile accessed",
                authData
            })
        }
    })
})
function verifyToken(req,res,next){
    const bearerHeader= req.headers['authorization'];
    if(typeof bearerHeader !=='undefined'){
        const bearer = bearerHeader.split(" ");
        const token=bearer[1];
        req.token=token;
        next();
    } else {
        res.send({
            result:"Token is not Valid"
        })
    }
}



// add-task
router.post("/",verifyToken,(req,res)=>{
    const task= new Task({
        taskName:req.body.taskName,
        taskDate:req.body.taskDate,
        taskStatus:req.body.taskStatus
    });
    task.save(task).then(data=>{
        res.send(data);
    })
    .catch(err=>{
        res.status(500).send({
            message:err.message || "some error occured"
        });
    });
});

//get all tasks

router.get("/",verifyToken,(req,res)=>{
    const taskName= req.query.taskName;
    var condition=taskName ? { taskName: { $regex: new RegExp(taskName), $options: "i" } } : {};

    Task.find(condition).then(data=>{
        res.send(data);
    })
    .catch(err=>{
        res.status(500).send({
            message:err.message || "some error occured while retrieving tasks"
        });
    });
});

 //find a single project

 router.get("/:id",verifyToken,(req, res) => {
    const id = req.params.id;
  
    Task.findById(id)
      .then(data => {
        if (!data)
          res.status(404).send({ message: "Not found Task with id " + id });
        else res.send(data);
      })
      .catch(err => {
        res
          .status(500)
          .send({ message: "Error retrieving Tasks with id=" + id });
      });
  }) ;

  // update

  router.put("/:id",verifyToken,(req, res) => {
    if (!req.body) {
      return res.status(400).send({
        message: "Data to update can not be empty!"
      });
    }
  
    const id = req.params.id;
  
    Task.findByIdAndUpdate(id, req.body, { useFindAndModify: false })
      .then(data => {
        if (!data) {
          res.status(404).send({
            message: `Cannot update Task with id=${id}. Maybe Task was not found!`
          });
        } else res.send({ message: "Task was updated successfully." });
      })
      .catch(err => {
        res.status(500).send({
          message: "Error updating Task with id=" + id
        });
      });
  }) ;

  //delete

  router.delete("/:id",verifyToken,(req,res)=> {
    const id = req.params.id;
  
    Task.findByIdAndRemove(id, { useFindAndModify: false })
      .then(data => {
        if (!data) {
          res.status(404).send({
            message: `Cannot delete Task with id=${id}. Maybe Task was not found!`
          });
        } else {
          res.send({
            message: "Task was deleted successfully!"
          });
        }
      })
      .catch(err => {
        res.status(500).send({
          message: "Could not delete Task with id=" + id
        });
      });
  }) ;

//   router.post('/paginate',verifyToken,(req,res)=>{
//     try{

//         var page=req.body.page;
//         var sort=req.body.sort;
//         var task_data;
//         if(sort){

//         } else {
//             task_data=Task.find().limit(2);
//         }
//         res.status(200).send({success:true,msg:'Task details',data:task_data})

//     } catch (error) {
//         res.status(400).send({success:false,msg:error.message});
//     }
//   })

module.exports=router;
