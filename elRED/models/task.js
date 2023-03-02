const mongoose=require('mongoose');
const Schema=mongoose.Schema;

const TaskSchema = new Schema({
    taskName:String,
    taskDate:Date,
    taskStatus:String
    // verified:Boolean
})

const Task= mongoose.model('Task',TaskSchema);

module.exports=Task