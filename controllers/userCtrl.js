const Users = require('../models/userModel')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const userCtrl = {
    register: async (req, res) =>{
        try{
            const {name, email, password} = req.body;

            const user = await Users.findOne({email})
            if(user) return res.status(400).json({msg: "The email already exists!"})

            if(password.length < 6)
                return res.status(400).json({msg: "Password has to be atleast 6 characters long!"})

            // Password Encryption
            const passwordHash = await bcrypt.hash(password, 10)
            const newUser = new Users({
                name, email, password: passwordHash
            })

            //Save mongodb
            await newUser.save()

            //Create jsonwebtoken to authenticate

            const accesstoken = createAccessToken({id: newUser._id})

            res.json({accesstoken})
            // res.json({msg: "Register Success!"})


        }catch(err){
            return res.status(500).json({msg: err.messagee})
        }
    }
}

const createAccessToken = (user) =>{
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1d'})
}

module.exports = userCtrl 