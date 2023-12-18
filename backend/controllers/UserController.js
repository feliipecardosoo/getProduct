const User = require('../models/User')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

// Healpers
const createUserToken = require('../helpers/create-user-token');
const getToken = require('../helpers/get-token');

module.exports = class UserController {

    static async register (req, res) {
        const {name, email, phone, password, confirmpassword } = req.body

        // Validations
        const validations = [
            { field: 'name', message: 'O nome é obrigatório!' },
            { field: 'email', message: 'O email é obrigatório!' },
            { field: 'phone', message: 'O número é obrigatório!' },
            { field: 'password', message: 'A senha é obrigatória!' },
        ];
        
        for (const validation of validations) {
            const { field, message } = validation;
            if (!req.body[field]) {
                res.status(422).json({ message });
                return;
            }
        }

        // check if user exists
        const userExists = await User.findOne({ email:email })
        
        if(userExists){
            res
            .status(422)
            .json({
                message: 'Por favor, use outro email!'
            })
            return
        }

                // check if passwords match
        if (password !== confirmpassword) {
            res
            .status(422)
            .json({
                message: 'As senhas nao conferem!'
            })
            return
        }

        // create a password
        const salt = await bcrypt.genSalt(12)
        const passwordHash = await bcrypt.hash(password, salt)

        // create a user 
        const user = new User ({
            name,
            email,
            phone,
            password: passwordHash
        })

        try {
            const newUser = await user.save()
            await createUserToken(newUser, req, res) 
        } catch (error) {
            res.status(500).json({message: error})
        }
    }
    static async login (req,res) {

        const {email, password } = req.body

        if(!email) {
            res.status(422).json({ message: 'O email nao foi inserido da maneira correta' })
            return
        }
        if(!password) {
            res.status(422).json({ message: 'A password nao foi inserida da maneira correta '})
            return
        }

         // check if user exists
         const user = await User.findOne({ email:email })
        
         if(!user){
             res
             .status(422)
             .json({
                 message: 'Nao ha usuario cadastrado com este email'
             })
             return
         }

         // check if password match with db password
         const checkPassword = await bcrypt.compare(password, user.password)

         if(!checkPassword) {
            res
            .status(422)
            .json({
                message: 'Senha Invalida'
            })
            return
         }

        await createUserToken(user, req, res)
    }
    static async checkUser (req,res) {

        let currentUser

        if(req.headers.authorization) {
            const token = getToken(req)
            const decoded = jwt.verify(token, 'nossosecret')

            currentUser = await User.findById(decoded.id)
            currentUser.password = undefined
        } else {
            currentUser = null
        }
        res.status(200).send(currentUser)
    }
    static async getUserById (req, res) {

        const id = req.params.id

        const user = await User.findById(id).select('-password')

        if(!user) {
            res
            .status(422)
            .json({
                message: 'Usuario nao encontrado!'
            })
            return
        }
        res.status(200).json({user})
    }
}

 