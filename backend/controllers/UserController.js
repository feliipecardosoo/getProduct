const createUserToken = require('../helpers/create-user-token');
const User = require('../models/User')
const bcrypt = require('bcrypt')

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
}

