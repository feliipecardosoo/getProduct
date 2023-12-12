const User = require('../models/User')

module.exports = class UserController {

    static async register (req, res) {
        const {name, email, phone, password, confirmpassword } = req.body

        // Validations
        const validations = [
            { field: 'name', message: 'O nome é obrigatório!' },
            { field: 'email', message: 'O email é obrigatório!' },
            { field: 'phone', message: 'O número é obrigatório!' },
            { field: 'password', message: 'A senha é obrigatória!' },
            { field: 'confirmpassword', message: 'As senhas não são correspondentes' }
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
                message: 'Por favor, use outro!'
            })
            return
        }
    }
}

