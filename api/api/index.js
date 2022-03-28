const method    = require('../methods/validation')
const db        = require('../db/db')
const bcrypt    = require('bcrypt')
const jwt       = require('jsonwebtoken')
const express   = require('express')
const server    = express.Router()

const {  Secret }    = require('../.env')


function authorizedUser(req,res,next){
    const _Token = req.headers['x-access-token']

    jwt.verify(_Token,Secret,(err, decoded)=>{
        if(err) return res.status(401)
                          .send('Você precisa estar logado para esta ação.')

        req.id = decoded.id
        next()
    })
}


const cryptograph = password =>{
    const salt = bcrypt.genSaltSync(10)
    return bcrypt.hashSync(password,salt)
}


server.route('/api/v1/users').get(authorizedUser,async(req,res)=>{
    await db.select(['id','nome','email'])
            .from('usuario')
            .then(response => res.status(200).json(response))
            .catch(_ => res.status(500).send('Ocorreu um erro no servidor.'))
}).post(async(req, res)=>{
    const USERS = {  ...req.body  }

    try{
        method(USERS.nome,  'Nome de usuário não informado.')
        method(USERS.email, 'Email não informado.')
        method(USERS.senha, 'senha não informada.')
    }catch(_){
        return res.status(500).send('Ocorreu um erro no servidor.')
    }

    USERS.senha = cryptograph(USERS.senha)

   await db.insert(USERS)
           .from('usuario')
           .then(_ =>  res.status(201).send('Usuário criado com sucesso.'))
           .catch(_ => res.status(400).send('Erro ao inserir os dados.'))
}).delete(authorizedUser,async(req,res)=>{
    await db.delete()
            .table('usuario')
            .then(_ => res.status(204).send('Dados removidos com Sucesso.'))  
            .catch(_ => res.status(500).send('Ocorreu um erro no servidor.'))
})


server.route('/api/v1/users/:id').get(authorizedUser,async(req,res)=>{
    const USERS = { ...req.params }

    await db.where({id: USERS.id})
            .select(['id','nome','email'])
            .from('usuario')
            .then(response => res.status(200).json(response))
            .catch(_     => res.status(500).send('Ocorreu um erro no servidor.'))
}).delete(authorizedUser,async(req,res)=>{
    const USERS = { ...req.params }

    await db.where({id: USERS.id})
            .delete()
            .from('usuario')
            .then(_ => res.status(204).json())
            .catch(err => res.status(404).send(err))
}).put(authorizedUser,async(req,res)=>{
    const USERS   = {  ...req.body   }

    const searchUser = await db.where({ email: USERS.email })
                               .andWhere('id',req.params.id)
                               .table('usuario')
                               .first()

    if(!searchUser) return res.status(404)
                              .send('Usuário não encontrado.')
    
    if(searchUser){
            try{
                method(USERS.nome,  'Nome de usuário não informado.')
                method(USERS.email, 'Email não informado.')
                method(USERS.senha, 'Senha não informada.')
        }catch(err){
            return res.status(400)
                      .send(err)
        }

        USERS.senha = cryptograph(USERS.senha)

        await db.where({id: req.params.id})
                .update(USERS)
                .from('usuario')
                .then(_ => res.status(201).send('Usuário alterado com sucesso.'))
                .catch(_ => res.status(500).send('Ocorreu um erro no servidor.'))
    }
   
})


server.route('/api/v1/login').post(async(req,res)=>{
    const USERS = {  ...req.body  }

    if(!USERS.email || !USERS.senha) return res.status(400)
                                               .send('Email e senha não informados.')

    const searchUser = await db.where({ email: USERS.email })
                               .table('usuario')
                               .first()

    if(!searchUser) return res.status(404)
                              .send('Usuário não encontrado.')

    if(searchUser) {
        const passwordCompare = bcrypt.compareSync(USERS.senha,searchUser.senha)

        if(!passwordCompare) return res.status(401)
                                       .send('Email/Senha inválidos!')

        if(passwordCompare) {

                     const _Token = jwt.sign({id: USERS.id}, 
                                                     Secret,
                                          { expiresIn: 60 })

            return    db.where({email: USERS.email})
                        .first()
                        .table('usuario')
                        .then(_ => {res.status(200).json({
                                auth: true,
                                _Token
                        })})
                        .catch(err => res.status(400).json(err))
     }
    }
})


module.exports = server