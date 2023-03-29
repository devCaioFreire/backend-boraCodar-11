// IMPORTS
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();

// Define as opções do CORS
const corsOptions = {
    origin: 'http://localhost:5173',
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST']
};

// Adiciona o middleware CORS às rotas
app.use(cors(corsOptions));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


// MODELS
const User = require('./models/User');

// CREDENCIAIS
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;

// CONFIG JSON RESPONSE
app.use(express.json());

// CONEXÃO COM BANCO DE DADOS
mongoose
    .connect(`mongodb+srv://${DB_USER}:${DB_PASS}@vertigo.okghfuw.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3001)
        console.log('Server is running');
    })
    .catch((err) => console.log(err));

// ROTA PUBLICA
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'API RUNNING' });
})

// ROTA PRIVADA
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // VERIFICANDO SE O ID EXISTE NO BANCO DE DADOS
    const user = await User.findById(id, '-password');
    if (!user) {
        return res.status(404).json({ msg: 'Usuário não autenticado!' });
    };
    res.status(200).json({ user });
});

// REGISTRANDO USUÁRIO
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    // VALIDAÇÕES
    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório!' })
    }
    if (!email) {
        return res.status(422).json({ msg: 'O e-mail é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    // VERIFICANDO SE O USER EXISTE
    const userExist = await User.findOne({ email });

    if (userExist) {
        return res.status(422).json({ msg: 'Esse e-mail já está sendo utilizado!' })
    }

    // CRIANDO A SENHA
    const salt = await bcrypt.genSalt(15);
    const passwordHash = await bcrypt.hash(password, salt);

    // CRIPTOGRAFA A SENHA ANTES DE SALVAR NO BANCO DE DADOS
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save();

        res.status(201).json({ msg: 'Usuário registrado no banco de dados.' });
    }
    catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Parece que houve um erro interno no servidor... tente novamente mais tarde.' })
    }
})

// LOGANDO USUÁRIO
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    // VERIFICANDO SE O USER EXISTE
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    // VALIDAÇÕES
    if (!email) {
        return res.status(422).json({ msg: 'O e-mail é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    // COMPARANDO SE A SENHA É IGUAL
    const checkPassword = await bcrypt.compare(password, user.password)
    if (!checkPassword) {
        return res.status(404).json({ msg: 'A senha está incorreta!' })
    }

    try {
        const secret = process.env.SECRET;
        const { _id, name } = user;
        const userProps = { _id, name };

        const token = jwt.sign({ id: user._id, }, secret);
        res.cookie('token', token, { httpOnly: true });
        res.status(200).json({ msg: 'Usuário autenticado', token, userProps });
    }
    catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Parece que houve um erro interno no servidor... tente novamente mais tarde.' })
    }
})

function checkToken(req, res, next) {
    // const authHeader = req.headers['authorization'];
    // const token = authHeader && authHeader.split(' ')[1];
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ msg: 'Acesso Negado!' })
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next();
    }
    catch (error) {
        res.status(400).json({ msg: 'Token Inválido!' })
    }
}
