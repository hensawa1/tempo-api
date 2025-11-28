const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// CONFIGURAÇÃO CRUCIAL PARA O RENDER:
// O Render injeta a porta automaticamente na variável process.env.PORT
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'segredo_super_seguro';

// Habilita CORS para permitir que seu App Ionic acesse o servidor
app.use(cors());
app.use(bodyParser.json());

// Conexão DB
// AVISO: No plano grátis do Render, este arquivo será resetado quando o servidor reiniciar.
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error(err.message);
    console.log('Conectado ao SQLite.');
});

// Cria tabela de usuários
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    zip TEXT
)`);

// ROTA DE TESTE (Para você saber se o servidor subiu)
app.get('/', (req, res) => {
    res.send('Servidor TempoAoVivo está ONLINE no Render!');
});

// ROTA DE REGISTRO
app.post('/register', (req, res) => {
    const { name, email, password, phone, address, city, zip } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Nome, Email e Senha são obrigatórios.' });
    }

    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Erro no servidor.' });

        const sql = `INSERT INTO users (name, email, password, phone, address, city, zip) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        db.run(sql, [name, email, hash, phone, address, city, zip], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'E-mail já existe.' });
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ message: 'Usuário criado!', userId: this.lastID });
        });
    });
});

// ROTA DE LOGIN
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = `SELECT * FROM users WHERE email = ?`;

    db.get(sql, [email], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Credenciais inválidas.' });

        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) return res.status(401).json({ error: 'Credenciais inválidas.' });

            const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });

            res.json({
                message: 'Login OK',
                token: token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    phone: user.phone,
                    city: user.city,
                    address: user.address,
                    zip: user.zip
                }
            });
        });
    });
});

// Inicialização
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});