const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// CONFIGURAÇÃO DO RENDER
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'segredo_super_seguro';

app.use(cors());
app.use(bodyParser.json());

// Conexão DB (Lembre-se: No plano grátis do Render, isso reseta ao reiniciar)
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error(err.message);
    console.log('Conectado ao SQLite.');
});

// Cria tabela users
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

// Rota de Teste
app.get('/', (req, res) => {
    res.send('API do TempoAoVivo está ONLINE no Render!');
});

// Rota de Cadastro
app.post('/register', (req, res) => {
    const { name, email, password, phone, address, city, zip } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
    }

    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Erro ao criptografar senha.' });

        const sql = `INSERT INTO users (name, email, password, phone, address, city, zip) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        db.run(sql, [name, email, hash, phone, address, city, zip], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'E-mail já cadastrado.' });
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ message: 'Usuário criado com sucesso!', userId: this.lastID });
        });
    });
});

// Rota de Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = `SELECT * FROM users WHERE email = ?`;

    db.get(sql, [email], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Usuário ou senha incorretos.' });

        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) return res.status(401).json({ error: 'Usuário ou senha incorretos.' });

            const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });

            res.json({
                message: 'Login autorizado',
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

// --- ROTA DE PERFIL (COM A CORREÇÃO DO LOGOUT) ---
app.get('/user/:id', (req, res) => {
    const sql = "SELECT id, name, email, phone, city, address, zip FROM users WHERE id = ?";
    db.get(sql, [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: "Erro ao buscar dados" });

        // A MUDANÇA IMPORTANTE ESTÁ AQUI:
        // Se o usuário não for encontrado (ex: banco resetou), devolve erro 404
        if (!row) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        res.json(row);
    });
});

// Atualizar Perfil
app.put('/user/:id', (req, res) => {
    const { name, phone, address, city, zip } = req.body;
    db.run(`UPDATE users SET name=?, phone=?, address=?, city=?, zip=? WHERE id=?`, 
        [name, phone, address, city, zip, req.params.id], 
        (err) => {
            if(err) return res.status(500).json({error: "Erro ao atualizar"});
            res.json({message: 'Atualizado'});
        }
    );
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
