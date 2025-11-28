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

// Conexão DB (Resetado ao reiniciar no plano grátis)
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

// --- ROTA DE CADASTRO COM VALIDAÇÕES ---
app.post('/register', (req, res) => {
    const { name, email, password, phone, address, city, zip } = req.body;

    // 1. Validação de Campos Obrigatórios
    if (!name || !email || !password || !phone || !zip) {
        return res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
    }

    // 2. Validação de Senha (Mínimo 8 caracteres)
    if (password.length < 8) {
        return res.status(400).json({ error: 'A senha deve ter no mínimo 8 caracteres.' });
    }

    // 3. Validação de Telefone (Limpeza e DDD)
    // Remove tudo que não for número
    const cleanPhone = phone.toString().replace(/\D/g, '');
    // Aceita: (11) 99999-9999 (11 dígitos) ou (11) 3333-3333 (10 dígitos)
    if (cleanPhone.length < 10 || cleanPhone.length > 11) {
        return res.status(400).json({ error: 'Telefone inválido. Use o formato DDD+Número (Ex: 11999999999).' });
    }

    // 4. Validação de CEP (Deve ter 8 dígitos)
    const cleanZip = zip.toString().replace(/\D/g, '');
    if (cleanZip.length !== 8) {
        return res.status(400).json({ error: 'CEP inválido. Deve conter apenas 8 números.' });
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

// Rota de Perfil (Protegida contra banco resetado)
app.get('/user/:id', (req, res) => {
    const sql = "SELECT id, name, email, phone, city, address, zip FROM users WHERE id = ?";
    db.get(sql, [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: "Erro ao buscar dados" });

        // Se não achar o usuário, retorna 404 para o app deslogar
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