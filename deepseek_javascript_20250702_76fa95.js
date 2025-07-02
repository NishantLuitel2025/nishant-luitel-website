// server.js
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/nishant-luitel', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// User Model
const User = mongoose.model('User', {
    username: String,
    email: String,
    password: String,
    createdAt: { type: Date, default: Date.now }
});

// File Model
const File = mongoose.model('File', {
    filename: String,
    path: String,
    size: Number,
    type: String,
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    sharedWith: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        permission: { type: String, enum: ['view', 'download', 'edit'] }
    }],
    createdAt: { type: Date, default: Date.now }
});

// Configure file storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send('Access denied');
    
    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send('Invalid token');
    }
};

// Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).send('User already exists');
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create user
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        
        // Create token
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
        
        res.header('Authorization', token).send({ user, token });
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('Invalid credentials');
        
        // Check password
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).send('Invalid credentials');
        
        // Create token
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
        
        res.header('Authorization', token).send({ user, token });
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/api/files', authenticate, upload.single('file'), async (req, res) => {
    try {
        const { originalname, filename, size, mimetype } = req.file;
        
        const file = new File({
            filename: originalname,
            path: filename,
            size,
            type: mimetype,
            owner: req.user._id
        });
        
        await file.save();
        res.send(file);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.get('/api/files', authenticate, async (req, res) => {
    try {
        const files = await File.find({
            $or: [
                { owner: req.user._id },
                { 'sharedWith.user': req.user._id }
            ]
        }).populate('owner', 'username');
        
        res.send(files);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/api/files/:id/share', authenticate, async (req, res) => {
    try {
        const { userId, permission } = req.body;
        const file = await File.findOne({
            _id: req.params.id,
            owner: req.user._id
        });
        
        if (!file) return res.status(404).send('File not found');
        
        file.sharedWith.push({ user: userId, permission });
        await file.save();
        
        res.send(file);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));