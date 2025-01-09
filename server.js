const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const handlebars = require('handlebars');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Connexion à MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connexion à MongoDB réussie');
  })
  .catch((error) => {
    console.error('Erreur de connexion à MongoDB:', error);
  });

// Configuration du transporteur email
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, 
  requireTLS: true,
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD
  }
});



// Fonction d'envoi d'email
const sendEmail = async (email, subject, payload, template) => {
  try {
    const templatePath = path.join(__dirname, 'templates', template);
    const source = fs.readFileSync(templatePath, 'utf8');
    const compiledTemplate = handlebars.compile(source);
    
    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: subject,
      html: compiledTemplate(payload)
    };

    await transporter.sendMail(mailOptions);
    return { success: true };
  } catch (error) {
    console.error('Erreur sendEmail:', error);
    return { success: false, error: error.message };
  }
};

// Schéma utilisateur modifié avec champs optionnels
const userSchema = new mongoose.Schema({
  prenom: { type: String, default: '' },
  nom: { type: String, default: '' }, 
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpiry: Date
});

const User = mongoose.model('User', userSchema);


// Route pour l'inscription
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, prenom = '', nom = '' } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Cet email est déjà utilisé' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      email,
      password: hashedPassword,
      prenom,
      nom
    });
    
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.status(201).json({ 
      token,
      message: 'Inscription réussie ! Bienvenue !',
      user: {
        id: user._id,
        email: user.email,
        prenom: user.prenom,
        nom: user.nom
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur lors de l\'inscription' });
  }
});

// Route pour la connexion
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }
    
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ 
      token,
      message: 'Connexion réussie ! Bon retour parmi nous !',
      user: {
        id: user._id,
        email: user.email,
        prenom: user.prenom,
        nom: user.nom
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur lors de la connexion' });
  }
});

app.get('/api/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Token invalide ou expiré' });
    }
    
    res.json({ message: 'Token valide' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur lors de la vérification du token' });
  }
});
// Route pour la demande de réinitialisation du mot de passe
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }
    
    const resetToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 heure
    await user.save();
    
    // const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
    const resetLink = `https://joyful-malabi-b5abcd.netlify.app/reset-password/${resetToken}`;
    
    const result = await sendEmail(
      email,
      "Réinitialisation de votre mot de passe",
      {
        name: user.prenom || email.split('@')[0], 
        resetLink: resetLink,
      },
      'resetPassword.html'
    );

    if (result.success) {
      res.json({ message: 'Instructions envoyées par email.' });
    } else {
      throw new Error(result.error);
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur lors de la réinitialisation du mot de passe' });
  }
});

// Route pour réinitialiser le mot de passe
app.post('/api/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    
    const user = await User.findOne({
      resetToken,
      resetTokenExpiry: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Token invalide ou expiré' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();
    
    res.json({ message: 'Mot de passe réinitialisé avec succès' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur lors de la réinitialisation du mot de passe' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});