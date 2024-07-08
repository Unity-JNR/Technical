import express from 'express';
import { readFile, writeFile } from 'fs/promises';
import { config } from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';

config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());

// Define CORS options
const corsOptions = {
  origin: 'https://smart-view-760ef.web.app', // Replace with your actual frontend URL
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // Enable credentials (cookies, authorization headers)
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Function to read user data from JSON file
async function getUserData() {
  const jsonData = await readFile(new URL('./users.json', import.meta.url));
  return JSON.parse(jsonData.toString());
}

// Function to read payload data from JSON file
async function getPayload() {
  const jsonData = await readFile(new URL('./payload.JSON', import.meta.url));
  return JSON.parse(jsonData.toString());
}

// Function to hash passwords using bcrypt
function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}

// Function to generate JWT tokens
function generateToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

// Route to fetch all users
app.get('/users', async (req, res) => {
  try {
    const userData = await getUserData();
    res.json(userData);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error fetching users', error: error.message });
  }
});

// Route to fetch a specific user by ID
app.get('/users/:id', async (req, res) => {
  try {
    const userData = await getUserData();
    const user = userData.find(u => u.id === parseInt(req.params.id));
    if (user) {
      res.json(user);
    } else {
      res.status(404).send({ message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error fetching user', error: error.message });
  }
});

// Route to fetch payload data
app.get('/payload', async (req, res) => {
  try {
    const payloadData = await getPayload();
    res.json(payloadData);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error fetching payload', error: error.message });
  }
});

// Route to register a new user
app.post('/register', async (req, res) => {
  try {
    const hashedPassword = hashPassword(req.body.password);
    const userData = await getUserData();
    const newUser = { ...req.body, password: hashedPassword };
    userData.push(newUser);
    await writeFile(new URL('./users.json', import.meta.url), JSON.stringify(userData));
    const token = generateToken(newUser.id);
    res.status(201).send({ message: 'User registered successfully', token });
  } catch (error) {
    res.status(500).send({ message: 'Error registering user', error: error.message });
  }
});

// Route to handle user login
app.post('/login', async (req, res) => {
  try {
    const userData = await getUserData();
    const user = userData.find(u => u.email === req.body.email);
    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }
    const validPassword = bcrypt.compareSync(req.body.password, user.password);
    if (!validPassword) {
      return res.status(401).send({ message: 'Invalid credentials' });
    }
    const token = generateToken(user.id);
    res.cookie('token', token, {
      httpOnly: true,
      secure: false,
      maxAge: 3600000,
      sameSite: 'lax',
    });
    res.cookie('userId', user.id, {
      httpOnly: true,
      secure: false,
      maxAge: 3600000,
      sameSite: 'lax',
    });
    res.status(200).send({ message: 'Login successful', token, user });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error logging in', error: error.message });
  }
});

// Route to delete a user by ID
app.delete('/users/:id', async (req, res) => {
  try {
    const userData = await getUserData();
    const userIdToDelete = parseInt(req.params.id, 10);
    const updatedUserData = userData.filter(user => user.id !== userIdToDelete);
    if (updatedUserData.length < userData.length) {
      await writeFile(new URL('./users.json', import.meta.url), JSON.stringify(updatedUserData));
      res.status(200).send({ message: 'User deleted successfully' });
    } else {
      res.status(404).send({ message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error deleting user', error: error.message });
  }
});

// Route to update a user by ID
app.patch('/users/:id', async (req, res) => {
  try {
    const userData = await getUserData();
    const userIdToUpdate = parseInt(req.params.id, 10);
    const { name, ...otherUpdatedFields } = req.body;
    const userIndex = userData.findIndex(user => user.id === userIdToUpdate);
    if (userIndex !== -1) {
      if ('password' in otherUpdatedFields) {
        const newPasswordHashed = hashPassword(otherUpdatedFields.password);
        otherUpdatedFields.password = newPasswordHashed;
      }
      if (name) {
        userData[userIndex].name = name;
      }
      Object.assign(userData[userIndex], otherUpdatedFields);
      await writeFile(new URL('./users.json', import.meta.url), JSON.stringify(userData));
      res.status(200).send({ message: 'User updated successfully' });
    } else {
      res.status(404).send({ message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error updating user', error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port http://localhost:${PORT}`);
});
