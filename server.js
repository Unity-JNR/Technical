import express from 'express';
// import fs from 'fs';
import { readFile } from 'fs/promises';
import { config } from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { writeFile } from 'fs/promises';
import cookieParser from 'cookie-parser';
// import cookie from 'cookie';



config();

const app = express();
const PORT = process.env.PORT || 3000;


app.use(express.json());


app.use(cookieParser());


async function getUserData() {
  // What it means: This function is asynchronous, which means it can wait for things to finish before moving on, using await
  const jsonData = await readFile(new URL('./users.json', import.meta.url));
  /*
  await: Tells the function to wait until the file is read completely.
  readFile: Reads the contents of the file.
  new URL('./users.json', import.meta.url): Specifies the location of the users.json file relative to where the current script is running.

  */
  return JSON.parse(jsonData.toString());
     /*
      jsonData.toString(): Converts the raw file data to a string.
      JSON.parse(...): Converts the string into a JavaScript object.
     */
}

getUserData().then(user => console.log(user));
  /*  getUserData(): Calls the getUserData function.
    .then(user => console.log(user)): Waits for the function to finish, then prints the result (user) to the console. */

async function getPayload(){
  const jsonData = await readFile(new URL('./payload.json', import.meta.url));
  return JSON.parse(jsonData.toString());
}

getPayload().then(payload => console.log(payload));

function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}
/*
 Hashes a password using bcrypt.
 * 
 * This function takes a plain text password and converts it into a hashed version.
 * Hashing is important for security because it ensures that passwords are not
 * stored in plain text, reducing the risk in case of a data breach.
 * The bcrypt algorithm adds random data to the password before hashing,
 * making it more secure against certain types of attacks like rainbow table attacks.
*/

function generateToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

/*
 Generates a JSON Web Token (JWT) for a user ID.
 * his function creates a token that securely identifies a user.
 * JWTs are used for authentication and to securely transmit information
 * between parties. The token expires after 1 hour ('1h'), enhancing security
 * by limiting its validity period.
*/

app.get('/users', async (req, res) => {
  try {
    const userData = await getUserData();
    res.json(userData);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error fetching users', error: error.message });
  }
});
app.get('/payload', async (req, res) => {
  try {
    const payloadData = await getPayload();
    res.json(payloadData);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error fetching payload', error: error.message });
  }
});


app.post('/register', async (req, res) => {
  try {
    const hashedPassword = hashPassword(req.body.password);
    const userData = await getUserData(); // Assuming getUserData reads from a JSON file
    const newUser = {...req.body, password: hashedPassword };
    userData.push(newUser); // Simplified storage logic
    await writeFile(new URL('./users.json', import.meta.url), JSON.stringify(userData));

    const token = generateToken(newUser.id);
    res.status(201).send({ message: 'User registered successfully', token });
  } catch (error) {
    res.status(500).send({ message: 'Error registering user', error: error.message });
  }
});

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
    res.status(200).send({ message: 'Login successful', token });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error logging in', error: error.message });
  }
});

app.delete('/users/:id', async (req, res) => {
  try {
    const userData = await getUserData();
    const userIdToDelete = parseInt(req.params.id, 10); // Convert ID to integer
    const updatedUserData = userData.filter(user => user.id!== userIdToDelete);

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

app.patch('/users/:id', async (req, res) => {
  try {
    const userData = await getUserData();
    const userIdToUpdate = parseInt(req.params.id, 10); // Convert ID to integer
    const { name,...otherUpdatedFields } = req.body; // Destructure the fields to update from the request body

    const userIndex = userData.findIndex(user => user.id === userIdToUpdate);
    if (userIndex!== -1) {
      // Handle password separately since it needs to remain hashed
      if ('password' in otherUpdatedFields) {
        const newPasswordHashed = hashPassword(otherUpdatedFields.password);
        otherUpdatedFields.password = newPasswordHashed;
      }

      // Update the user's name and other fields
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