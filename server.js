import express from 'express';
// import fs from 'fs';
import { readFile } from 'fs/promises';
import { config } from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { writeFile } from 'fs/promises';
import cookieParser from 'cookie-parser';
import cors from 'cors';
// import cookie from 'cookie';



config();

const app = express();
const PORT = process.env.PORT || 3000;


app.use(express.json());
app.use(express.static('public'));


app.use(cookieParser());
app.use(cors())


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
  const jsonData = await readFile(new URL('./payload.JSON', import.meta.url));
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

// Define a route handler for GET requests to '/users'
app.get('/users', async (req, res) => {
  try {
    // Attempt to retrieve user data asynchronously
    const userData = await getUserData();
    // Send the retrieved user data as a JSON response
    res.json(userData);
  } catch (error) {
    // Log any errors to the console
    console.error(error);
    // Send a 500 status code and error message if something goes wrong
    res.status(500).send({ message: 'Error fetching users', error: error.message });
  }
});

app.get('/users/:id', async (req, res) => {
  try {
    // Retrieve existing user data asynchronously
    const userData = await getUserData();
    // Find the user with the provided ID in the user data
    const user = userData.find(u => u.id === parseInt(req.params.id));
    // If the user is found, send it as a JSON response
    if (user) {
      res.json(user);
    } else {
      // If the user is not found, send a 404 status code with an error message
      res.status(404).send({ message: 'User not found' });
    }
  } catch (error) {
    // Log any errors to the console
    console.error(error);
    // Send a 500 status code and error message if something goes wrong
    res.status(500).send({ message: 'Error fetching user', error: error.message });
  
}});


// Define a route handler for GET requests to '/payload'
app.get('/payload', async (req, res) => {
  try {
      // Attempt to retrieve user data asynchronously
    const payloadData = await getPayload();
    // Send the retrieved payload data as a JSON response
    res.json(payloadData);
  } catch (error) {
     // Log any errors to the console
    console.error(error);
     // Send a 500 status code and error message if something goes wrong
    res.status(500).send({ message: 'Error fetching payload', error: error.message });
  }
});


// Define a route handler for POST requests to '/register'
app.post('/register', async (req, res) => {
  try {
    // Hash the password provided in the request body
    const hashedPassword = hashPassword(req.body.password);

    // Retrieve existing user data asynchronously
    const userData = await getUserData();

    // Create a new user object, including the hashed password
    const newUser = { ...req.body, password: hashedPassword };

    // Add the new user to the existing user data
    userData.push(newUser);

    // Write the updated user data back to the users.json file
    await writeFile(new URL('./users.json', import.meta.url), JSON.stringify(userData));

    // Generate a token for the new user
    const token = generateToken(newUser.id);

    // Send a response with a status of 201 (Created), including a success message and the token
    res.status(201).send({ message: 'User registered successfully', token });
  } catch (error) {
    // Send a 500 status code and error message if something goes wrong
    res.status(500).send({ message: 'Error registering user', error: error.message });
  }
});


// Define a route handler for POST requests to '/login'
app.post('/login', async (req, res) => {
  try {
    // Retrieve user data asynchronously
    const userData = await getUserData();
    // Find a user with the matching email in the request body
    const user = userData.find(u => u.email === req.body.email);

    // If user not found, send a 404 status code with an error message
    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }

    // Compare the provided password with the stored hashed password
    const validPassword = bcrypt.compareSync(req.body.password, user.password);
    // If the password is invalid, send a 401 status code with an error message
    if (!validPassword) {
      return res.status(401).send({ message: 'Invalid credentials' });
    }

    // Generate a JSON Web Token (JWT) for the authenticated user
    const token = generateToken(user.id);
    // Set the token and user ID as cookies in the response
    res.cookie('token', token, {
      httpOnly: true,    // Make the cookie inaccessible to JavaScript on the client-side
      secure: false,     // Set to true if using HTTPS
      maxAge: 3600000,   // Set cookie expiration time (1 hour in milliseconds)
      sameSite: 'lax',   // Control when cookies are sent with cross-site requests
    });
    res.cookie('userId', user.id, {
      httpOnly: true,    // Make the cookie inaccessible to JavaScript on the client-side
      secure: false,     // Set to true if using HTTPS
      maxAge: 3600000,   // Set cookie expiration time (1 hour in milliseconds)
      sameSite: 'lax',   // Control when cookies are sent with cross-site requests
    });
    // Send a 200 status code with a success message and the token
    res.status(200).send({ message: 'Login successful', token ,user});
  } catch (error) {
    // Log any errors to the console
    console.error(error);
    // Send a 500 status code with an error message if something goes wrong
    res.status(500).send({ message: 'Error logging in', error: error.message });
  }
});



// Define a route handler for DELETE requests to '/users/:id'
app.delete('/users/:id', async (req, res) => {
  try {
    // Retrieve current user data asynchronously
    const userData = await getUserData();

    // Get the user ID from the request parameters and convert it to an integer
    const userIdToDelete = parseInt(req.params.id, 10);

    // Filter out the user with the specified ID
    const updatedUserData = userData.filter(user => user.id !== userIdToDelete);

    // Check if the user was found and deleted
    if (updatedUserData.length < userData.length) {
      // Write the updated user data back to the file
      await writeFile(new URL('./users.json', import.meta.url), JSON.stringify(updatedUserData));
      // Send a success response
      res.status(200).send({ message: 'User deleted successfully' });
    } else {
      // Send a response indicating the user was not found
      res.status(404).send({ message: 'User not found' });
    }
  } catch (error) {
    // Log any errors to the console
    console.error(error);
    // Send a 500 status code and error message if something goes wrong
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