import express from 'express';
import {config} from "dotenv"

config();

const app = express();
const PORT = process.env.PORT || 3000;


app.use(express.json());





app.listen(PORT, () => {
    console.log(`Server running on port http://localhost:${PORT}`);
  });