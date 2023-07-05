const express = require('express');
const app = express();
const routes = require('./routes');

const { verifyToken } = require('./authMiddleware');
// ... Any other necessary setup

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(verifyToken);

app.use('/', routes);
const port = process.env.PORT;

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});