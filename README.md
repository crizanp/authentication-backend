# Backend Setup for Your Project

This repository contains the backend code for your project. Follow the instructions below to set up and run the backend on your local machine.

## Prerequisites

Ensure you have the following installed:
- [Node.js](https://nodejs.org/) (v12 or higher)
- [npm](https://www.npmjs.com/) (comes with Node.js)
- [MongoDB](https://www.mongodb.com/cloud/atlas) (set up a MongoDB Atlas cluster or a local instance)
- [Git](https://git-scm.com/)

## Installation

Follow these steps to get the backend running on your local machine:

### 1. Clone the repository
Clone the repository to your local machine using the following command:

- git clone https://github.com/crizanp/authentication-backend

### 2 .env Backend

MONGO_URI=mongodb+srv://username:<password>@cluster0.nugvn.mongodb.net/
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRES_IN=3600
EMAIL_HOST=smtp.gmail.com
EMAIL_USER=user@gmail.com
EMAIL_PASS=here shou ldbe keys

-Replace username:<password> in MONGO_URI with your MongoDB credentials.
-Set your own secret key in JWT_SECRET.
-Set the expiration time in JWT_EXPIRES_IN (in seconds).
-Update EMAIL_USER and EMAIL_PASS with your email credentials (ensure access to Gmail SMTP if using Gmail).

### 3 install dependencies

-npm install

### 4 start server

node server.js
or, npm run dev 
or, npm start

Once the backend is running, follow the instructions in the Frontend GitHub repository - https://github.com/crizanp/full-auth-system to complete the frontend setup.


