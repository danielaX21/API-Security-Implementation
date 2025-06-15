# 🔐 JWT Task Manager – Go-Based Secure Task App

## Project Overview

This project is a secure, token-based task management system built with **Go (Golang)** and a lightweight **HTML/JavaScript** frontend. It provides user authentication using **JWT (JSON Web Tokens)** and supports **role-based access control** (admin/user). Authenticated users can view and add personal tasks, while administrators have elevated access to view all users.

Frontend: `index.html`  
Backend API: Runs locally on `localhost:8080`

---

## The Go Backend Is Responsible For:

- Reading and validating users stored in a `users.json` file (passwords encrypted using bcrypt).
- Generating JWT tokens with embedded claims (username and role).
- Verifying tokens for secure access to protected API endpoints.
- Providing role-based access to admin-only features.
- Logging all requests and errors into `api.log`.
- Handling CORS headers for frontend compatibility.

---

## How It Works

### 🔐 Authentication & Authorization

- A user logs in via the HTML page by providing a **username** and **password**.
- The backend validates the credentials and returns a **JWT token** on success.
- The frontend stores this token locally and attaches it to every API request.
- Token includes role info (`admin` or `user`), used for permission checks.

### 📋 Task Management

- Authenticated users can view (`GET /tasks`) and add (`POST /tasks`) their personal tasks.
- Tasks are stored in memory (per session) and are isolated per user.

### 🛡️ Admin Features

- Admin users can access an additional endpoint: `GET /admin/users`
- This endpoint returns a list of all usernames (no passwords or sensitive data).
- Visible only to admins in the frontend through a dynamic UI button.

---

## Skills Applied in This Project

- Web backend development with **Go** and `gin-gonic`
- **JWT-based security** and token validation
- **Role-based access control** via middleware
- Password encryption using `bcrypt`
- Secure frontend interaction via **Authorization headers**
- Logging and error handling
- CORS setup for client-server communication

---

## Technologies & Components Used

- [Go (Golang)](https://golang.org/) – Backend language
- [Gin](https://github.com/gin-gonic/gin) – HTTP web framework
- [JWT (dgrijalva/jwt-go)](https://github.com/dgrijalva/jwt-go) – Token-based authentication
- [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) – Password hashing
- HTML + JavaScript – Frontend UI
- LocalStorage – Token storage on client side
- JSON – Used for storing users and tasks

---

## How to Run the Project

### 1. Install Dependencies

go get github.com/gin-gonic/gin
go get github.com/dgrijalva/jwt-go
go get golang.org/x/crypto/bcrypt

### 2.Create users.json
You can generate hashed passwords using the code from bycript folder.

### 3. Run the backend server
go run main.go

### 4.Open thefrontend for index.html
---
## Real-World Applications – Why This Project Is Important

- This project offers a lightweight yet powerful template for:

- Secure API design using token-based authentication

- Building admin panels with role-based access

- Prototyping task or user management apps

- Learning Go's middleware and web service capabilities