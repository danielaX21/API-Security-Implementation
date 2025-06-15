// package main

// import (
// 	"net/http"
// 	"os"
// 	"strings"
// 	"time"

// 	"github.com/dgrijalva/jwt-go"
// 	"github.com/gin-gonic/gin"
// )

// var jwtKey = []byte("my_secret_key")

// type Claims struct {
// 	Username string `json:"username"`
// 	jwt.StandardClaims
// }

// func generateToken(c *gin.Context) {
// 	claims := &Claims{
// 		Username: "user",
// 		StandardClaims: jwt.StandardClaims{
// 			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
// 		},
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(jwtKey)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"token": tokenString})
// }

// func extractToken(c *gin.Context) string {
// 	authHeader := c.GetHeader("Authorization")
// 	if authHeader == "" {
// 		return ""
// 	}
// 	parts := strings.Split(authHeader, " ")
// 	if len(parts) == 2 && parts[0] == "Bearer" {
// 		return parts[1]
// 	}
// 	return ""
// }

// func protectedEndpoint(c *gin.Context) {
// 	tokenString := extractToken(c)
// 	if tokenString == "" {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or wrong format token"})
// 		return
// 	}

// 	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
// 		return jwtKey, nil
// 	})

// 	if err != nil || !token.Valid {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return
// 	}

// 	claims, ok := token.Claims.(*Claims)
// 	if !ok || claims.ExpiresAt < time.Now().Unix() {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired or is invalid"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "This is a protected resource!"})
// }

// func main() {
// 	// Deschide sau creează fișierul de log
// 	f, err := os.OpenFile("api.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		panic(err)
// 	}

// 	// Gin va scrie logurile în fișier
// 	gin.DefaultWriter = f
// 	gin.DefaultErrorWriter = f

// 	r := gin.Default()

// 	r.POST("/token", generateToken)
// 	r.GET("/protected", protectedEndpoint)

// 	r.Run(":8080")
// }

// /*HOW to run
// Terminal 1
// trebuie descracte dependintele
// 1 go get -u github.com/gin-gonic/gin
// 2 go get -u github.com/dgrijalva/jwt-go
// 3 go run main.go
// output:
// [GIN-debug] Listening and serving HTTP on :8080

// Terminal 2
// 1 pentru a obtine tockenul :curl -X POST http://localhost:8080/token
// 2 daca incerc sa accesez endppointul fara a introduce tockenul curl -X GET http://localhost:8080/protected
// { "message": Missing tocken"}
// 3 curl -X GET http://localhost:8080/protected -H "Authorization: Bearer my_token"
// { "message": "This is a protected resource!" }

// */

// //var2
// package main

// import (
// 	"net/http"
// 	"os"
// 	"strings"
// 	"time"

// 	"github.com/dgrijalva/jwt-go"
// 	"github.com/gin-gonic/gin"
// )

// // cheia secretă pentru semnarea tokenurilor
// var jwtKey = []byte("my_secret_key")

// // simulăm o bază de date de useri cu parole și roluri
// var users = map[string]struct {
// 	Password string
// 	Role     string
// }{
// 	"admin": {"adminpass", "admin"},
// 	"user":  {"userpass", "user"},
// }

// // Claims - structura care va fi stocată în JWT
// type Claims struct {
// 	Username string `json:"username"`
// 	Role     string `json:"role"`
// 	jwt.StandardClaims
// }

// // Funcție pentru generarea tokenului JWT pe baza username/parolă
// func generateToken(c *gin.Context) {
// 	var creds struct {
// 		Username string `json:"username"`
// 		Password string `json:"password"`
// 	}
// 	if err := c.ShouldBindJSON(&creds); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
// 		return
// 	}

// 	// Verificăm dacă utilizatorul există și parola e corectă
// 	user, ok := users[creds.Username]
// 	if !ok || user.Password != creds.Password {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
// 		return
// 	}

// 	// Cream token-ul cu nume și rol
// 	claims := &Claims{
// 		Username: creds.Username,
// 		Role:     user.Role,
// 		StandardClaims: jwt.StandardClaims{
// 			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
// 		},
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(jwtKey)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"token": tokenString})
// }

// // Extragem tokenul JWT din headerul Authorization
// func extractToken(c *gin.Context) string {
// 	authHeader := c.GetHeader("Authorization")
// 	if authHeader == "" {
// 		return ""
// 	}
// 	parts := strings.Split(authHeader, " ")
// 	if len(parts) == 2 && parts[0] == "Bearer" {
// 		return parts[1]
// 	}
// 	return ""
// }

// // Middleware pentru a verifica tokenul și extrage Claims
// func validateToken(c *gin.Context) (*Claims, bool) {
// 	tokenString := extractToken(c)
// 	if tokenString == "" {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or wrong format token"})
// 		return nil, false
// 	}

// 	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
// 		return jwtKey, nil
// 	})
// 	if err != nil || !token.Valid {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return nil, false
// 	}

// 	claims, ok := token.Claims.(*Claims)
// 	if !ok || claims.ExpiresAt < time.Now().Unix() {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired or is invalid"})
// 		return nil, false
// 	}

// 	return claims, true
// }

// // Endpoint protejat – accesat doar cu token valid (oricine)
// func userEndpoint(c *gin.Context) {
// 	claims, ok := validateToken(c)
// 	if !ok {
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{
// 		"message":  "Hello, user!",
// 		"username": claims.Username,
// 		"role":     claims.Role,
// 	})
// }

// // Endpoint protejat – doar adminul are acces
// func adminEndpoint(c *gin.Context) {
// 	claims, ok := validateToken(c)
// 	if !ok {
// 		return
// 	}
// 	if claims.Role != "admin" {
// 		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to access this resource"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{
// 		"message": "Welcome, admin!",
// 	})
// }

// func main() {
// 	// Deschide fișierul de log
// 	f, err := os.OpenFile("api.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		panic(err)
// 	}
// 	gin.DefaultWriter = f
// 	gin.DefaultErrorWriter = f

// 	r := gin.Default()

// 	// Endpoint pentru autentificare
// 	r.POST("/token", generateToken)

// 	// Endpointuri protejate
// 	r.GET("/user", userEndpoint)
// 	r.GET("/admin", adminEndpoint)

// 	r.Run(":8080")
// }

// package main

// import (
// 	"encoding/json"
// 	"io/ioutil"
// 	"net/http"
// 	"strings"
// 	"time"

// 	"github.com/dgrijalva/jwt-go"
// 	"github.com/gin-gonic/gin"
// 	"golang.org/x/crypto/bcrypt"
// )

// var jwtKey = []byte("my_secret_key")

// type User struct {
// 	Password string `json:"password"`
// 	Role     string `json:"role"`
// }

// type Claims struct {
// 	Username string `json:"username"`
// 	Role     string `json:"role"`
// 	jwt.StandardClaims
// }

// type Task struct {
// 	ID      int    `json:"id"`
// 	Content string `json:"content"`
// }

// var users map[string]User
// var tasks = make(map[string][]Task)

// func loadUsers() {
// 	data, err := ioutil.ReadFile("users.json")
// 	if err != nil {
// 		panic("Nu pot citi users.json: " + err.Error())
// 	}
// 	json.Unmarshal(data, &users)
// }

// func main() {
// 	loadUsers()

// 	r := gin.Default()

// 	r.Use(func(c *gin.Context) {
// 		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
// 		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
// 		if c.Request.Method == "OPTIONS" {
// 			c.AbortWithStatus(204)
// 			return
// 		}
// 		c.Next()
// 	})

// 	r.POST("/token", generateToken)
// 	r.GET("/protected", protectedEndpoint)
// 	r.GET("/tasks", getTasks)
// 	r.POST("/tasks", addTask)

// 	r.Run(":8080")
// }

// func generateToken(c *gin.Context) {
// 	var creds struct {
// 		Username string `json:"username"`
// 		Password string `json:"password"`
// 	}
// 	if err := c.BindJSON(&creds); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Date invalide"})
// 		return
// 	}

// 	user, ok := users[creds.Username]
// 	if !ok || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credentiale invalide"})
// 		return
// 	}

// 	expirationTime := time.Now().Add(time.Hour * 1)
// 	claims := &Claims{
// 		Username: creds.Username,
// 		Role:     user.Role,
// 		StandardClaims: jwt.StandardClaims{
// 			ExpiresAt: expirationTime.Unix(),
// 		},
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(jwtKey)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Eroare la generarea tokenului"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"token": tokenString})
// }

// func extractToken(c *gin.Context) string {
// 	authHeader := c.GetHeader("Authorization")
// 	if authHeader == "" {
// 		return ""
// 	}
// 	parts := strings.Split(authHeader, " ")
// 	if len(parts) == 2 && parts[0] == "Bearer" {
// 		return parts[1]
// 	}
// 	return ""
// }

// func getClaims(c *gin.Context) (*Claims, bool) {
// 	tokenString := extractToken(c)
// 	if tokenString == "" {
// 		return nil, false
// 	}

// 	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
// 		return jwtKey, nil
// 	})

// 	if err != nil || !token.Valid {
// 		return nil, false
// 	}

// 	claims, ok := token.Claims.(*Claims)
// 	if !ok || claims.ExpiresAt < time.Now().Unix() {
// 		return nil, false
// 	}

// 	return claims, true
// }

// func protectedEndpoint(c *gin.Context) {
// 	claims, ok := getClaims(c)
// 	if !ok {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalid sau expirat"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": "Acces permis pentru " + claims.Username})
// }

// func getTasks(c *gin.Context) {
// 	claims, ok := getClaims(c)
// 	if !ok {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token lipsă sau invalid"})
// 		return
// 	}

// 	userTasks := tasks[claims.Username]
// 	c.JSON(http.StatusOK, userTasks)
// }

// func addTask(c *gin.Context) {
// 	claims, ok := getClaims(c)
// 	if !ok {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token lipsă sau invalid"})
// 		return
// 	}

// 	var newTask Task
// 	if err := c.BindJSON(&newTask); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Task invalid"})
// 		return
// 	}

// 	userTasks := tasks[claims.Username]
// 	newTask.ID = len(userTasks) + 1
// 	tasks[claims.Username] = append(userTasks, newTask)

// 	c.JSON(http.StatusOK, gin.H{"message": "Task adăugat cu succes"})
// }
//varinat functionala pt json bcryptat

package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("my_secret_key")

type User struct {
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

type Task struct {
	ID      int    `json:"id"`
	Content string `json:"content"`
}

var users map[string]User
var tasks = make(map[string][]Task)

func loadUsers() {
	data, err := ioutil.ReadFile("users.json")
	if err != nil {
		panic("Nu pot citi users.json: " + err.Error())
	}
	json.Unmarshal(data, &users)
}

func main() {
	loadUsers()

	// Logare în fișier
	f, err := os.OpenFile("api.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	gin.DefaultWriter = f
	gin.DefaultErrorWriter = f

	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Public endpoint pentru autentificare (login)
	r.POST("/token", generateToken)

	// Endpointuri protejate - middleware verificare token
	auth := r.Group("/")
	auth.Use(authMiddleware)

	auth.GET("/protected", protectedEndpoint)
	auth.GET("/tasks", getTasks)
	auth.POST("/tasks", addTask)

	// Endpoint admin only
	auth.GET("/admin/users", adminOnly(getAllUsers))

	r.Run(":8080")
}

func generateToken(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Date invalide"})
		return
	}

	user, ok := users[creds.Username]
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credentiale invalide"})
		return
	}

	expirationTime := time.Now().Add(time.Hour * 1)
	claims := &Claims{
		Username: creds.Username,
		Role:     user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Eroare la generarea tokenului"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func extractToken(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

func getClaims(c *gin.Context) (*Claims, bool) {
	tokenString := extractToken(c)
	if tokenString == "" {
		return nil, false
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, false
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || claims.ExpiresAt < time.Now().Unix() {
		return nil, false
	}

	return claims, true
}

// Middleware pentru autentificare
func authMiddleware(c *gin.Context) {
	claims, ok := getClaims(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalid sau expirat"})
		c.Abort()
		return
	}
	c.Set("claims", claims) // salvează claims pentru handleri
	c.Next()
}

// Middleware pentru autorizare doar admin
func adminOnly(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		val, _ := c.Get("claims")
		claims := val.(*Claims)
		if claims.Role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Acces interzis: doar admin poate accesa"})
			return
		}
		handler(c)
	}
}

func protectedEndpoint(c *gin.Context) {
	val, _ := c.Get("claims")
	claims := val.(*Claims)
	c.JSON(http.StatusOK, gin.H{"message": "Acces permis pentru " + claims.Username})
}

func getTasks(c *gin.Context) {
	val, _ := c.Get("claims")
	claims := val.(*Claims)

	userTasks := tasks[claims.Username]
	c.JSON(http.StatusOK, userTasks)
}

func addTask(c *gin.Context) {
	val, _ := c.Get("claims")
	claims := val.(*Claims)

	var newTask Task
	if err := c.BindJSON(&newTask); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Task invalid"})
		return
	}

	userTasks := tasks[claims.Username]
	newTask.ID = len(userTasks) + 1
	tasks[claims.Username] = append(userTasks, newTask)

	c.JSON(http.StatusOK, gin.H{"message": "Task adăugat cu succes"})
}

// Endpoint accesibil doar adminilor – returnează DOAR lista de username-uri (fără parole)
func getAllUsers(c *gin.Context) {
	usernames := make([]string, 0, len(users))
	for username := range users {
		usernames = append(usernames, username)
	}
	c.JSON(http.StatusOK, usernames)
}
