package main

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func generateToken(c *gin.Context) {
	claims := &Claims{
		Username: "user",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
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

func protectedEndpoint(c *gin.Context) {
	tokenString := extractToken(c)
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or wrong format token"})
		return
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || claims.ExpiresAt < time.Now().Unix() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired or is invalid"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "This is a protected resource!"})
}

func main() {
	// Deschide sau creează fișierul de log
	f, err := os.OpenFile("api.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	// Gin va scrie logurile în fișier
	gin.DefaultWriter = f
	gin.DefaultErrorWriter = f

	r := gin.Default()

	r.POST("/token", generateToken)
	r.GET("/protected", protectedEndpoint)

	r.Run(":8080")
}

/*HOW to run
Terminal 1
trebuie descracte dependintele
1 go get -u github.com/gin-gonic/gin
2 go get -u github.com/dgrijalva/jwt-go
3 go run main.go
output:
[GIN-debug] Listening and serving HTTP on :8080

Terminal 2
1 pentru a obtine tockenul :curl -X POST http://localhost:8080/token
2 daca incerc sa accesez endppointul fara a introduce tockenul curl -X GET http://localhost:8080/protected
{ "message": Missing tocken"}
3 curl -X GET http://localhost:8080/protected -H "Authorization: Bearer my_token"
{ "message": "This is a protected resource!" }

*/
