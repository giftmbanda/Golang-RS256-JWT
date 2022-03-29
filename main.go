package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"time"
)

//Claims can have user id.. etc for Identification purpose
type Claims struct {
	Userid     string `json:"userid"`
	Authstatus string `json:"authstatus"`
	Role       string `json:"userrole"`
	Exp        int64  `json:"exp"`
	jwt.StandardClaims
}

var (
	privateKey []byte //openssl genrsa -out jwt-private.pem 3072
	publicKey  []byte //openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
	err        error
)

func init() {
	privateKey, err = ioutil.ReadFile("certs/jwt-private.pem") //used for generating the token
	errLog(err)
	publicKey, err = ioutil.ReadFile("certs/jwt-public.pem") //used for validating the token
	errLog(err)
}

func GenerateToken(userId string, authstatus string, userrole string) (interface{}, error) {
	privateRSA, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	errLog(err)

	claims := Claims{
		userId,
		authstatus,
		userrole,
		time.Now().Add(time.Second*900).UnixNano() / int64(time.Second),
		jwt.StandardClaims{},
	}

	signedString := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token, err := signedString.SignedString(privateRSA)
	return token, err
}

func ValidateToken(inToken interface{}) (interface{}, error) {
	publicRSA, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	errLog(err)

	token, err := jwt.Parse(inToken.(string), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicRSA, err
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil //fmt.Println("Valid token")
	} else {
		return nil, err //fmt.Println("Invalid token")
	}
}

func main() {
	token, err := GenerateToken("giftmbanda@gmail.com", "true", "admin") //generate token
	errLog(err)

	fmt.Println(token)

	claims, err := ValidateToken(token) // validate token
	errLog(err)

	claimValue := claims.(jwt.MapClaims) 
	// extract token claims
	fmt.Println(claimValue["userid"], claimValue["authstatus"],claimValue["userrole"],claimValue["exp"],)
}

func errLog(err error) {
	if err != nil {
		log.Fatal("Error:", err.Error())
	}
}
