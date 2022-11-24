package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/charge"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name     string `json: "Name"`
	Email    string `json: "email"`
	Password string `json: "password"`
	Admin    bool   `json: "Admin"`
}

type Product struct {
	Id       int    `json: "Id"`
	Name     string `json: "Name"`
	Quantity int    `json: "Quantity"`
	Price    int    `json: "Price"`
}

type ChargeJSON struct {
	Amount       int64  `json:"amount"`
	ReceiptEmail string `json:"receiptEmail"`
}

var Database *sql.DB
var newProduct Product
var newUser User
var productsArr = []Product{}
var sampleSecretKey = []byte(os.Getenv("SECRET"))

func main() {
	conn, err := sql.Open("pgx", "host=localhost dbname=tskDatabase user=tskUsr password=7531 port=5432")
	Database = conn
	CheckError(err)
	err = conn.Ping()

	if err != nil {
		log.Fatal("Connection Error", err)
	}

	fmt.Println("Connected to postgres")

	router := gin.Default()

	router.GET("/products", listProductsHandler)
	router.POST("/products", verifyJWT(addProductHandler))
	router.PUT("/products/:id", verifyJWT(updateProductHandler))
	router.DELETE("/products/:id", verifyJWT(deleteProductHandler))
	router.POST("/api/charges/:id", HandlePayment)
	router.POST("/users/signup", signUpHandler)
	router.POST("/users/login", loginHandler)

	router.Run("localhost:3000")

	defer conn.Close()

}

func generateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString(sampleSecretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func verifyJWT(next func(gCon *gin.Context)) gin.HandlerFunc {
	return gin.HandlerFunc(func(gCon *gin.Context) {
		if gCon.Request.Header["Token"] != nil {
			token, err := jwt.Parse(gCon.Request.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				_, ok := token.Method.(*jwt.SigningMethodHMAC)
				if !ok {
					gCon.Writer.WriteHeader(http.StatusUnauthorized)
					_, err := gCon.Writer.Write([]byte("You're Unauthorized!"))
					if err != nil {
						print(err.Error())
						return nil, err
					}
				}
				return sampleSecretKey, nil
			})
			if err != nil {
				print(err.Error())
				gCon.Writer.WriteHeader(http.StatusUnauthorized)
				_, err2 := gCon.Writer.Write([]byte("You're Unauthorized due to error parsing the JWT"))
				if err2 != nil {
					return
				}
				return
			}
			if token.Valid {
				next(gCon)
			} else {
				gCon.Writer.WriteHeader(http.StatusUnauthorized)
				_, err := gCon.Writer.Write([]byte("You're Unauthorized due to invalid token"))
				if err != nil {
					print(err.Error())
					return
				}
				return
			}
		} else {
			gCon.Writer.WriteHeader(http.StatusUnauthorized)
			_, err := gCon.Writer.Write([]byte("You're Unauthorized due to No token in the header"))
			if err != nil {
				return
			}
		}

	})
}

func getProductsFromDb() {

	rows, err := Database.Query(`SELECT "id", "Name", "quantity", "price" FROM "products"`)
	CheckError(err)
	for rows.Next() {
		var Name string
		var quantity, price, id int
		err := rows.Scan(&id, &Name, &quantity, &price)

		if err != nil {
			log.Println("err while scanning for row")
		}
		fetchedProducts := Product{id, Name, quantity, price}
		productsArr = append(productsArr, fetchedProducts)

	}
	defer rows.Close()
}

func listProductsHandler(context *gin.Context) {

	getProductsFromDb()
	context.IndentedJSON(http.StatusCreated, productsArr)
	productsArr = nil
}

func signUpHandler(context *gin.Context) {

	if err := context.BindJSON(&newUser); err != nil {
		return
	}
	hashed, _ := HashPassword(newUser.Password)
	_, e := Database.Exec(`INSERT INTO users("Name", "email", "password", "isAdmin") VALUES($1, $2, $3, $4)`, newUser.Name, newUser.Email, hashed, newUser.Admin)
	CheckError(e)

}

func addProductHandler(context *gin.Context) {
	if err := context.BindJSON(&newProduct); err != nil {
		return
	}
	_, e := Database.Exec(`INSERT INTO products("Name", "quantity", "price") VALUES($1, $2, $3)`, newProduct.Name, newProduct.Quantity, newProduct.Price)
	CheckError(e)

}

func updateProductHandler(context *gin.Context) {
	if err := context.BindJSON(&newProduct); err != nil {
		return
	}
	idP := context.Param("id")
	updateStmt := `update "products" set "Name"=$1, "quantity"=$2, "price"=$3 where "id"=$4`
	_, e := Database.Exec(updateStmt, newProduct.Name, newProduct.Quantity, newProduct.Price, idP)
	CheckError(e)

}

func deleteProductHandler(context *gin.Context) {
	if err := context.BindJSON(&newProduct); err != nil {
		return
	}

	idPd := context.Param("id")
	deleteStmt := `delete from "products" where "id"=$1`
	_, e := Database.Exec(deleteStmt, idPd)
	CheckError(e)
}

func loginHandler(context *gin.Context) {
	var userResult = []User{}
	if err := context.BindJSON(&newUser); err != nil {
		return
	}
	rows, e := Database.Query(`SELECT "email", "password" FROM "users"`)
	CheckError(e)

	for rows.Next() {
		var Email, Password, Name string
		var Admin bool
		err := rows.Scan(&Email, &Password)

		if err != nil {
			log.Println("err while scanning for row")
		}
		user := User{Name, Email, Password, Admin}
		if user.Email == newUser.Email {
			userResult = append(userResult, user)
			break
		}
	}
	if len(userResult) > 0 && CheckPasswordHash(newUser.Password, userResult[0].Password) {
		tokenStr, err := generateJWT()
		if err != nil {
			context.Writer.WriteHeader(500)
			return
		}
		context.IndentedJSON(200, tokenStr)
		return
	}
	context.Writer.WriteHeader(404)
	defer rows.Close()

}

func HashPassword(password string) (string, error) {
	bytes, error := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), error
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func HandlePayment(context *gin.Context) {
	var json ChargeJSON
	context.BindJSON(&json)

	stripe.Key = os.Getenv("SECRETKEY")
	idPs := context.Param("id")
	getProductsFromDb()
	intVar, eRror := strconv.Atoi(idPs)
	if eRror != nil {
		fmt.Println(eRror)
	}
	for i, value := range productsArr {
		if int64(json.Amount) < int64(value.Price) && intVar == value.Id {

			context.String(http.StatusOK, "Amount is less than the price")

			return
		}
		if intVar == value.Id && value.Quantity == 0 {
			context.String(http.StatusOK, "Product out of Stock")
			return
		}
		if i == len(productsArr)-1 && intVar != value.Id {
			context.String(http.StatusOK, "Invalid Product Id")
			return
		}
		if intVar == value.Id {
			quantity := value.Quantity - 1
			updateStmt := `update "products" set "Name"=$1, "quantity"=$2, "price"=$3 where "id"=$4`
			_, e := Database.Exec(updateStmt, value.Name, quantity, value.Price, idPs)
			CheckError(e)
		}

	}

	productsArr = nil

	_, err := charge.New(&stripe.ChargeParams{
		Amount:       stripe.Int64(json.Amount * 100),
		Currency:     stripe.String(string(stripe.CurrencyAUD)),
		Source:       &stripe.SourceParams{Token: stripe.String("tok_visa")},
		ReceiptEmail: stripe.String(json.ReceiptEmail)})
	if err != nil {

		context.String(http.StatusBadRequest, "Request failed")
		return
	}

	context.String(http.StatusCreated, "Successfully charged")
}

func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
