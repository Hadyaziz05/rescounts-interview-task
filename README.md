# rescounts-interview-task

## About
A simple e-commerce Go web application that handles authentication for users as well as creation, updating, listing, and deleting products.

## Setup
- Git clone this repository
- Install pgAdmin4
- `cd` into the directory then run `go run main.go`

### Authentication
A user can login with their credentials using
```javascript
POST /users/login
{
  "Email": "XXXXX",
  "Password: "YYYYY",
}
```
A user can sign up with their credentials using
```javascript
POST /users/signup
{
  "Name": "AAAAAA",
  "Email": "XXXXX",
  "Password: "YYYYY",
  "Admin": false,
}
```
<b>Users passwords are hashed before being inserted into the database</b>

### Viewing Products
All users are allowed to see the list of products stored in the database and to buy via Stripe
```javascript
List
GET /products
```
```javascript
Buy 
POST/api/charges/{id}
{
  "amount": 200,
  "receiptEmail": "XXXXX" 
}
```

### Managing Products
Admin users are allowed to add, remove, edit products existing in the database using the following endpoints
```javascript
Create
POST /products
{
    "Name": "pen",
    "Quantity": 20,
    "Price": 200
}
```
```javascript
Edit
PUT /products/{id}
{
    "Name": "pen",
    "Quantity": 20,
    "Price": 200
}
```
```javascript
Delete
DELETE /products/{id}
```
<b>These endpoints are protected via JWT middleware.</b>
