package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type DataItem struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type Product struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	SKU      string  `json:"sku"`
	Quantity int     `json:"quantity"`
	Price    float64 `json:"price"`
}

type User struct {
	Username string
	Password string
	Role     string
}

var users = []User{
	{"admin", "admin123", "admin"},
	{"user", "user123", "user"},
}

var sessions = map[string]string{}

var data []DataItem
var nextDataID = 1

var products []Product
var nextProductID = 1

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/login", login).Methods("POST")

	r.Handle("/api/data", authMiddleware(http.HandlerFunc(getData), []string{"admin", "user"})).Methods("GET")
	r.Handle("/api/data", authMiddleware(http.HandlerFunc(createData), []string{"admin"})).Methods("POST")
	r.Handle("/api/data/{id}", authMiddleware(http.HandlerFunc(updateData), []string{"admin"})).Methods("PUT")
	r.Handle("/api/data/{id}", authMiddleware(http.HandlerFunc(deleteData), []string{"admin"})).Methods("DELETE")

	r.Handle("/api/products", authMiddleware(http.HandlerFunc(getProducts), []string{"admin", "user"})).Methods("GET")
	r.Handle("/api/products", authMiddleware(http.HandlerFunc(createProduct), []string{"admin"})).Methods("POST")
	r.Handle("/api/products/{id}", authMiddleware(http.HandlerFunc(updateProduct), []string{"admin"})).Methods("PUT")
	r.Handle("/api/products/{id}", authMiddleware(http.HandlerFunc(deleteProduct), []string{"admin"})).Methods("DELETE")

	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(r)

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, u := range users {
		if u.Username == creds.Username && u.Password == creds.Password {
			token := generateToken()
			sessions[token] = u.Role
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"token": token, "role": u.Role})
			return
		}
	}
	http.Error(w, `{"error":"Invalid Credentials"}`, http.StatusUnauthorized)
}

func generateToken() string {
	rand.Seed(time.Now().UnixNano())
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func authMiddleware(next http.Handler, allowedRoles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		role, ok := sessions[token]
		if !ok {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		for _, allowed := range allowedRoles {
			if role == allowed {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
	})
}

// ---------------- User CRUD ----------------
func getData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func createData(w http.ResponseWriter, r *http.Request) {
	var item DataItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	item.ID = nextDataID
	nextDataID++
	data = append(data, item)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func updateData(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	var updated DataItem
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for i, item := range data {
		if item.ID == id {
			data[i] = updated
			data[i].ID = id
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(data[i])
			return
		}
	}
	http.Error(w, "Item not found", http.StatusNotFound)
}

func deleteData(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	for i, item := range data {
		if item.ID == id {
			data = append(data[:i], data[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.Error(w, "Item not found", http.StatusNotFound)
}

// ---------------- Product CRUD ----------------
func getProducts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}

func createProduct(w http.ResponseWriter, r *http.Request) {
	var item Product
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	item.ID = nextProductID
	nextProductID++
	products = append(products, item)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func updateProduct(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	var updated Product
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for i, item := range products {
		if item.ID == id {
			products[i] = updated
			products[i].ID = id
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(products[i])
			return
		}
	}
	http.Error(w, "Product not found", http.StatusNotFound)
}

func deleteProduct(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	for i, item := range products {
		if item.ID == id {
			products = append(products[:i], products[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.Error(w, "Product not found", http.StatusNotFound)
}
