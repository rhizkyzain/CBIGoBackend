package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// DataItem represents a user item
type DataItem struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// User represents a hardcoded user
type User struct {
	Username string
	Password string
	Role     string
}

// in-memory storage
var data []DataItem
var nextID int = 1

// hardcoded users
var users = []User{
	{"admin", "admin123", "admin"},
	{"user", "user123", "user"},
}

// simple in-memory session store: token -> role
var sessions = map[string]string{}

func main() {
	r := mux.NewRouter()

	// Auth routes
	r.HandleFunc("/login", login).Methods("POST")

	// Data routes with middleware
	r.Handle("/api/data", authMiddleware(http.HandlerFunc(getData), []string{"admin", "user"})).Methods("GET")
	r.Handle("/api/data", authMiddleware(http.HandlerFunc(createData), []string{"admin"})).Methods("POST")
	r.Handle("/api/data/{id}", authMiddleware(http.HandlerFunc(updateData), []string{"admin"})).Methods("PUT")
	r.Handle("/api/data/{id}", authMiddleware(http.HandlerFunc(deleteData), []string{"admin"})).Methods("DELETE")

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// ----------------- AUTH -----------------

// login handler
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
			// generate a random token
			token := generateToken()
			sessions[token] = u.Role

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"token": token, "role": u.Role})
			return
		}
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// generate a simple random token
func generateToken() string {
	rand.Seed(time.Now().UnixNano())
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// middleware to check token + role
func authMiddleware(next http.Handler, allowedRoles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization") // expect token in header
		role, ok := sessions[token]
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// check role
		for _, allowed := range allowedRoles {
			if role == allowed {
				next.ServeHTTP(w, r)
				return
			}
		}

		http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
	})
}

// ----------------- DATA -----------------

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
	item.ID = nextID
	nextID++
	data = append(data, item)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func updateData(w http.ResponseWriter, r *http.Request) {
	idStr := mux.Vars(r)["id"]
	id, _ := strconv.Atoi(idStr)

	var updated DataItem
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for i, item := range data {
		if item.ID == id {
			data[i].Name = updated.Name
			data[i].Email = updated.Email
			data[i].Role = updated.Role

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(data[i])
			return
		}
	}

	http.Error(w, "Item not found", http.StatusNotFound)
}

func deleteData(w http.ResponseWriter, r *http.Request) {
	idStr := mux.Vars(r)["id"]
	id, _ := strconv.Atoi(idStr)

	for i, item := range data {
		if item.ID == id {
			data = append(data[:i], data[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	http.Error(w, "Item not found", http.StatusNotFound)
}
