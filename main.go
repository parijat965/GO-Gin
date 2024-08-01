package main

import (
    "time"
    "fmt"
    "log"
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/jinzhu/gorm"
    _ "github.com/jinzhu/gorm/dialects/postgres"
    "golang.org/x/crypto/bcrypt"
)

var db *gorm.DB
var err error

type Book struct {
    ID     uint   `json:"id"`
    Title  string `json:"title"`
    Author string `json:"author"`
}

type User struct {
    ID       uint   `json:"id"`
    Name     string `json:"name"`
    Email    string `json:"email"`
    Phone    string `json:"phone"`
    Password string `json:"password"`
}

func main() {
    dsn := "host=localhost user=postgres password=postgres dbname=go_db port=5432 sslmode=disable"
    db, err = gorm.Open("postgres", dsn)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()
    db.AutoMigrate(&Book{}, &User{})

    r := gin.Default()
    r.LoadHTMLGlob("templates/*")

    r.GET("/foo", func(c *gin.Context) {
        fmt.Println("The URL: ", c.Request.Host+c.Request.URL.Path)
    })

    r.GET("/", func(c *gin.Context) {
        userID, err := c.Cookie("user_id")
        if err != nil {
            c.Redirect(http.StatusSeeOther, "/login")
            return
        }
        loginTime, err := c.Cookie("login_time")
        if err != nil {
            c.Redirect(http.StatusSeeOther, "/login")
            return
        }
        loginTimestamp, err := time.Parse(time.RFC3339, loginTime)
        if err != nil || time.Since(loginTimestamp) > time.Hour {
            c.Redirect(http.StatusSeeOther, "/login")
            return
        }
        var user User
        if err := db.First(&user, userID).Error; err != nil {
            c.Redirect(http.StatusSeeOther, "/login")
            return
        }
        c.HTML(http.StatusOK, "index.html", gin.H{
            "Name":  user.Name,
            "Email": user.Email,
        })
    })

    r.GET("/login", func(c *gin.Context) {
        c.HTML(http.StatusOK, "login.html", nil)
    })
    
    r.POST("/login", loginUser)
    
    r.GET("/users", func(c *gin.Context) {
        c.HTML(http.StatusOK, "users.html", nil)
    })

    r.GET("/book_list", func(c *gin.Context) {
        c.HTML(http.StatusOK, "book_list.html", nil)
    })

    r.GET("/books", getBooks)
    r.POST("/books", createBook)
    r.PUT("/books/:id", updateBook)
    r.DELETE("/books/:id", deleteBook)

    r.GET("/api/users", getUsers)
    r.POST("/api/users", createUser)
    r.PUT("/api/users/:id", updateUser)
    r.DELETE("/api/users/:id", deleteUser)
    r.GET("/logout", logoutUser)

    r.Run(":8080")
}

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func loginUser(c *gin.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var foundUser User
    if err := db.Where("email = ?", user.Email).First(&foundUser).Error; err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }

    if !checkPasswordHash(user.Password, foundUser.Password) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }

    timestamp := time.Now().Format(time.RFC3339)
    c.SetCookie("user_id", fmt.Sprint(foundUser.ID), 3600, "/", "localhost", false, true)
    c.SetCookie("login_time", timestamp, 3600, "/", "localhost", false, true)
    c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func logoutUser(c *gin.Context) {
    c.SetCookie("user_id", "", -1, "/", "localhost", false, true)
    c.SetCookie("login_time", "", -1, "/", "localhost", false, true)
    c.Redirect(http.StatusSeeOther, "/login")
}


func getBooks(c *gin.Context) {
    var books []Book
    if err := db.Find(&books).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, books)
}

func createBook(c *gin.Context) {
    var book Book
    if err := c.ShouldBindJSON(&book); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    if err := db.Create(&book).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, book)
}

func updateBook(c *gin.Context) {
    id := c.Param("id")
    var book Book
    if err := db.Where("id = ?", id).First(&book).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Book not found"})
        return
    }
    if err := c.ShouldBindJSON(&book); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    db.Save(&book)
    c.JSON(http.StatusOK, book)
}

func deleteBook(c *gin.Context) {
    id := c.Param("id")
    if err := db.Where("id = ?", id).Delete(Book{}).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Book not found"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Book deleted"})
}

func getUsers(c *gin.Context) {
    var users []User
    if err := db.Find(&users).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, users)
}

func createUser(c *gin.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    hashedPassword, err := hashPassword(user.Password)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    user.Password = hashedPassword

    if err := db.Create(&user).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, user)
}

func updateUser(c *gin.Context) {
    id := c.Param("id")
    var user User
    if err := db.Where("id = ?", id).First(&user).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    db.Save(&user)
    c.JSON(http.StatusOK, user)
}

func deleteUser(c *gin.Context) {
    id := c.Param("id")
    if err := db.Where("id = ?", id).Delete(User{}).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}
