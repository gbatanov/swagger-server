package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	curl "github.com/andelf/go-curl"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/matishsiao/goInfo"
)

const Version = "0.7.24"

var Os string = ""

// ApiKey for authorization with ApiKey
const ApiKey = "sdjhaZsfhabvbAasNmdjhDgkhadAkghad2kj"

// login/password for authorization with token
const Login = "login"
const Password = "12345"

type Claims struct {
	Login string `json:"login"`
	jwt.RegisteredClaims
}

// Create a struct to read the login and password from the request body
type Credentials struct {
	Password string `json:"password"`
	Login    string `json:"login"`
}

var jwtKey = []byte(ApiKey)

var baseDir string = ""

type MyResponse struct {
	head string
	body string
}

func main() {
	gi, _ := goInfo.GetInfo()
	Os = gi.GoOS

	// директория запуска программы (не по go run !!!!)
	var rootDir, _ = filepath.Abs(filepath.Dir(os.Args[0]))
	fmt.Println(rootDir)
	baseDir = filepath.Join(rootDir, "..")
	fmt.Println(baseDir)

	fmt.Println("\nHTTP Server start")
	sigs := make(chan os.Signal, 1)
	// признак прерывания по Ctrl+C
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// Создаем переменную для сервера
	var srv http.Server

	// Завершение по сигналам прерывания
	go func() {
		sig := <-sigs
		fmt.Println("\nSignal:", sig)
		srv.Shutdown(context.Background())
	}()
	// Создаем маршрутизатор
	mux := http.NewServeMux()
	// Наполняем его обрабатываемыми маршрутами
	register_routing(mux)
	if Os == "darwin" {
		srv.Addr = "192.168.88.70:2121"
	} else {
		srv.Addr = "192.168.88.240:2121"
	}
	srv.Handler = mux
	srv.ListenAndServe()

	fmt.Println("\nHTTP Server finished")

}

func register_routing(mux *http.ServeMux) {

	mux.HandleFunc("/token", get_token)
	mux.HandleFunc("/test_post/", test_post_handler)
	mux.HandleFunc("/test/", test_handler)
	mux.HandleFunc("/metrics", metrics)
	mux.HandleFunc("/", default_handler)
}

// Тут я переопределяю поведение при ошибке 404
func NotFound(w http.ResponseWriter, r *http.Request) {

	host := r.Host
	var my_resp MyResponse
	var protocol string
	_, proto_redirect := r.Header["X-Forwarded-Proto"]
	if proto_redirect && r.Header["X-Forwarded-Proto"][0] == "https" {
		protocol = "https://"
	} else {
		protocol = "http://"
	}

	baseUrl, _ := url.Parse(protocol + host)
	my_resp.body = "<div>Wrong URL</div>"
	my_resp.body += fmt.Sprintf("<a href=\"%s\">Home page</a>", baseUrl.String())

	my_resp.head = "<title>Page not found</title>"
	send_answer(w, my_resp, 404, string("text/html"))
}

// Функция генерит токен по логину паролю
func get_token(w http.ResponseWriter, r *http.Request) {
	var my_resp MyResponse
	var creds Credentials
	code := http.StatusOK
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		my_resp.body = "Ошибка авторизации. Некорректная структура запроса."
		code = http.StatusBadRequest
	} else if creds.Password != Password || creds.Login != Login {

		my_resp.body = "Ошибка авторизации. Некорректная пара логин/пароль."
		code = http.StatusUnauthorized
	} else {
		// Declare the expiration time of the token
		// here, we have kept it as 30 minutes
		expirationTime := time.Now().Add(30 * time.Minute)
		// Create the JWT claims, which includes the username and expiry time
		claims := &Claims{
			Login: creds.Login,
			RegisteredClaims: jwt.RegisteredClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		// Declare the token with the algorithm used for signing, and the claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Create the JWT string
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			// If there is an error in creating the JWT return an internal server error
			my_resp.body = "Ошибка авторизации. Не удалось создать токен."
			code = http.StatusInternalServerError
		} else {
			fmt.Println(tokenString)
			my_resp.body = tokenString
		}
	}
	contentType := "text/plain"
	my_resp.head = ""
	send_answer(w, my_resp, code, contentType)
}

// Проверка авторизации
func check_authorize(w http.ResponseWriter, r *http.Request) bool {
	var my_resp MyResponse
	auth := r.Header.Get("X-API_KEY")
	if len(auth) > 0 {
		if auth == ApiKey {
			return true
		}
		w.Header().Add("WWW_Authenticate", "ApiKey")
	} else {
		auth = r.Header.Get("Authorization")
		if len(auth) > 0 {
			tknStr := strings.Split(auth, " ")[1]
			//			fmt.Println(tknStr)
			claims := &Claims{}
			tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})
			if err == nil && tkn.Valid {
				return true
			}
		}
		w.Header().Add("WWW_Authenticate", "Bearer")
	}

	my_resp.body = "Ошибка авторизации"
	code := 401
	contentType := "text/plain"

	my_resp.head = ""
	send_answer(w, my_resp, code, contentType)
	return false
}

// Обработчик POST-запроса с дополнительными параметрами в URL
func test_post_handler(w http.ResponseWriter, r *http.Request) {

	if !check_authorize(w, r) {
		return
	}

	var my_resp MyResponse
	var code int = 200
	contentType := "text/plain"

	fmt.Println("\nContent-Type:")
	fmt.Println(r.Header.Get("Content-Type"))
	fmt.Println("\nHeaders:")
	show_headers(r)
	fmt.Println("\nQuery Params:")
	m, _ := get_params(r)
	fmt.Println(m)
	fmt.Println("\nBody:")
	body, _ := ioutil.ReadAll(r.Body)
	fmt.Println(string(body))

	my_resp.body, _ = curl_query()

	my_resp.head = ""
	send_answer(w, my_resp, code, contentType)

}

// Обработчик GET-запроса с параметрами в URL
func test_handler(w http.ResponseWriter, r *http.Request) {
	if !check_authorize(w, r) {
		return
	}
	var my_resp MyResponse

	var code int = 200
	contentType := "text/plain"

	//	m, _ := get_params(r)
	//	fmt.Println(m)

	my_resp.body, _ = curl_query()

	my_resp.head = ""
	send_answer(w, my_resp, code, contentType)

}

// Получение ответа из статического файла
func metrics(w http.ResponseWriter, r *http.Request) {
	//	if !check_authorize(w, r) {
	//		return
	//	}
	var my_resp MyResponse

	var code int = 200
	contentType := "text/html"

	dat, err := os.ReadFile(baseDir + "/static_pages/metrics")
	if err != nil {
		dat = make([]byte, 1)
		dat[0] = 0
		code = 500
	}

	my_resp.body = string(dat)

	my_resp.head = ""
	contentType = "text/html"
	send_answer(w, my_resp, code, contentType)

}

func default_handler(w http.ResponseWriter, r *http.Request) {

	var my_resp MyResponse

	var code int = 200
	contentType := "text/html"

	url := r.URL.Path
	//	fmt.Println(url)
	if Os == "darwin" {
		if len(r.URL.Path) == 0 || r.URL.Path == "/" {
			url = "/dist/darwin/index.html"
		} else if r.URL.Path == "/v1" {
			url = "/conf/darwin/v1.json"
		}

	} else {
		if len(r.URL.Path) == 0 || r.URL.Path == "/" {
			url = "/dist/index.html"
		} else if r.URL.Path == "/v1" {
			url = "/conf/v1.json"
		}
	}
	dat, err := os.ReadFile(baseDir + url)
	if err != nil {
		dat = make([]byte, 1)
		dat[0] = 0
		code = 500
	}

	my_resp.body = string(dat)

	my_resp.head = ""

	if url == "index.html" {
		contentType = "text/html"
	} else if url == "test1.yml" {
		contentType = "application/yaml"
	} else if strings.Contains(url, ".css") {
		contentType = "text/css"
	} else if strings.Contains(url, ".js") {
		contentType = "text/javascript"
	}

	send_answer(w, my_resp, code, contentType)

}

// Локальные функции
// Отправка ответа клиенту
func send_answer(w http.ResponseWriter, my_resp MyResponse, code int, contentType string) {

	var result string = my_resp.body

	send_headers(w, code, contentType)
	w.Write([]byte(result))
}

// Извлечение параметров запроса из Uri
func get_params(req *http.Request) (url.Values, error) {
	uri := req.RequestURI
	u, err := url.Parse(uri)
	if err != nil {
		return url.Values{}, err
	}
	m, _ := url.ParseQuery(u.RawQuery)
	return m, nil
}

// Отправка заголовка клиенту
func send_headers(w http.ResponseWriter, code int, contentType string) {
	/*
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, PATCH, OPTIONS")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type, api_key, Authorization")
	*/
	w.Header().Add("Content-Type", contentType)
	w.WriteHeader(code)
}

// Callback - функция CURL запроса
func write_data(ptr []byte, userdata interface{}) bool {
	ch, ok := userdata.(chan string)
	if ok {
		ch <- string(ptr)
		return true // ok
	} else {
		println("ERROR!")
		return false
	}
}

// Запрос метрик через CURL запрос
func curl_query() (string, error) {
	easy := curl.EasyInit()
	defer easy.Cleanup()

	if Os == "darwin" {
		easy.Setopt(curl.OPT_URL, "http://192.168.88.76:8092/metrics")
	} else {
		easy.Setopt(curl.OPT_URL, "http://localhost:8092/metrics")
	}
	easy.Setopt(curl.OPT_WRITEFUNCTION, write_data)
	ch := make(chan string, 100)
	var data string
	go func(ch chan string) {
		for {
			data = <-ch
		}
	}(ch)

	easy.Setopt(curl.OPT_WRITEDATA, ch)

	err := easy.Perform()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return "", err
	}
	return data, err
}

func show_headers(req *http.Request) {

	// Этот обработчик делает что-то более сложное,
	// читая все заголовки HTTP-запроса и вставляя их в тело ответа.
	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Printf("%v: %v\n", name, h)
		}
	}
}
