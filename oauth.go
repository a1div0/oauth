// klenov
// 2019.10.27

package oauth

import (
    "fmt"
    "net/http"
    "strings"
    "crypto/aes"
    "crypto/rand"
    "time"
    "encoding/binary"
    "encoding/hex"
    "io"
    "bytes"
)

// Авторизационные данные пользователя
type UserData struct {
    UserId int64
    Name string
    Email string
    ExtId string
    OAuthServiceName string
}

// Интерфейс сервиса авторизации
type OAuthorizator interface {
    ServiceName() (string)
    LoginURL(verification_code_callback_url string, state string) (string)
    OnRecieveVerificationCode(code string, u *UserData) (error)
}

type DB_UserRegistrator interface {
    UserRegistration(u *UserData) error
}

type OAuthServices map[string]OAuthorizator

// Коллекция сервисов авторизации
type OAuthCollect struct {
    verification_code_callback_url string
    done_auth_url string
    only_https bool
    //db *DB_UserRegistrator
    oauth_services OAuthServices
    server_psw []byte // 32
    server_xor []byte // 16
    server_rnd string // 32
}

// Содержимое CSRF-токена
type TokenData struct {
    UserId int64 // 8 bytes
    Dt int64 // 8 bytes
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Раздел экспорта

func (s *OAuthCollect) Init(VerificationCodeCallbackURL string, DoneAuthUrl string, OnlyHttps bool) (error) {
    s.verification_code_callback_url = VerificationCodeCallbackURL
    s.done_auth_url     = DoneAuthUrl
    s.only_https        = OnlyHttps
    s.oauth_services    = make(OAuthServices)
    s.server_psw        = make([]byte, 32)
    s.server_xor        = make([]byte, 16)

    if _, err := io.ReadFull(rand.Reader, s.server_psw); err != nil {
        return err
    }
    if _, err := io.ReadFull(rand.Reader, s.server_xor); err != nil {
        return err
    }

    var rnd32 []byte
    rnd32 = make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, rnd32); err != nil {
        return err
    }

    s.server_rnd = fmt.Sprintf("%x", rnd32)
    return nil
}

func (s *OAuthCollect) AddService(srv OAuthorizator) (error) {
    s.oauth_services[srv.ServiceName()] = srv
    return nil
}

// Получить фрагмент модуля "settings.js"
func (s *OAuthCollect) GetSettingsJS() (string) {
    result := ""
    for srv_name, srv := range s.oauth_services {
        state := srv.ServiceName() + "," + s.server_rnd
        login_url_raw := srv.LoginURL(s.verification_code_callback_url, state)
        login_url := strings.ReplaceAll(login_url_raw, "%", "%%")
        result += fmt.Sprintf("const OAUTH_%s_URL = \"%s\";\n", strings.ToUpper(srv_name), login_url)
    }

    return result
}

// При получении кода авторизации
func (s *OAuthCollect) OnRecieveVerificationCode(w http.ResponseWriter, r *http.Request, db DB_UserRegistrator) (error) {

    // Определяем сервис
    state := strings.Join(r.Form["state"], "");
    if (len(state) > 128 + 1 + 64) {
        // 128 - максимальная длина имени сервиса
        // 1 - запятая
        // 64 - длина ключа
        return fmt.Errorf("Unknown state, code 1")
    }
    state_items := strings.Split(state, ",")
    if (len(state_items) != 2) {
        return fmt.Errorf("Unknown state, code 2")
    }
    if (state_items[1] != s.server_rnd) { // если пройдёт это условие, то скорее всего это мы всё-таки подавали запрос
        return fmt.Errorf("Unknown state, code 3")
    }

    service_name := state_items[0]
    service, service_exist := s.oauth_services[service_name]
    if (!service_exist) { // если пройдёт это условие, значит service_name "чист"
        return fmt.Errorf("Unknown service OAuth")
    }

    code := strings.Join(r.Form["code"], "")
    if (!s.code_is_valid(service, code)) {
        return fmt.Errorf("Verification code is not valid!")
    }

    var u UserData
    err := service.OnRecieveVerificationCode(code, &u)
    if (err != nil) {
        return err
    }

    u.OAuthServiceName = service_name

    // теперь запись в базу
    err = db.UserRegistration(&u)
    if (err != nil) {
        return err
    }

    // token
    csrf_token, err := s.csrf_token(&u)
    if (err != nil) {
        return err
    }

    // добавить куки, http.SetCookie(w, &cookie_name) // не получилось использовать - пропускает русские символы
    s.set_cookie(w, "user_name", u.Name)
    s.set_cookie(w, "user_mail", u.Email)
    s.set_cookie(w, "user_oauth_srv", u.OAuthServiceName)
    s.set_cookie(w, "csrf_token", csrf_token)

    // и редирект на главную страницу
    http.Redirect(w, r, s.done_auth_url, http.StatusMovedPermanently)

    return nil
}

func (s *OAuthCollect) CheckAuth(w http.ResponseWriter, r *http.Request) (int64, error) {
    // сравниваем csrf-токен в куках, параметрах и заголовке авторизации
    // если что-то не то -- переходим на страницу логина соответствующего сервиса
    // есть идея номер сервиса упаковать в верхний байт user_id - нет, просто перебрасывать на главную страницу
    // расшифровываем и возвращаем user_id
    // возвращаем ошибку - если при проверке что-то не работает
    // ноль - если доступ запрещён, или в любом случае возвращать 403?
    return 0, nil
}

// Получить данные из CSRF-токена
func (s *OAuthCollect) csrf_token_to_user_data(csrf_token string, token_data *TokenData) (error) {

    aes_bytes, err := hex.DecodeString(csrf_token)
    if err != nil {
        return err
    }

    c, err := aes.NewCipher(s.server_psw)
    if err != nil {
        return err
    }

    xor_bytes := make([]byte, 16)
    c.Decrypt(xor_bytes, aes_bytes)

    raw_bytes := make([]byte, 16)
    for i := 0; i < 16; i++ {
        raw_bytes[i] = xor_bytes[i] ^ s.server_xor[i]
    }

    buf := bytes.NewBuffer(raw_bytes)
    err = binary.Read(buf, binary.LittleEndian, token_data)
    if err != nil {
        return err
    }

    return nil
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Внутренняя кухня

// Преобразовать данные авторизации UserData в CSRF-токен
func (s *OAuthCollect) csrf_token(u *UserData) (string, error) {

    var buf bytes.Buffer

    token_data := TokenData{
        UserId : u.UserId,
        Dt : time.Now().Unix(),
    }
    err := binary.Write(&buf, binary.LittleEndian, token_data)
    if err != nil {
        return "", err
    }
    raw_bytes := buf.Bytes()

    // вместо соли применить xor со случайным массивом байт, массив хранить вместе с паролем
    xor_bytes := make([]byte, 16)
    for i := 0; i < 16; i++ {
        xor_bytes[i] = raw_bytes[i] ^ s.server_xor[i]
    }

    // потом шифруем в AES
    c, err := aes.NewCipher(s.server_psw)
    if err != nil {
        return "", err
    }
    aes_bytes := make([]byte, 16)
    c.Encrypt(aes_bytes, xor_bytes)

    return fmt.Sprintf("%x", aes_bytes), nil
}

func (s *OAuthCollect) set_cookie(w http.ResponseWriter, name string, value string) {
    secure := ""
    if (s.only_https) {
        secure = "Secure;"
    }
    cookie_str := fmt.Sprintf("%s=%s;path=/;Max-Age=8035200;%s", name, value, secure)
    w.Header().Add("Set-Cookie", cookie_str)
}

func (s *OAuthCollect) code_is_valid(service OAuthorizator, code string) (bool) {

    LimitVerificationCodeSize := 1024
    if (len(code) > LimitVerificationCodeSize) {
        return false
    }

    if (strings.Contains(code, "&")) {
        return false
    }

    return true
}
