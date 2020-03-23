package oauth

import (
    "testing"
    //"net/http"
    "net/http/httptest"
    "strings"
    "fmt"
)

type OAuthTest struct {
    Client_id string
    Client_psw string
    State string
}

func (s *OAuthTest) ServiceName() (string) {
    return "test"
}

func (s *OAuthTest) LoginURL(verification_code_callback_url string, state string) (string) {
    s.State = state
    return "https://oauth.test.ru?client_id=" + s.Client_id + "&state=" + state
}

func (s *OAuthTest) OnRecieveVerificationCode(code string, u *UserData) (error) {
    u.Name = "Это пробный акк"
    u.Email = "test@test.com"
    u.ExtId = "123"
    return nil
}

type DataBaseTest struct {

}

func (db *DataBaseTest) UserRegistration(u *UserData) error {
    u.UserId = 345
    return nil
}

func TestAddService(t *testing.T) {
    var collect OAuthCollect
    collect.Init("http://example.com/oauth_callback", "/", false)

    srv := OAuthTest {
        Client_id: "cid123",
        Client_psw: "psw123",
    }

    err:= collect.AddService(&srv)
    if (err != nil) {
        t.Error(err)
    }

    js := collect.GetSettingsJS()
    js = strings.Replace(js, "\n", "", -1)
    chk_js := fmt.Sprintf("const OAUTH_TEST_URL = \"https://oauth.test.ru?client_id=cid123&state=%s\";", srv.State)
    if (js != chk_js) {
        t.Error("_settings.js должен содержать строку:\n", chk_js, "но содержит:\n", js)
    }
}

func TestOnRcvVerificationCode(t *testing.T) {
    var collect OAuthCollect
    done_auth_url := "/"
    collect.Init("http://example.com/oauth_callback", done_auth_url, false)

    srv := OAuthTest {
        Client_id: "cid123",
        Client_psw: "psw123",
    }
    collect.AddService(&srv)
    collect.GetSettingsJS()
    request_url := "https://goods.com/cmd/oauth_verification_code?code=111222&state="+srv.State

    r := httptest.NewRequest("GET", request_url, nil)
    r.ParseForm()
	w := httptest.NewRecorder()

    var  db DataBaseTest
    err := collect.OnRecieveVerificationCode(w, r, &db)
    if (err != nil) {
        t.Error(err)
        return
    }

    resp := w.Result()
    if (resp.StatusCode != 301) {
        t.Error("Код ответа = ", resp.StatusCode, ", а должен быть = 301\n")
    }

    h := w.Header()
    Location := h.Get("Location")
    if (Location != done_auth_url) {
        t.Error("Location = '", Location, "', а должно быть = '",done_auth_url,"'\n")
    }

    var cookies_map map[string]string
    cookies_map = make(map[string]string)
    cookies := h["Set-Cookie"]
    for _, cookie := range cookies {
        if (strings.HasPrefix(cookie, "user_name")) {
            cookies_map["user_name"] = cookie
        }
        if (strings.HasPrefix(cookie, "user_mail")) {
            cookies_map["user_mail"] = cookie
        }
        if (strings.HasPrefix(cookie, "user_oauth_srv")) {
            cookies_map["user_oauth_srv"] = cookie
        }
        if (strings.HasPrefix(cookie, "csrf_token")) {
            cookies_map["csrf_token"] = cookie
        }
    }

    CheckCookie(t, cookies_map, "user_name", "user_name=Это пробный акк;path=/;Max-Age=8035200;")
    CheckCookie(t, cookies_map, "user_mail", "user_mail=test@test.com;path=/;Max-Age=8035200;")
    CheckCookie(t, cookies_map, "user_oauth_srv", "user_oauth_srv=test;path=/;Max-Age=8035200;")

    csrf_cookie, csrf_token_exist := cookies_map["csrf_token"]

    if csrf_token_exist {
    }else{
        t.Error("Отсутствует cookie[csrf_token]\n")
        return
    }

    csrf_cookie_half := strings.Split(csrf_cookie, ";")[0]
    csrf_token := strings.Split(csrf_cookie_half, "=")[1]

    var td TokenData
    err = collect.csrf_token_to_user_data(csrf_token, &td)
    if (err != nil) {
        t.Error(err)
        return
    }else if (td.UserId != 345) {
        t.Error("TokenData.UserId = ", td.UserId, ", а должно быть = 345\n")
    }

    //dt := time.Unix(td.Dt, 0)
}

func CheckCookie(t *testing.T, cookies_map map[string]string, cookie_name string, valid_value string) {
    var msg string
    if rcv_val, val_exist := cookies_map[cookie_name]; val_exist {
        if (rcv_val != valid_value) {
            msg = fmt.Sprintf("cookie[%s] = %s, а должно быть = '%s'\n", cookie_name, rcv_val, valid_value)
            t.Error(msg)
        }
    }else{
        msg = fmt.Sprintf("Отсутствует cookie[%s]\n", cookie_name)
        t.Error(msg)
    }
}
