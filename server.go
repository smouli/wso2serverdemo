package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/minio/minio/pkg/auth"
)

func GetMinioToken(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println("GetMinioToken:ParseForm(): %v", err)
		http.Error(w, "Parse Error", 400)
	}
	//fmt.Println(r.Form)

	//Read the AccessToken from the request form
	token := r.FormValue("AccessToken")
	fmt.Printf("GetMinioToken: %s\n", token)
	//Validate the token just read
	ok, expTime, err := validateAccessToken(token)
	if !ok {
		fmt.Println("GetMinioToken:ValidateToken(): %v", err)
		http.Error(w, "Authentication Failed", 401)
	}

	// Read the credentials from the Minio json file
	cred, err := parseConfig(expTime)
	if err != nil {
		fmt.Println("GetMinioToken:ParseConfig(): %v", err)
	}

	//Marshal the credentials back to the client as JSON
	b, _ := json.Marshal(cred)
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func validateAccessToken(accessToken string) (bool, float64, error) {
	minioTokenUrl := "https://localhost:9443"
	resource := "/oauth2/introspect"
	u, err := url.ParseRequestURI(minioTokenUrl)
	if err != nil {
		log.Fatalln(err)
		return false, -1, err
	}
	u.Path = resource
	urlStr := u.String()
	data := url.Values{}
	data.Add("token", accessToken)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	r, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatalln(err)
		return false, -1, err
	}

	// fmt.Println("URL STR= ", urlStr)

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Authorization", "Basic YWRtaW46YWRtaW4=")

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	resp, err := client.Do(r)
	if err != nil {
		log.Fatalln(err)
		return false, 0, err
	}

	defer resp.Body.Close()
	// fmt.Printf("RESP BODY IS %s\n", resp.Body)
	// fmt.Printf("RESP headers are %s\n", resp.Header)
	// fmt.Println("RESP STATUS CODE is ", resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
		return false, -1, err
	}

	var validator map[string]interface{}
	json.Unmarshal(body, &validator)
	//fmt.Println(string(body))
	ok := validator["active"]
	timeValid := validator["exp"].(float64) - validator["iat"].(float64)
	return ok.(bool), timeValid, err

}

func parseConfig(timeValid float64) (*auth.Credentials, error) {
	content, _ := ioutil.ReadFile("/Users/sanatmouli/.minio/config.json")
	var result map[string]interface{}
	json.Unmarshal(content, &result)
	cred := result["credential"].(map[string]interface{})
	credmap := make(map[string]string, 2)
	for key, value := range cred {
		credmap[key] = value.(string)
		//fmt.Println(key, value.(string))
	}
	authcred := &auth.Credentials{
		AccessKey: credmap["accessKey"],
		SecretKey: credmap["secretKey"],
		ExpTime:   timeValid,
	}

	//fmt.Printf("accessKey: %s, secretKey: %s\n", accessKey, secretKey)
	//return accessKey, secretKey, nil
	return authcred, nil
}

func main() {
	http.HandleFunc("/getminiotoken", GetMinioToken)
	fmt.Println("Listening on port 4000")
	if err := http.ListenAndServe(":4000", nil); err != nil {
		log.Fatal(err)
	}
}
