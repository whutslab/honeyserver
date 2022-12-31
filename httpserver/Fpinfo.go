package httpserver

import (
	"encoding/json"
	"github.com/spf13/viper"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type FpInfo struct {
	Id                  string `bson:"id"`
	CreationDate        string `bson:"creationDate"`
	TimeZone            string `bson:"timezone"`
	HardwareConcurrency string `bson:"hardwareConcurrency"`
	UserAgentHttp       string `bson:"userAgentHttp"`
	LanguageHttp        string `bson:"languageHttp"`
	ResolutionJS        string `bson:"resolutionJS"`
	PlatformJS          string `bson:"platformJS"`
	PluginsJS           string `bson:"pluginsJS"`
	RendererWebGLJS     string `bson:"rendererWebGLJS"`
	CanvasJSHashed      string `bson:"canvasJSHashed"`
	CookiesJS           string `bson:"cookiesJS"`
	DNTJS               string `bson:"dntJS"`
	Hostid              string `bson:"hostid"`
	Result              string `bson:"result"`
}

type FpRes struct {
	fpinfo FpInfo
	result string
	hostid string
}

var db *mgo.Database
var FPtoES FpRes

func init() {
	viper.SetConfigFile("./config.toml")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("config.toml Read error:", err.Error())
	}
	localurl := viper.GetString("mongo.url")
	session, err := mgo.Dial("mongodb://" + localurl)
	if err != nil {
		log.Fatal(err)
	}
	session.SetMode(mgo.Monotonic, true)
	db = session.DB("agent")
}

func FpAllInfo(rawdata []byte) (result FpInfo) {
	json.Unmarshal(rawdata, &result)
	return result
}

func SetReturn(result string, fpdata FpInfo) {
	FPtoES.result = result
	FPtoES.fpinfo = fpdata
	FPtoES.hostid = fpdata.Hostid
}

func FingerFPinfo() {
	log.Println("Start listening fingerprint")
	http.HandleFunc("/honeypot/fingerprint", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Server", "golang server")
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("OK"))
		err := request.ParseForm()
		if err != nil {
			log.Fatal("parse form error ", err)
		}
		defer request.Body.Close()
		con, _ := ioutil.ReadAll(request.Body)
		fpdata := FpAllInfo(con)
		log.Println("get fingerprint successfully")
		c := db.C("fpinfo")
		total_doc, _ := c.Find(bson.M{}).Count()
		c.Upsert(bson.M{"counter": total_doc + 1}, bson.M{"$set": &fpdata})
		arg1 := "./FPStalker-modify/main_modify.py"
		cmd := exec.Command("python3", arg1, "automl", "myexpname", "6")
		output, _ := cmd.CombinedOutput()
		result := string(output)
		c = db.C("FpLibrary")
		if strings.Contains(result, "no match") {
			total_doc, _ = c.Find(bson.M{}).Count()
			c.Upsert(bson.M{"counter": total_doc + 1}, bson.M{"$set": &fpdata})
			result = "no"
		} else if strings.Contains(result, "exactly matched") {
			sid := strings.Split(result, ":")[1]
			sid = strings.Replace(sid, " ", "", -1)
			sid = strings.Replace(sid, "\n", "", -1)
			result = "exactlyyes"
		} else if strings.Contains(result, "ml nearest") {
			sid := strings.Split(result, ":")[1]
			sid = strings.Replace(sid, " ", "", -1)
			sid = strings.Replace(sid, "\n", "", -1)
			total_doc, _ = c.Find(bson.M{}).Count()
			c.Upsert(bson.M{"counter": total_doc + 1}, bson.M{"$set": &fpdata})
			result = "nearyes"
		} else {
			result = "error"
		}
		log.Println("fingerprint result is: ", result)
		fpdata.Result = result
		c = db.C("FPresult")
		c.Upsert(bson.M{"creationTime": fpdata.CreationDate}, bson.M{"$set": &fpdata})
	})
	err := http.ListenAndServe(":8900", nil)
	if err != nil {
		log.Println("ListenAndServe error:", err.Error())
	}
}

func HoneyHandler(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case "POST":
		writer.Header().Set("Server", "golang server")
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("OK"))
		err := request.ParseForm()
		if err != nil {
			log.Fatal("parse form error ", err)
		}
		defer request.Body.Close()
		con, _ := ioutil.ReadAll(request.Body)
		fpdata := FpAllInfo(con)
		log.Println("get fingerprint successfully")
		c := db.C("fpinfo")
		total_doc, _ := c.Find(bson.M{}).Count()
		c.Upsert(bson.M{"counter": total_doc + 1}, bson.M{"$set": &fpdata})
		arg1 := "./FPStalker-modify/main_modify.py"
		cmd := exec.Command("python3", arg1, "automl", "myexpname", "6")
		output, _ := cmd.CombinedOutput()
		result := string(output)
		c = db.C("FpLibrary")
		if strings.Contains(result, "no match") {
			total_doc, _ = c.Find(bson.M{}).Count()
			c.Upsert(bson.M{"counter": total_doc + 1}, bson.M{"$set": &fpdata})
			result = "no"
		} else if strings.Contains(result, "exactly matched") {
			sid := strings.Split(result, ":")[1]
			sid = strings.Replace(sid, " ", "", -1)
			sid = strings.Replace(sid, "\n", "", -1)
			result = "exactlyyes"
		} else if strings.Contains(result, "ml nearest") {
			sid := strings.Split(result, ":")[1]
			sid = strings.Replace(sid, " ", "", -1)
			sid = strings.Replace(sid, "\n", "", -1)
			total_doc, _ = c.Find(bson.M{}).Count()
			c.Upsert(bson.M{"counter": total_doc + 1}, bson.M{"$set": &fpdata})
			result = "nearyes"
		} else {
			result = "error"
		}
		log.Println("fingerprint result is: ", result)
		fpdata.Result = result
		c = db.C("FPresult")
		c.Upsert(bson.M{"creationTime": fpdata.CreationDate}, bson.M{"$set": &fpdata})
	case "GET":
		vars := request.URL.Query()
		honeyid := vars.Get("id")
		callerip := ClientIP(request)
		var resultdata map[string]string
		resultdata = map[string]string{
			"honeyid":  honeyid,
			"callerip": callerip,
			"opentime": time.Now().Format("2006-01-02T15:04:05"),
		}
		c := db.C("honeytrace")
		c.Upsert(bson.M{"opentime": string(time.Now().Unix())}, bson.M{"$set": &resultdata})
		log.Printf("File %s was opened at %s\n", resultdata["honeyid"], resultdata["opentime"])
	}
}

func HoneyTrace() {
	server := &http.Server{
		Addr:         "192.168.137.65:8900",
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/honeypot/honeyfile/", HoneyHandler)
	server.Handler = mux
	log.Println("Start listening HoneyTrace")
	server.ListenAndServe()
}

func ClientIP(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	ip := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
	if ip != "" {
		return ip
	}
	ip = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	if ip != "" {
		return ip
	}
	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return ip
	}
	return ""
}
