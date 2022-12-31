package detection

import (
	"fmt"
	"github.com/markuskont/go-sigma-rule-engine/pkg/sigma/v2"
	"github.com/spf13/viper"
	"honey_demo/models"
	"log"
	"strings"
	"time"
)

type parseTestCase struct {
	Rule     string
	Pos, Neg []string
}
type logList struct {
	total int64
	//logs []hostLog
	logs []map[string]interface{}
}

type hostLog struct {
	Timestamp              time.Time `json:"@timestamp"`
	Comm                   string    `json:"comm"`
	Data_type              string    `json:"data_type"`
	Exe                    string    `json:"exe"`
	Exe_md5                string    `json:"exe_md5"`
	Run_path               string    `json:"run_path"`
	Hostname_str           string    `json:"hostname_str"`
	Nodename               string    `json:"nodename"`
	Ld_preload             string    `json:"ld_preload"`
	Local_ip_str           string    `json:"local_ip_str"`
	Dip                    string    `json:"dip"`
	Dport                  string    `json:"dport"`
	Sip                    string    `json:"sip"`
	Sport                  string    `json:"sport"`
	Socket_process_pid     string    `json:"socket_process_pid"`
	Socket_process_exe     string    `json:"socket_process_exe"`
	Socket_process_exe_md5 string    `json:"socket_process_exe_md5"`
	Pid                    string    `json:"pid"`
	Pid_tree               string    `json:"pid_tree"`
	Ppid                   string    `json:"ppid"`
	Sa_family              string    `json:"sa_family"`
	Ssh_connection         string    `json:"ssh_connection"`
	Stdin_connect          string    `json:"stdin_connect"`
	Stdout_connect         string    `json:"stdout_connect"`
	Tgid                   string    `json:"tgid"`
	Time                   string    `json:"time"`
	Tty_name               string    `json:"tty_name"`
	Uid                    string    `json:"uid"`
	User                   string    `json:"user"`
}

// DynamicMap is a reference type for implementing sigma Matcher
type DynamicMap map[string]interface{}

// Keywords implements Keyworder
func (s DynamicMap) Keywords() ([]string, bool) {
	return []string{s["argv"].(string)}, true
	//return nil, false
}

// Select implements Selector
func (s DynamicMap) Select(key string) (interface{}, bool) {
	return GetField(key, s)
}

func GetField(key string, data map[string]interface{}) (interface{}, bool) {
	if data == nil {
		return nil, false
	}
	bits := strings.SplitN(key, ".", 2)
	if len(bits) == 0 {
		return nil, false
	}
	if val, ok := data[bits[0]]; ok {
		switch res := val.(type) {
		case map[string]interface{}:
			return GetField(bits[1], res)
		default:
			return val, ok
		}
	}
	return nil, false
}

func DetectTest(index string) {
	nodenames := models.AggGetAllnodenames(index)
	for {
		if models.IndexExists(index) {
			var lastTime string
			log.Printf("elasticsearch index {%s} exist!\n", index)
			viper.SetConfigFile("./config.toml")
			err := viper.ReadInConfig()
			if err != nil {
				log.Fatal("read config failed: %v", err)
			}
			ruleset, err := sigma.NewRuleset(sigma.Config{
				Directory: viper.GetStringSlice("dir.directory"),
			})
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Found %d files, %d ok, %d failed, %d unsupported\n",
				ruleset.Total, ruleset.Ok, ruleset.Failed, ruleset.Unsupported)
			log.Println("Search nodenames queue:", nodenames)
			for _, nodename := range nodenames {
				var obj DynamicMap
				var es_data models.LogList
				var total_matched = int64(0)
				es_data, lastTime, _ = models.ScrollQueryLogBytime(index, nodename)
				for _, single_data := range es_data.Logs {
					var tag []string
					var description string
					var honey_source interface{}
					for _, rule := range ruleset.Rules {
						obj = single_data
						tag = []string{"Unknown"}
						description = ""
						honey_source = obj["hostid"]
						//honey_source = "ef21ee7e-0373-49a6-b1e2-a4ffd5e52cbc"
						if rule.Match(obj) {
							// handle rule match here
							total_matched = total_matched + 1
							//fmt.Println(rule.Rule.Tags)
							tag = rule.Rule.Tags
							description = rule.Rule.Description
							fmt.Println(rule.Rule.Description)
							break
						}
					}
					models.InsertEs(tag, description, obj, time.Now(), honey_source)
				}
				log.Printf("Taged logs num is %d,Unknown logs num is %d\n", total_matched, es_data.Total-total_matched)
			}
			//models.DeleteDataBytime(index, lastTime)
			fmt.Println("lastTime : ", lastTime)
		}
		time.Sleep(time.Second * 60)
	}
	//for _, c := range parseTestCases {
	//	for _, c := range c.Neg{
	//		if err := json.Unmarshal([]byte(c), &obj); err != nil {
	//			fmt.Println("failed")
	//		}
	//		for _, rule := range ruleset.Rules {
	//			if rule.Match(obj) {
	//				// handle rule match here
	//				fmt.Println(" Matched ")
	//				fmt.Println(rule.Rule.Tags)
	//			}else {
	//				fmt.Println(" Not Matched ",obj)
	//			}
	//		}
	//	}
	//}
}
