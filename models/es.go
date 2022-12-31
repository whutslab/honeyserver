package models

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/olivere/elastic/v7"
	"github.com/spf13/viper"
	"io"
	"log"
	"strings"
	"time"
)

type LogList struct {
	Total int64
	//logs []hostLog
	Logs []map[string]interface{}
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

type ESSave struct {
	DataTag     []string               `json:"datatag"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Time        time.Time              `json:"time"`
	HoneySource interface{}            `json:"honey_source"`
}

type FpInfo struct {
	Hostid string `json:"hostid"`
}

var Client *elastic.Client
var esChan chan ESSave
var nowindicesName string

func init() {
	nowDate := time.Now().Local().Format("2006_01")
	nowindicesName = "tag_logs" + nowDate
	viper.SetConfigFile("./config.toml")
	var err error
	err = viper.ReadInConfig()
	if err != nil {
		log.Fatal("config.toml Read error:", err.Error())
	}
	Client, err = elastic.NewClient(elastic.SetURL(viper.GetStringSlice("elasticsearch.url")...))
	if err != nil {
		log.Fatal("Elastic NewClient error:", err.Error())
	}
	indexNameList, err := Client.IndexNames()
	if err != nil {
		log.Fatal("Client IndexNames error:", err.Error())
		return
	}
	if !inArray(indexNameList, nowindicesName, false) {
		newIndex(nowindicesName)
	}
	esChan = make(chan ESSave, 4096)
}

// InsertEs 将数据插入es
func InsertEs(dataTag []string, description string, data map[string]interface{}, nowtime time.Time, honey_source interface{}) {
	esChan <- ESSave{dataTag, description, data, nowtime, honey_source}
}

func DeleteDataBytime(index string, lastTime string) {
	if IndexExists(index) {
		timeRange := elastic.NewRangeQuery("@timestamp").Lte(lastTime)
		_, err := Client.DeleteByQuery().
			Index(index).
			Query(timeRange).
			Pretty(true).
			Do(context.Background())
		if err != nil {
			log.Fatal(err.Error())
			return
		}
		log.Printf("LastQuery time is {%s}\n", lastTime)
		//log.Printf("Deleted %d datas", res.Total)
	} else {
		log.Printf("Now index:%s doesn't exit,remove failed!", index)
	}
}

func AggGetAllnodenames(index string) []string {
	var nodenamelist []string
	if IndexExists(index) {
		resp, err := Client.Search().
			Index(index).
			Query(elastic.NewMatchAllQuery()).
			Aggregation("aggnodename", elastic.NewTermsAggregation().Field("nodename.keyword")).
			Pretty(true).
			Do(context.Background())
		if err == nil {
			agg, found := resp.Aggregations.Terms("aggnodename")
			if !found {
				log.Println("Agg result data not found")
			}
			for _, bucket := range agg.Buckets {
				bucketValue := bucket.Key.(string)
				nodenamelist = append(nodenamelist, bucketValue)
			}
		} else {
			log.Printf("Agg query failed with %v\n", err)
		}
	} else {
		log.Printf("Now index:%s doesn't exit", index)
	}
	return nodenamelist
}

func InsertThread() {
	log.Println("start insert thread")
	var data ESSave
	for {
		data = <-esChan
		_, err := Client.Index().
			Index(nowindicesName).
			BodyJson(data).
			Do(context.Background())
		if err != nil {
			log.Printf("insert es index{%s}  error: %v\n", nowindicesName, err)
		}
	}
}

func InsertSingle(data interface{}, indexName string) {
	_, err := Client.Index().
		Index(indexName).
		BodyJson(data).
		Do(context.Background())
	if err != nil {
		log.Printf("insert es index{%s}  error: %v\n", indexName, err)
	} else {
		log.Println("Insert success")
	}
}

func IndexExists(index string) bool {
	exists, err := Client.IndexExists(index).Do(context.Background())
	if err != nil {
		log.Printf("%v\n", err)
	}
	return exists
}

func newIndex(name string) {
	log.Println("init indice", name)
	_, err := Client.CreateIndex(name).Do(context.Background())
	if err != nil {
		log.Fatal("Create index failed ", err.Error())
	}
}

func ScrollQueryLogBytime(index string, nodename string) (LogList, string, error) {
	var res LogList
	termQuery := elastic.NewMatchQuery("nodename", nodename)
	nowTime := time.Now().Format("2006-01-02T15:04:05.000")
	timeRangeQuery := elastic.NewRangeQuery("@timestamp").Lte(nowTime)
	boolFilter := elastic.NewBoolQuery().Must(termQuery).Filter(timeRangeQuery)
	svc := Client.Scroll(index).Query(boolFilter).Size(100).TrackTotalHits(true)
	for {
		searchResult, err := svc.Do(context.TODO())
		if err == io.EOF {
			log.Printf("Nodename:%s hits %d\n", nodename, searchResult.TotalHits())
			break
		}
		for _, hit := range searchResult.Hits.Hits {
			var item map[string]interface{}
			err := json.Unmarshal(hit.Source, &item)
			if err != nil {
				log.Println(err.Error())
				continue
			}
			res.Logs = append(res.Logs, item)
			res.Total = res.Total + 1
		}
	}
	//log.Printf("Nodename %s Deal with %d docs", nodename, res.Total)
	return res, nowTime, nil
}

func QueryLogBytime(index string, nodename string) (LogList, string, error) {
	var res LogList
	termQuery := elastic.NewMatchQuery("nodename", nodename)
	nowTime := time.Now().Format("2006-01-02T15:04:05.000")
	timeRangeQuery := elastic.NewRangeQuery("@timestamp").Lte(nowTime)
	boolFilter := elastic.NewBoolQuery().Must(termQuery).Filter(timeRangeQuery)
	searchResult, err := Client.Search(index).Query(boolFilter).Sort("@timestamp", false).Do(context.Background())
	if err != nil {
		return res, nowTime, err
	}
	log.Printf("The Query Hits %d", searchResult.Hits.TotalHits.Value)
	if searchResult.Hits.TotalHits.Value != 0 {
		for _, hit := range searchResult.Hits.Hits {
			//var item hostLog
			var item map[string]interface{}
			err := json.Unmarshal(hit.Source, &item)
			if err != nil {
				log.Println(err.Error())
				continue
			}
			res.Logs = append(res.Logs, item)
			res.Total = res.Total + 1
		}
	} else {
		res.Total = 0
	}
	log.Printf("Fetch data %d docs", res.Total)
	return res, nowTime, err
}

func inArray(list []string, value string, like bool) bool {
	for _, v := range list {
		if like {
			if strings.Contains(value, v) {
				return true
			}
		} else {
			if value == v {
				return true
			}
		}
	}
	return false
}

func ScrollQueryLog(index string, nodename string) (LogList, string, error) {
	var res LogList
	termQuery := elastic.NewMatchQuery("nodename", nodename)
	nowTime := time.Now().Format("2006-01-02T15:04:05.000")
	timeRangeQuery := elastic.NewRangeQuery("@timestamp").Lte(nowTime)
	boolFilter := elastic.NewBoolQuery().Must(termQuery).Filter(timeRangeQuery)
	searchResult1, err := Client.Scroll(index).Query(boolFilter).Scroll("5m").Size(100).Do(context.Background())
	fmt.Printf("首次游标分页查询 num : %d", searchResult1.Hits.TotalHits.Value)
	if err != nil {
		log.Fatalf("elastic首次查询游标失败:%v", err)
	}
	for _, hit := range searchResult1.Hits.Hits {
		var item map[string]interface{}
		err := json.Unmarshal(hit.Source, &item)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		res.Logs = append(res.Logs, item)
		res.Total = res.Total + 1
	}
	scrollID := searchResult1.ScrollId
	startIndex := len(searchResult1.Hits.Hits)
	for {
		// 根据ScrollID检索下一个批次的结果，注意：初始搜索请求和每个后续滚动请求返回一个新的_scroll_id，只有最近的_scroll_id才能被使用。
		searchResult, err := Client.Scroll(index).ScrollId(scrollID).Do(context.TODO())
		if err != nil && !strings.Contains(err.Error(), "EOF") {
			log.Printf("elastic游标查询数据失败:%v", err)
		}

		//判断游标ID
		if searchResult.ScrollId == "" {
			log.Printf("elastic首次查询游标为空:%v", index)
		}
		scrollID = searchResult.ScrollId

		//判断是否查询到文档
		if searchResult.Hits == nil {
			log.Print("游标查询到的文档为nil")
			return res, nowTime, err
		}
		log.Printf("ES查询到的命中数据条数TotalHits:%v", searchResult.Hits.TotalHits)

		//遍历查询到的文档组合服务操作数据对象切片
		for _, hit := range searchResult.Hits.Hits {
			item := make(map[string]interface{})
			err := json.Unmarshal(hit.Source, &item)
			if err != nil {
				log.Fatal(err.Error())
				continue
			}
			res.Logs = append(res.Logs, item)
			res.Total = res.Total + 1
		}

		//判断是否分页查询完毕
		if int64(startIndex+len(searchResult.Hits.Hits)) >= searchResult.Hits.TotalHits.Value {
			break
		}
		//更新下次分页查询起始位置
		startIndex += len(searchResult.Hits.Hits)
		log.Printf("索引%v数据总量:%v,已经获取:%v", index, searchResult.Hits.TotalHits, startIndex)
	}
	log.Printf("数据总量:%d\n", res.Total)
	_, err = Client.ClearScroll().ScrollId(searchResult1.ScrollId).Do(context.TODO())
	if err != nil {
		log.Printf("清除游标失败,error info:%v", err)
		return res, nowTime, err
	}
	return res, nowTime, err
}
