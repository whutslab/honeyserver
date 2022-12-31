package main

import (
	_ "fmt"
	"honey_demo/httpserver"
	"honey_demo/models"
	"log"
	"sync"
	"time"
)

func main() {
	//规则测试
	var wg sync.WaitGroup
	nowDate := time.Now().Format("2006.01.02")
	nowindicesName := "logstash-kafka-" + nowDate
	//nowindicesName := "logstash-kafka-04.27"
	log.Println("index name => ", nowindicesName)
	wg.Add(3)
	go func() {
		models.InsertThread()
		wg.Done()
	}()
	//logstash-kafka-2021.03.11
	go func() {
		//detection.DetectTest("logstash-kafka-2021.05.02")
		//test := models.AggGetAllnodenames("logstash-kafka-2021.05.02")
		//models.QueryLogBytime(nowindicesName,"9927889b5e4a")
		//models.DeleteDataBytime("logstash-kafka-2021.03.24","2021-03-24T07:48:51.979")
		wg.Done()
	}()
	go func() {
		//httpserver.FingerFPinfo()
		//httpserver.HoneyNotice()
		httpserver.HoneyTrace()
		wg.Done()
	}()
	wg.Wait()
}
