package main

import (
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/M0hammedImran/go-server-template/cmd/consumer/auth"
	"github.com/apache/pulsar-client-go/pulsar"
)

func main() {
	accessID := "5hwawt5am8x4r8hkpnrp"
	accessKey := "02cbc9bee37945c6adc5426bc534e91c"
	aesKey := accessKey[8:24]
	topic := fmt.Sprintf("persistent://%s/out/test/event", accessID)

	client, err := pulsar.NewClient(pulsar.ClientOptions{
		TLSAllowInsecureConnection: true,
		URL:                        "pulsar+ssl://mqe.tuyain.com:7285",
		Authentication:             auth.NewAuthProvider(accessID, accessKey),
	})
	if err != nil {
		panic(err)
	}
	var cfg = pulsar.ConsumerOptions{
		Topic:                       topic,
		SubscriptionName:            subscriptionName(topic),
		SubscriptionInitialPosition: pulsar.SubscriptionPositionEarliest,
		Type:                        pulsar.Failover,
	}
	consumer, err := client.Subscribe(cfg)
	if err != nil {
		panic(err)
	}
	var ctx = context.Background()
	fmt.Println("start consumer")
	go func() {
		for {
			fmt.Println("consuming...")

			msg, err := consumer.Receive(context.Background())
			if err != nil {
				fmt.Printf("consumer receive failed %+v ", err)
				continue
			}
			// let's decode the payload with AES
			m := map[string]interface{}{}
			err = json.Unmarshal(msg.Payload(), &m)
			if err != nil {
				fmt.Printf("json unmarshal failed err %+v\n", err)
				ctx.Done()
			}
			bs := m["data"].(string)
			de, err := base64.StdEncoding.DecodeString(string(bs))
			if err != nil {
				fmt.Printf("base64 decode failed err %+v\n", err)
				ctx.Done()
			}
			decode := EcbDecrypt(de, []byte(aesKey))
			var payload ConsumerPayload
			err = json.Unmarshal(decode, &payload)
			if err != nil {
				fmt.Printf("json unmarshal failed err %+v\n", err)
				ctx.Done()
			}

			logValue, _ := json.MarshalIndent(payload, "", "  ")
			fmt.Printf("decoded: %+v\n", string(logValue))

			retryCount := 3
			for j := 0; j < retryCount; j++ {
				err := consumer.Ack(msg)
				if err != nil {
					fmt.Printf("ack failed %+v", string(msg.Payload()))
					time.Sleep(time.Second)
				}
			}
		}
	}()

	<-ctx.Done()
}
func EcbDecrypt(data, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(data))
	size := block.BlockSize()
	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], data[bs:be])
	}
	return PKCS5Unpadding(decrypted)
}

func PKCS5Unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func subscriptionName(topic string) string {
	return getTenant(topic) + "-sub"
}

func getTenant(topic string) string {
	topic = strings.TrimPrefix(topic, "persistent://")
	end := strings.Index(topic, "/")
	return topic[:end]
}

type ConsumerPayload struct {
	BizCode   string  `json:"bizCode"`
	BizData   BizData `json:"bizData"`
	Timestamp int64   `json:"ts"`
}
type Properties struct {
	Code  string `json:"code"`
	DpID  int    `json:"dpId"`
	Time  int64  `json:"time"`
	Value any    `json:"value"`
}
type BizData struct {
	DevID      string       `json:"devId"`
	DataID     string       `json:"dataId"`
	ProductID  string       `json:"productId"`
	Properties []Properties `json:"properties"`
}
