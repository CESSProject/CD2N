package client

import (
	"context"

	"github.com/go-redis/redis/v8"
)

const (
	//the cnd node provides user data to the provider
	CHANNEL_PROVIDE = "provide_task"
	//the cnd node requests the provider to retrieve data
	CHANNEL_RETRIEVE = "retrieve_task"

	CHANNEL_DATA_OFFLOAD = "data_offload_task"

	CHANNEL_IPFS_RETRIEVE = "ipfs_retrieve_task"
)

func NewRedisClient(addr, username, password string) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Username: username,
		Password: password,
		DB:       0,
	})
	return client
}

func SubscribeMessage(cli *redis.Client, ctx context.Context, receiver chan<- *redis.Message, channel ...string) {
	sub := cli.Subscribe(ctx, channel...)
	defer sub.Close()
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			receiver <- msg
		}
	}
}
