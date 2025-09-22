package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CESSProject/go-sdk/libs/tsproto"
)

type AlertHandler interface {
	Alert(severity, message string)
}

type AlertRegister interface {
	Register(AlertHandler)
}

type LarkAlarm struct {
	AlertName  string `json:"alertname"`
	Region     string `json:"region"`
	Serverity  string `json:"severity"`
	Message    string `json:"message"`
	Startat    string `json:"startat"`
	Endat      string `json:"endat"`
	Url        string `json:"url"`
	Maintainer string `json:"maintainer"`
	Hook       string `json:"-"`
}

type DefaultAlarm struct{}

func (da DefaultAlarm) Alert(severity, message string) {}

func NewLarkAlertHandler(conf config.Config) LarkAlarm {
	return LarkAlarm{
		AlertName:  conf.AlertName,
		Region:     conf.Region,
		Hook:       conf.AlertHook,
		Maintainer: conf.Maintainer,
		Url:        conf.Url,
	}
}

func (la LarkAlarm) Alert(severity, message string) {
	if la.Hook == "" {
		return
	}
	la.Message = message
	la.Serverity = severity
	la.Startat = fmt.Sprint(time.Now().UnixMilli())
	jbytes, err := json.Marshal(la)
	if err != nil {
		return
	}
	tsproto.SendHttpRequest(http.MethodPost, la.Hook,
		map[string]string{"Content-Type": "application/json"}, bytes.NewBuffer(jbytes))
}

func AlarmInjection(alert AlertHandler, registers ...AlertRegister) {
	for _, register := range registers {
		register.Register(alert)
	}
}
