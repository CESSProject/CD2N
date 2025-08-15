package response

const (
	CODE_DL_SUCCESS = 10200
	CODE_DL_ERROR   = 10210
)

const (
	CODE_UP_SUCCESS      = 10100
	CODE_UP_ERROR        = 10110
	CODE_UP_NOT_AUTH     = 10111
	CODE_UP_INVALID_NAME = 10112
	CODE_UP_INSUFF_SPACE = 10113
	CODE_UP_FILE_EXIST   = 10114
)

type Response struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

func NewResp(code int, msg string, data any) Response {
	return Response{
		Code: code,
		Msg:  msg,
		Data: data,
	}
}
