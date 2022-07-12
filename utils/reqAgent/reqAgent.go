package reqagent

import (
	"github.com/wadeking98/gohammer/config"
	"github.com/wadeking98/gohammer/utils"
)

type ReqAgent interface {
	Send([]string, *utils.Counter, *config.Args) (bool, error)
}
