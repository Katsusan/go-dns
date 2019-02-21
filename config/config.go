package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/pelletier/go-toml"
)

//Tiny describes the struct for gDNS config
type Tiny struct {
	ConfigFileName string
	ConfigType     string
	ParseResult    map[string]interface{}
	ConfigErr      error
}

//NewConfig will initialize the config
func NewConfig(cfgfile string) *Tiny {
	t := &Tiny{
		ConfigFileName: cfgfile,
		ConfigType:     "",
		ParseResult:    make(map[string]interface{}),
		ConfigErr:      nil,
	}

	//open config file failed
	if _, err := os.Open(cfgfile); err != nil {
		t.ConfigErr = err
		return t
	}

	//determine the config type by suffix of file name, toml or yaml
	for _, cfgtype := range []string{"toml", "tml", "yaml", "yml"} {
		if strings.HasSuffix(cfgfile, cfgtype) {
			t.ConfigType = cfgtype
			break
		}
	}

	if t.ConfigType == "" {
		t.ConfigErr = errors.New("not supported config file")
	}

	return t
}

//ReadConfig will read from config file and write it into ParseResult
func (t *Tiny) ReadConfig(cfgio io.Reader) {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(cfgio); err != nil && err != io.EOF {
		t.ConfigErr = err
		return
	}

	switch t.ConfigType {
	case "toml", "tml":
		tree, err := toml.LoadReader(buf)
		if err != nil {
			t.ConfigErr = err
			return
		}
		t.ParseResult = tree.ToMap()
	case "yaml", "yml":
		if err := yaml.Unmarshal(buf.Bytes(), &t.ParseResult); err != nil {
			t.ConfigErr = err
			return
		}
	default:
		t.ConfigErr = errors.New("not supported config format")
		return
	}
}
