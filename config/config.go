package config

import (
	"bytes"
	"io"

	"gopkg.in/yaml.v2"

	"github.com/pelletier/go-toml"
)

type ConfigFile struct {
	ConfigFileName string
	ConfigType     string
	ParseResult    map[string]interface{}
	ConfigErr      error
}

//
func (c *ConfigFile) ReadConfig(cfgio io.Reader) {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(cfgio); err != nil && err != io.EOF {
		c.ConfigErr = err
		return
	}

	switch c.ConfigType {
	case "toml", "tml":
		tree, err := toml.LoadReader(buf)
		if err != nil {
			c.ConfigErr = err
			return
		}
		c.ParseResult = tree.ToMap()
	case "yaml", "yml":
		if err := yaml.Unmarshal(buf.Bytes(), &c.ParseResult); err != nil {
			c.ConfigErr = err
			return
		}
	}
}
