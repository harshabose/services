package https

import (
	"time"
)

type Config struct {
	Addr         string        `json:"addr"`
	Port         uint16        `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	KeepHosting  bool          `json:"keep_hosting"`

	CertPath string `json:"-"`
	KeyFile  string `json:"-"`
}

func DefaultConfig() Config {
	c := Config{}
	c.SetDefaults()

	return c
}

func (c *Config) SetDefaults() {
	if c.Addr == "" {
		c.Addr = "0.0.0.0"
	}

	if c.Port == 0 {
		c.Port = 8080
	}

	if c.ReadTimeout == 0 {
		c.ReadTimeout = 30 * time.Second
	}

	if c.WriteTimeout == 0 {
		c.WriteTimeout = 30 * time.Second
	}
}
