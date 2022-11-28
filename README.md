# Tapo SmartPlug API Client


## About

Implementation of Tapo API using a
[reverse engineering blog post](https://k4czp3r.xyz/reverse-engineering/tp-link/tapo/2020/10/15/reverse-engineering-tp-link-tapo.html).

## Library

```go
    import (
		"github.com/richardjennings/tapo/pkg/tapo"
    )
    var t *tapo.Tapo
    var r map[string]interface{}
    var err error
    t, err = tapo.NewTapo(ip, username, password)
	r, err = t.TurnOn()
	r, err = t.TurnOff()
	r, err = t.GetEnergyUsgae()
	r, err = t.DeviceInfo()
```

## CLI

`go install github.com/richardjennings/tapo`

### Usage
```
tapo <ip-address> <username> <password> [on, off, energy-usage, device-info]
```

For example:

```
tapo 192.168.0.101 email@address thepassword energy-usage
{
  "error_code": 0,
  "result": {
    "current_power": 0,
    ...
    "month_energy": 10000,
    "month_runtime": 10000,
    "today_energy": 400,
    "today_runtime": 300
  }
}
```


