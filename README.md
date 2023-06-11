# cdns

A highly customizable dns server.

---

### How to build
```
make build
```
```
Release 默认包含所有插件，如果想减小二进制可执行文件体积，去除不需用到的插件，可以编辑：
    matchPlugin/plugin.go 在不需要的匹配插件前加 ”//“
    matchPlugin/plugin.go 在不需要的执行插件前加 ”//“
    例如：
    _ "path/to/plugin-need"
    // _ "path/to/plugin-unneed"

Release contains all plugins by default, if you want to reduce the size of the binary executable and remove unneeded plugins, you can edit:
    matchPlugin/plugin.go Add "//" in front of unneeded match plugin
    matchPlugin/plugin.go Add "//" in front of unneeded exec plugin
    Example:
    _ "path/to/plugin-need"
    // _ "path/to/plugin-unneed"
```

### Example Config
```
中文用户可以阅览示例配置文件，有详细配置信息：config_example_cn.yaml
please see config_example_cn.yaml
```

## License

---

cdns is licensed under the GPL-3.0 License.