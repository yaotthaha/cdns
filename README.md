# cdns

```cdns``` 是一个使用 Golang 编写的，高度自定义的 DNS 服务器

---

### 如何构建
```
make build
```
```
Release 如果想减小二进制可执行文件体积，去除不需用到的插件，可以编辑：
    matchPlugin/plugin.go 在不需要的匹配插件前加 ”//“
    matchPlugin/plugin.go 在不需要的执行插件前加 ”//“
    例如：
    _ "path/to/plugin-need"
    // _ "path/to/plugin-unneed"
```

### 文档
[https://cdns-wiki.yaott.eu.org](https://cdns-wiki.yaott.eu.org)

## License

---

cdns is licensed under the GPL-3.0 License.