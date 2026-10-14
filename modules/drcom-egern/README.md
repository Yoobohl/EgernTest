# Dr.COM × Egern 校园网流量小组件

## 功能

- 读取 `http://10.100.88.2/drcom/chkstatus` 的 JSON / JSONP 状态数据。
- `actdf` = 下行（下载）、`actuf` = 上行（上传）、`flow` = 总流量、`v4ip` = 校园网 IPv4。
- 按 KB（原始数字）换算成 MB/GB，兼容 B、MB 单位的学校变体。
- 自适应主屏幕小号、中号、大号和锁屏三个组件大小。
- 显示未认证 / 请求失败，不需要提供账户密码。

## CDN 模块安装（推荐）

模块地址：<https://cdn.jsdmirror.com/gh/Yoobohl/EgernTest@main/modules/drcom-egern/drcom.module.yaml>

脚本地址：<https://cdn.jsdmirror.com/gh/Yoobohl/EgernTest@main/modules/drcom-egern/drcom-widget.js>

1. Egern → 工具 → 模块 → +，填写上述模块地址并保存。
2. 启用模块，在模块的 Env 中按学校实际接口设置 `DRCOM_API_URL`，其余参数按需调整。
3. 在小组件画廊查看 `Dr.COM 校园网`，添加到桌面后选择该组件。

模块内的脚本 URL 已是绝对 CDN 地址，无需另行导入 JS。该模块可独立安装。

## 本地安装

1. Egern → 工具 → 脚本 → +，创建 **generic** 类型脚本，名称填写 `drcom-traffic-script`。
2. 文件位置选择「本地」，新建 `drcom-widget.js`，点击「编辑文件」，粘贴 `drcom-widget.js` 的全部代码并保存。
3. Egern → 分析 → 小组件画廊 → +，名称填 `Dr.COM 校园网`，脚本选择 `drcom-traffic-script`。
4. 在桌面添加 Egern 小组件，编辑并选择 `Dr.COM 校园网`。

这条路径不需要将任何文件上传到互联网；本地 Script + Widget 与模块声明产生相同的小组件效果。

## 模块安装

提供 `drcom.module.yaml` 模块。它包含 `generic` 脚本声明和小组件声明，默认从上述 CDN 加载脚本：

- **使用本地文件**：使用前述本地 Script + Widget 安装流程。
- **更换托管地址**：修改模块中的 `script_url` 为 JS 文件的绝对 HTTPS 地址，再导入模块 URL。
- 不需要配置 MITM，也不需要任何登录脚本。

## 可修改配置

- `DRCOM_API_URL`: 默认 `http://10.100.88.2/drcom/chkstatus?callback=dr1003&jsVersion=4.1&v=630&lang=zh`
- `TRAFFIC_UNIT`: 默认 `KB`，如果学校将流量按字节返回则改为 `B`；若直接是 MB 改为 `MB`。
- `REFRESH_MINUTES`: 默认 5；最小按 5 分钟处理。iOS 决定何时真正刷新小组件，不能保证每 5 分钟执行。

注意：以上流量属于 Dr.COM 认证网关记录的累计量，而非实时吞吐率。当前仅在手机能直接访问校园网内部地址时可用；蜂窝网络或其他 Wi-Fi 不能直连时会显示错误。脚本显式选用 `DIRECT` 策略，避免校园内网请求错误走代理。如无法请求，请在 Egern 内检查本地网络权限及 DIRECT 策略/规则。

## 示例接口结构（匿名化）

```js
// JSONP 包裹或纯 JSON 均能处理
// dr1003({"result":1,"v4ip":"10.251.7.109","actdf":3825,"actuf":2125,"flow":5950})
```

对应：下载约 3.74 MB、上传约 2.08 MB、总计约 5.81 MB。
