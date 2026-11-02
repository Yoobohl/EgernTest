---
source: "https://egernapp.com/docs/example/proxy/"
---

# Egern as a Proxy Tool

Egern can serve as a proxy tool to route network traffic. The following examples demonstrate how to add a proxy server and use a remote proxy subscription.

## Using a Proxy Server

### Adding a Shadowsocks Proxy Server

Click `Tools` -> `Proxies` -> `+`, fill in `Name`, `Server`, `Port`, `Method`, and `Password`, then click Save.

![Adding a Shadowsocks Proxy Server](../../assets/a7857240a3973d.png)

### Adding the Proxy Server to a Policy Group

Click `Policy Groups` -> `Proxy` -> `ss` -> `Save`.

![Adding the Proxy Server to a Policy Group](../../assets/8ce43fb240571a.png)

## Using a Remote Proxy Subscription URL

### Changing Proxy to an External Policy Group

Click `Policy Groups` -> `Proxy` -> `Type` -> `External` -> `Add New URL`, enter the remote proxy's URL address, and click `Save`.

![Changing Proxy to an External Policy Group](../../assets/3051d3a3b4dc3e.png)
