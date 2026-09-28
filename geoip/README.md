# 此目录用于放置 MaxMind GeoLite2-City.mmdb 离线库
# 放置后把 .env 中 GEOIP_DB_PATH 指向容器内路径 /app/geoip/GeoLite2-City.mmdb 即可
# 未配置时会退化为在线解析（ip-api.com），内网环境可设置 GEOIP_ONLINE_FALLBACK=false 关闭
