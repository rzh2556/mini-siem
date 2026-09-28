# ---------- 第一阶段：安装依赖并构建前端静态资源 ----------
FROM node:20-alpine AS builder

WORKDIR /app

# 先复制依赖描述文件，便于利用 Docker 层缓存
COPY package*.json ./
# 使用国内镜像源加速依赖安装
RUN npm install --registry=https://registry.npmmirror.com

# 复制源码并执行生产构建，产物输出到 /app/dist
COPY . .
RUN npm run build

# ---------- 第二阶段：使用 Nginx 托管静态资源并反向代理后端 ----------
FROM nginx:alpine

# 拷贝构建产物到 Nginx 默认站点目录
COPY --from=builder /app/dist /usr/share/nginx/html
# 覆盖默认站点配置（SPA history 回退 + /api 反向代理 + gzip）
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
