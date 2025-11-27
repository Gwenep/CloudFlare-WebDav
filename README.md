# Cloudflare WebDAV文件服务

基于 Cloudflare Workers 和 KV 存储的 WebDAV 文件服务器实现，支持跨平台访问文件，无需绑卡开通R2存储。

## 功能特性

- ✅ 完整的 WebDAV 协议支持（PROPFIND、GET、PUT、DELETE、MKCOL、HEAD）
- ✅ 跨平台兼容性（支持 Windows 文件资源管理器、手机文件管理器等）
- ✅ 基于 Cloudflare Workers 和 KV 存储，全球边缘分发
- ✅ 基本认证保护
- ✅ 目录浏览功能
- ✅ 支持 Range 请求（断点续传）
- ✅ 优化的 KV 访问策略，减少不必要的请求
- ✅ 支持 Windows 客户端兼容性（MS-Author-Via 头部）
- ✅ 支持多种 DAV 版本（1, 2, 3）

## 部署要求

- Cloudflare 账号

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/yourusername/cloudflare-webdav.git
cd cloudflare-webdav
```

### 2. 安装依赖

```bash
npm install -g wrangler
```

### 3. 配置 KV 命名空间

创建一个 KV 命名空间用于存储文件和元数据：

```bash
wrangler kv:namespace create WEBDAV_STORAGE
```

### 4. 配置项目

编辑 `wrangler.toml` 文件，填入你的 Cloudflare 账号信息和 KV 命名空间 ID。

### 5. 设置认证信息

在部署前，你需要在环境变量中，设置WEBDAV_USERNAME 和 WEBDAV_PASSWORD 用户名和密码。

### 6. 部署项目

```bash
wrangler publish
```

## 客户端配置

### Windows 文件资源管理器（谨慎！存在严重的kv读取问题，频繁进行kv读取）

1. 打开文件资源管理器
2. 右键点击"此电脑"，选择"映射网络驱动器"
3. 在文件夹输入框中，输入：`\\your-worker-name.your-username.workers.dev@SSL\dav`
4. 勾选"使用其他凭据连接"
5. 输入你设置的用户名和密码

### macOS Finder

1. 打开 Finder
2. 点击"前往" > "连接服务器"
3. 输入：`https://your-worker-name.your-username.workers.dev`
4. 点击"连接"，输入用户名和密码

### 手机文件管理器

大多数支持 WebDAV 的手机文件管理器都可以连接：

- 服务器地址：`https://your-worker-name.your-username.workers.dev`
- 用户名：你设置的用户名
- 密码：你设置的密码

## 注意事项

1. **文件大小限制**：受 Cloudflare KV限制，单个文件大小建议不超过 10MB
2. **KV 存储空间**：注意监控你的 KV 存储空间使用情况
3. **认证安全**：确保设置强密码，考虑使用 HTTPS 连接
4. **性能优化**：对于大量文件操作，建议批量处理以减少 KV 请求次数
5. **错误处理**：遇到连接问题时，检查网络设置和防火墙配置

## 常见问题

### Q: 连接时提示认证失败
A: 检查用户名和密码是否正确，确保在代码中正确配置了 `WEBDAV_USERNAME` 和 `WEBDAV_PASSWORD` 变量。

### Q: 目录下无法看到文件
A: 确保 KV 命名空间正确配置，检查目录结构是否正确

### Q: 文件上传失败
A: 检查文件大小是否超过限制，确保 KV 存储空间充足

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目！