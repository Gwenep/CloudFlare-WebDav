// Web Crypto API 辅助函数
async function generateRandomString(length = 32) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// SHA-256 哈希函数
async function sha256(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// 安全相关配置
const RATE_LIMIT_WINDOW = 60 * 1000; // 1分钟窗口
const MAX_REQUESTS_PER_WINDOW = 60; // 每分钟最多60个请求
const MAX_UPLOAD_SIZE = 10 * 1024 * 1024; // 最大上传大小10MB

// 管理界面 HTML 模板已删除（不再需要管理功能）



// 请求速率限制实现（已禁用KV存储记录，避免生成rate_limit前缀的键）
async function applyRateLimit(request, env) {
  try {
    return null;
  } catch (error) {
    console.error('速率限制检查失败:', error);
    // 速率限制检查失败不应阻止请求，但应记录错误
    return null;
  }
}

// 处理请求的主函数
export default {
  async fetch(request, env, ctx) {
    try {
      // 应用请求速率限制
      const rateLimited = await applyRateLimit(request, env);
      if (rateLimited) {
        return rateLimited;
      }
      const url = new URL(request.url);
      const path = url.pathname;
      
      // 处理根路径
      if (path === '/') {
        return new Response('前面的区域请以后再来探索吧！', {
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
          }
        });
      }
      
      // 处理 WebDAV 请求，支持/dav路径
      try {
        // 检查是否是/dav路径的请求
        const isDavRequest = path.startsWith('/dav');
        
        if (isDavRequest) {
          // 对于/dav路径的请求，进行身份验证
          const authResult = await authenticateWebDAV(request, env);
          if (!authResult.authenticated) {
            return authResult.response;
          }
          
          // 去除/dav前缀，获取实际路径
          // 确保路径规范化，特别是处理根路径时
          const davPath = path === '/dav' || path === '/dav/' ? '/' : path.replace('/dav', '');
          
          // 处理 WebDAV 方法
          switch (request.method) {
            case 'OPTIONS':
              return handleOptions();
            case 'PROPFIND':
              return await handlePropfind(request, env, davPath);
            case 'GET':
              return await handleGet(env, davPath, request);
            case 'HEAD':
              // 处理HEAD请求，与GET类似但不返回内容
              const getResponse = await handleGet(env, davPath, request);
              return new Response(null, {
                headers: getResponse.headers,
                status: getResponse.status
              });
            case 'PUT':
              // 检查上传大小限制
              const contentLength = request.headers.get('Content-Length');
              if (contentLength && parseInt(contentLength) > MAX_UPLOAD_SIZE) {
                return new Response('上传文件过大', {
                  status: 413,
                  headers: {
                    'Content-Type': 'text/plain; charset=utf-8'
                  }
                });
              }
              return await handlePut(request, env, davPath);
            case 'DELETE':
              return await handleDelete(env, davPath);
            case 'MKCOL':
      return await handleMkcol(env, davPath);
    // 添加更多WebDAV方法支持
    case 'COPY':
    case 'MOVE':
    case 'PROPPATCH':
      // 这些方法对于Windows和某些客户端是必需的
      // 返回200但不阻止请求，允许客户端继续工作
      return new Response('方法不支持但允许继续', {
        status: 200,
        headers: {
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV',
          'Allow': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL',
          'X-Content-Type-Options': 'nosniff',
          'Content-Length': '0'
        }
      });
    default:
      // 为不支持的方法返回更友好的响应，确保移动文件管理器兼容性
      return new Response('方法不支持', { 
        status: 200,
        headers: {
          'Allow': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL',
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV',
          'X-Content-Type-Options': 'nosniff',
          'Content-Length': '0'
        }
      });
          }
        } else {
          // 非/dav路径返回404
          return new Response('Not Found', {
            status: 404,
            headers: {
              'Content-Type': 'text/plain; charset=utf-8'
            }
          });
        }
      } catch (error) {
        console.error('处理WebDAV请求时发生错误:', error);
        // 不向客户端暴露详细错误信息
        return new Response('服务器内部错误', {
          status: 500,
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'X-Content-Type-Options': 'nosniff'
          }
        });
      }
    } catch (error) {
      console.error('请求处理错误:', error);
      return new Response('内部服务器错误', { 
        status: 500,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }
  }
};

// WebDAV 认证函数
async function authenticateWebDAV(request, env) {
  try {
    const authHeader = request.headers.get('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      return {
        authenticated: false,
        response: new Response('WebDAV 需要认证', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="WebDAV Server"',
            'DAV': '1, 2',
            'Content-Type': 'text/plain; charset=utf-8'
          }
        })
      };
    }
    
    // 解码 Basic 认证凭据
    const encodedCredentials = authHeader.slice('Basic '.length);
    
    // 安全解码
    let decodedCredentials;
    try {
      decodedCredentials = atob(encodedCredentials);
    } catch (e) {
      console.error('凭据解码错误:', e);
      return {
        authenticated: false,
        response: new Response('无效的认证凭据', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="WebDAV Server"',
            'DAV': '1, 2',
            'Content-Type': 'text/plain; charset=utf-8'
          }
        })
      };
    }
    
    const separatorIndex = decodedCredentials.indexOf(':');
    if (separatorIndex === -1) {
      return {
        authenticated: false,
        response: new Response('无效的认证凭据格式', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="WebDAV Server"',
            'DAV': '1, 2',
            'Content-Type': 'text/plain; charset=utf-8'
          }
        })
      };
    }
    
    const username = decodedCredentials.substring(0, separatorIndex);
    const password = decodedCredentials.substring(separatorIndex + 1);
    
    // 验证凭据
     const isValid = await verifyWebDAVCredentials(env, username, password);
    
    if (!isValid) {
      return {
        authenticated: false,
        response: new Response('用户名或密码错误', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="WebDAV Server"',
            'DAV': '1, 2',
            'Content-Type': 'text/plain; charset=utf-8'
          }
        })
      };
    }
    
    return { authenticated: true };
  } catch (error) {
    console.error('WebDAV 认证错误:', error);
    return {
      authenticated: false,
      response: new Response('认证过程中出错', {
        status: 500,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8'
        }
      })
    };
  }
}

// 注意：generateCSRFToken函数已在文件顶部定义为异步版本，这里不再重复定义

// HTML 转义函数，防止 XSS
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// handleLoginPage 和 renderLoginPage 函数已删除（不再需要登录功能）






async function sha256Legacy(password, salt) {
  try {
    // 将密码和盐值转换为字节数组
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password + salt);
    
    // 计算哈希
    const hashBuffer = await crypto.subtle.digest('SHA-256', passwordData);
    
    // 转换为十六进制字符串
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return hashHex;
  } catch (error) {
    console.error('密码哈希计算失败:', error);
    throw error;
  }
}



// Web Crypto API 实现的 PBKDF2 函数
async function pbkdf2(password, salt, iterations, keySize) {
  try {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    const saltData = encoder.encode(salt);
    
    // 导入密码
    const importedKey = await crypto.subtle.importKey(
      'raw',
      passwordData,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );
    
    // 派生密钥
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltData,
        iterations: iterations,
        hash: 'SHA-256'
      },
      importedKey,
      keySize * 8 // 转换为位
    );
    
    // 转换为十六进制字符串
    const hexString = Array.from(new Uint8Array(derivedBits))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    return hexString;
  } catch (error) {
    console.error('PBKDF2 加密错误:', error);
    throw error;
  }
}

// 验证 WebDAV 凭据 - 直接从环境变量读取
async function verifyWebDAVCredentials(env, username, password) {
  try {
    // 直接从环境变量中获取WebDAV账号密码
    const envUsername = env.WEBDAV_USERNAME || 'default';
    const envPassword = env.WEBDAV_PASSWORD || 'default';
    
    // 简单的字符串匹配验证
    return username === envUsername && password === envPassword;
  } catch (error) {
    console.error('验证 WebDAV 凭证时出错:', error);
    return false;
  }
}

// 处理 WebDAV 请求
async function handleWebDAVRequest(request, env) {
  // 验证 WebDAV 账号密码
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return new Response('WebDAV 需要认证', {
      status: 401,
      headers: {
        'WWW-Authenticate': 'Basic realm="WebDAV Server"'
      }
    });
  }
  
  try {
    // 解码认证信息
    const encodedCredentials = authHeader.split(' ')[1];
    const decodedCredentials = atob(encodedCredentials);
    const [username, password] = decodedCredentials.split(':');
    
    // 验证账号密码
    const isValid = await verifyWebDAVCredentials(env, username, password);
    if (!isValid) {
      return new Response('认证失败', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="WebDAV Server"'
        }
      });
    }
  } catch (error) {
    console.error('WebDAV 认证错误:', error);
    return new Response('认证过程中发生错误', {
      status: 500
    });
  }
  
  // 基本的 WebDAV 方法处理
  const url = new URL(request.url);
  const path = url.pathname;
  
  switch (request.method) {
    case 'OPTIONS':
      return handleOptions();
    case 'PROPFIND':
      return handlePropfind(request, env, path);
    case 'GET':
        return handleGet(env, path, request);
    case 'PUT':
      return handlePut(request, env, path);
    case 'DELETE':
      return handleDelete(env, path);
    case 'MKCOL':
      return handleMkcol(env, path);
    default:
      return new Response('不支持的方法', { status: 501 });
  }
}

// 处理 OPTIONS 请求
function handleOptions() {
  return new Response(null, {
    headers: {
      'DAV': '1, 2, 3',
      'Allow': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL',
      'Accept-Ranges': 'bytes',
      'Content-Length': '0',
      'MS-Author-Via': 'DAV'
    }
  });
}

// 处理 PROPFIND 请求
async function handlePropfind(request, env, path) {
  try {
    // 规范化路径
    const normalizedPath = normalizePath(path);
    
    // 获取深度头，为手机文件管理器提供更好的兼容性
    const depthHeader = request.headers.get('Depth') || '1'; // 默认为1以显示目录内容
    const depth = depthHeader === 'infinity' ? -1 : parseInt(depthHeader) || 0;
    
    // 确保根目录存在
    await ensureRootDirectory(env);
    
    // 检查资源是否存在
    const resourceInfo = await getResourceInfo(env, normalizedPath);
    if (!resourceInfo) {
      return new Response('资源不存在', { status: 404 });
    }
    
    // 构建 XML 响应，使用完整的DAV命名空间
    let xmlBody = '<?xml version="1.0" encoding="utf-8" ?>\n<D:multistatus xmlns:D="DAV:">';
    
    // 添加当前资源的响应，传入完整的resourceInfo
    xmlBody += createResourceResponse(
      normalizedPath, 
      resourceInfo.type === 'directory', 
      new Date(resourceInfo.modifiedAt),
      resourceInfo
    );
    
    // 如果是深度遍历且是目录，列出子资源
    if ((depth > 0 || depth === -1) && resourceInfo.type === 'directory') {
      const children = await listDirectoryChildren(env, normalizedPath);
      
      for (const child of children) {
        const childPath = normalizedPath === '/' ? `/${child.name}` : `${normalizedPath}/${child.name}`;
        xmlBody += createResourceResponse(
          childPath, 
          child.type === 'directory', 
          new Date(child.modifiedAt),
          child
        );
      }
    }
    
    xmlBody += '</D:multistatus>';
    
    return new Response(xmlBody, {
      headers: {
        'Content-Type': 'application/xml',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV',
        'Content-Length': xmlBody.length.toString()
      }
    });
  } catch (error) {
    console.error('PROPFIND 处理错误:', error);
    return new Response('处理 PROPFIND 请求时出错', { status: 500 });
  }
}

// 创建资源响应 XML
function createResourceResponse(path, isDirectory, lastModified, resourceInfo = {}) {
  // 确保路径格式正确，添加绝对路径标记以兼容各种客户端
  const hrefPath = path.startsWith('/') ? path : `/${path}`;
  
  const resourceType = isDirectory ? '<D:resourcetype><D:collection/></D:resourcetype>' : '<D:resourcetype/>';
  const formattedDate = lastModified.toUTCString();
  const size = resourceInfo.size || (isDirectory ? 0 : undefined);
  
  // 为文件设置适当的内容类型
  let contentType = 'application/octet-stream';
  if (!isDirectory && resourceInfo.contentType) {
    contentType = resourceInfo.contentType;
  } else if (!isDirectory) {
    // 尝试根据文件扩展名猜测内容类型
    const extension = hrefPath.split('.').pop()?.toLowerCase();
    const extensionMimeTypes = {
      'txt': 'text/plain',
      'html': 'text/html',
      'htm': 'text/html',
      'css': 'text/css',
      'js': 'application/javascript',
      'json': 'application/json',
      'xml': 'application/xml',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
      'webp': 'image/webp',
      'pdf': 'application/pdf',
      'zip': 'application/zip',
      'rar': 'application/x-rar-compressed',
      '7z': 'application/x-7z-compressed',
      'mp3': 'audio/mpeg',
      'wav': 'audio/wav',
      'mp4': 'video/mp4',
      'avi': 'video/x-msvideo',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'xls': 'application/vnd.ms-excel',
      'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'ppt': 'application/vnd.ms-powerpoint',
      'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    };
    if (extension && extensionMimeTypes[extension]) {
      contentType = extensionMimeTypes[extension];
    }
  }
  
  // 生成更安全的ETag
  const etag = resourceInfo.etag || `"${formattedDate}-${size || 0}"`;
  
  // 获取显示名称
  const displayName = path.split('/').pop() || '/';
  
  // 为手机文件管理器和其他客户端提供全面的PROPFIND响应
  return `
    <D:response>
      <D:href>${hrefPath}</D:href>
      <D:propstat>
        <D:prop>
          ${resourceType}
          <D:getlastmodified>${formattedDate}</D:getlastmodified>
          <D:displayname>${displayName}</D:displayname>
          ${size !== undefined ? `<D:getcontentlength>${size}</D:getcontentlength>` : ''}
          <D:creationdate>${resourceInfo.createdAt ? new Date(resourceInfo.createdAt).toUTCString() : formattedDate}</D:creationdate>
          <D:getetag>${etag}</D:getetag>
          ${!isDirectory ? `<D:getcontenttype>${contentType}</D:getcontenttype>` : ''}
          <!-- Windows和手机文件管理器所需的额外属性 -->
          <D:iscollection>${isDirectory ? '1' : '0'}</D:iscollection>
          <!-- 标准WebDAV属性 -->
          <D:supportedlock></D:supportedlock>
          <D:lockdiscovery></D:lockdiscovery>
          <D:quota-available-bytes></D:quota-available-bytes>
          <D:quota-used-bytes></D:quota-used-bytes>
        </D:prop>
        <D:status>HTTP/1.1 200 OK</D:status>
      </D:propstat>
    </D:response>`;
}

// 处理 HEAD 请求
async function handleHead(env, path, request) {
  try {
    const normalizedPath = normalizePath(path);
    
    // 确保根目录存在
    await ensureRootDirectory(env);
    
    // 获取资源信息
    const resourceInfo = await getResourceInfo(env, normalizedPath);
    if (!resourceInfo) {
      return new Response(null, { 
        status: 404,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8'
        }
      });
    }
    
    // 检查是否是目录
    if (resourceInfo.type === 'directory') {
      // 对于目录，返回目录相关的头部
      return new Response(null, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Last-Modified': new Date(resourceInfo.modifiedAt).toUTCString(),
          'Accept-Ranges': 'bytes',
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV'
        }
      });
    }
    
    // 对于文件，获取元数据
    let metaData;
    try {
      metaData = await env.WEBDAV_STORAGE.get(`${normalizedPath}_meta`, 'json');
    } catch (e) {
      metaData = null;
    }
    
    // 确定内容类型
    const contentType = metaData?.contentType || getContentType(normalizedPath);
    
    // 创建响应头
    const headers = {
      'Content-Type': contentType,
      'Accept-Ranges': 'bytes',
      'Last-Modified': metaData?.modifiedAt ? new Date(metaData.modifiedAt).toUTCString() : new Date().toUTCString(),
      'DAV': '1, 2, 3',
      'MS-Author-Via': 'DAV'
    };
    
    // 添加文件大小信息，只使用元数据中的大小
    if (metaData?.size) {
      headers['Content-Length'] = metaData.size.toString();
    }
    
    // 返回空响应体的响应
    return new Response(null, {
      headers
    });
  } catch (error) {
    console.error('HEAD 处理错误:', error);
    return new Response(null, { 
      status: 500,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8'
      }
    });
  }
}

// 处理 GET 请求
async function handleGet(env, path, request) {
  try {
    const normalizedPath = normalizePath(path);
    
    // 确保根目录存在
    await ensureRootDirectory(env);
    
    // 获取资源信息
    const resourceInfo = await getResourceInfo(env, normalizedPath);
    if (!resourceInfo) {
      return new Response('文件不存在', { status: 404 });
    }
    
    // 检查是否是目录
    if (resourceInfo.type === 'directory') {
      // 如果是目录，返回目录列表的 HTML 页面
      return generateDirectoryListing(env, normalizedPath, resourceInfo);
    }
    
    // 从 KV 获取文件内容
    const content = await env.WEBDAV_STORAGE.get(normalizedPath, 'arrayBuffer');
    if (!content) {
      return new Response('文件不存在', { status: 404 });
    }
    
    // 获取文件元数据
    let metaData;
    try {
      metaData = await env.WEBDAV_STORAGE.get(`${normalizedPath}_meta`, 'json');
    } catch (e) {
      metaData = null;
    }
    
    // 确定内容类型
    const contentType = metaData?.contentType || getContentType(normalizedPath);
    
    // 创建响应头
    const headers = {
      'Content-Type': contentType,
      'Content-Length': content.byteLength.toString(), // 使用实际内容大小作为主要来源
      'Accept-Ranges': 'bytes',
      'Last-Modified': metaData?.modifiedAt ? new Date(metaData.modifiedAt).toUTCString() : new Date().toUTCString(),
      'Cache-Control': 'public, max-age=3600'
    };
    
    // 不再覆盖Content-Length，避免潜在的不一致
    // 使用实际读取的内容大小更准确且不需要额外KV访问
    
    // 处理 Range 请求（部分内容下载）
    const rangeHeader = request && request.headers ? request.headers.get('Range') : null;
    if (rangeHeader) {
      try {
        const rangeMatch = rangeHeader.match(/bytes=(\d+)-(\d*)/);
        if (rangeMatch) {
          const start = parseInt(rangeMatch[1]);
          const end = rangeMatch[2] ? parseInt(rangeMatch[2]) : content.byteLength - 1;
          
          if (start < content.byteLength && start <= end) {
            const rangeContent = content.slice(start, end + 1);
            headers['Content-Range'] = `bytes ${start}-${end}/${content.byteLength}`;
            headers['Content-Length'] = rangeContent.byteLength.toString();
            
            return new Response(rangeContent, {
              status: 206,
              headers
            });
          }
        }
      } catch (e) {
        console.error('处理 Range 请求失败:', e);
      }
    }
    
    return new Response(content, {
      headers
    });
  } catch (error) {
    console.error('GET 处理错误:', error);
    return new Response('下载文件时出错', { 
      status: 500,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8'
      }
    });
  }
}

// 生成目录列表 HTML
async function generateDirectoryListing(env, path, resourceInfo) {
  try {
    const children = await listDirectoryChildren(env, path);
    
    // 过滤掉任何可能的rate_limit记录
    const filteredChildren = children.filter(child => 
      !child.name.startsWith('rate_limit:')
    );
    
    let html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>目录列表 - ${path === '/' ? '根目录' : path}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    tr:hover { background-color: #f5f5f5; }
    a { color: #0366d6; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .dir { color: #0e7490; font-weight: bold; }
    .file { color: #4b5563; }
    .size { text-align: right; }
  </style>
</head>
<body>
  <h1>目录: ${path === '/' ? '根目录' : path}</h1>
  <table>
    <tr>
      <th>名称</th>
      <th>类型</th>
      <th class="size">大小</th>
      <th>修改时间</th>
    </tr>`;
    
    // 添加父目录链接
    if (path !== '/') {
      const parentPath = getParentPath(path);
      // 使用简单直接的方式构建父目录链接，确保不会出现双斜杠
      const parentLink = `/dav${parentPath}`.replace(/\/\//g, '/');
      html += `
      <tr>
        <td><a href="${parentLink}" class="dir">..</a></td>
        <td>目录</td>
        <td class="size">-</td>
        <td>-</td>
      </tr>`;
    }
    
    // 添加子资源
    for (const child of filteredChildren) {
      // 更精确的路径构建，避免根目录下出现双斜杠
      let fullLink;
      if (path === '/') {
        fullLink = `/dav/${child.name}`;
      } else {
        fullLink = `/dav${path}/${child.name}`;
      }
      // 最后再清理可能存在的双斜杠
      fullLink = fullLink.replace(/\/\//g, '/');
      const linkClass = child.type === 'directory' ? 'dir' : 'file';
      // 确保根目录下的子目录不会显示额外的斜杠
      const displayName = child.type === 'directory' ? `${child.name}/` : child.name;
      
      html += `
      <tr>
        <td><a href="${fullLink}" class="${linkClass}">${displayName}</a></td>
        <td>${child.type === 'directory' ? '目录' : '文件'}</td>
        <td class="size">${child.type === 'directory' ? '-' : (child.size ? formatFileSize(child.size) : '未知')}</td>
        <td>${new Date(child.modifiedAt).toLocaleString()}</td>
      </tr>`;
    }
    
    html += `
  </table>
</body>
</html>`;
    
    return new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache'
      }
    });
  } catch (error) {
    console.error('生成目录列表失败:', error);
    return new Response('无法生成目录列表', { status: 500 });
  }
}

// 处理 PUT 请求
async function handlePut(request, env, path) {
  try {
    const normalizedPath = normalizePath(path);
    
    // 确保根目录存在
    await ensureRootDirectory(env);
    
    // 读取请求体
    const content = await request.arrayBuffer();
    
    // 确保父目录存在
    const parentPath = getParentPath(normalizedPath);
    if (parentPath) {
      await ensureDirectoryExists(env, parentPath);
    }
    
    // 检查是否与现有目录冲突
    const existingInfo = await getResourceInfo(env, normalizedPath);
    if (existingInfo && existingInfo.type === 'directory') {
      return new Response('不能覆盖目录', { status: 409 });
    }
    
    // 保存文件内容
    await env.WEBDAV_STORAGE.put(normalizedPath, content);
    
    // 创建或更新文件元数据
    const now = new Date().toISOString();
    await env.WEBDAV_STORAGE.put(`${normalizedPath}_meta`, JSON.stringify({
      type: 'file',
      size: content.byteLength,
      modifiedAt: now,
      contentType: request.headers.get('Content-Type') || getContentType(normalizedPath)
    }));
    
    // 更新父目录修改时间
    await updateDirectoryTimestamp(env, parentPath);
    
    return new Response(null, { status: 201 });
  } catch (error) {
    console.error('PUT 处理错误:', error);
    return new Response('上传文件时出错', { status: 500 });
  }
}

// 处理 DELETE 请求
async function handleDelete(env, path) {
  try {
    const normalizedPath = normalizePath(path);
    
    // 禁止删除根目录
    if (normalizedPath === '/') {
      return new Response('不能删除根目录', { status: 403 });
    }
    
    // 检查资源是否存在
    const resourceInfo = await getResourceInfo(env, normalizedPath);
    if (!resourceInfo) {
      return new Response(null, { status: 404 });
    }
    
    if (resourceInfo.type === 'directory') {
      // 列出目录内容，检查是否为空
      const children = await listDirectoryChildren(env, normalizedPath);
      if (children.length > 0) {
        // 在 Cloudflare KV 中递归删除可能会有性能问题，这里简化处理
        // 实际应用中可能需要限制目录深度或实现异步删除队列
        return new Response('目录不为空', { status: 409 });
      }
      
      // 删除目录标记
      const dirPath = `${normalizedPath}_dir`;
      await env.WEBDAV_STORAGE.delete(dirPath);
    } else {
      // 删除文件内容和元数据
      await env.WEBDAV_STORAGE.delete(normalizedPath);
      await env.WEBDAV_STORAGE.delete(`${normalizedPath}_meta`);
    }
    
    // 更新父目录修改时间
    const parentPath = getParentPath(normalizedPath);
    await updateDirectoryTimestamp(env, parentPath);
    
    return new Response(null, { status: 204 });
  } catch (error) {
    console.error('DELETE 处理错误:', error);
    return new Response('删除文件时出错', { status: 500 });
  }
}

// 处理 MKCOL 请求（创建目录）
async function handleMkcol(env, path) {
  try {
    const normalizedPath = normalizePath(path);
    
    // 确保根目录存在
    await ensureRootDirectory(env);
    
    // 检查路径是否已存在
    const existingInfo = await getResourceInfo(env, normalizedPath);
    if (existingInfo) {
      return new Response('资源已存在', { status: 405 });
    }
    
    // 确保父目录存在
    const parentPath = getParentPath(normalizedPath);
    if (parentPath) {
      const parentInfo = await getResourceInfo(env, parentPath);
      if (!parentInfo || parentInfo.type !== 'directory') {
        return new Response('父目录不存在', { status: 409 });
      }
    }
    
    // 使用简化的目录存储方式，只创建一个目录标记
    const now = new Date().toISOString();
    const dirPath = `${normalizedPath}_dir`;
    
    await env.WEBDAV_STORAGE.put(dirPath, JSON.stringify({
      type: 'directory',
      createdAt: now,
      modifiedAt: now
    }));
    
    // 更新父目录修改时间
    await updateDirectoryTimestamp(env, parentPath);
    
    return new Response(null, { status: 201 });
  } catch (error) {
    console.error('MKCOL 处理错误:', error);
    return new Response('创建目录时出错', { status: 500 });
  }
}

// 辅助函数：规范化路径
function normalizePath(path) {
  // 防止空路径或null/undefined
  if (!path) return '/';
  
  // 确保路径以 / 开头
  let normalized = path.startsWith('/') ? path : '/' + path;
  
  // 移除连续的斜杠
  normalized = normalized.replace(/\/+/g, '/');
  
  // 对于Windows和SCP兼容性，保留末尾斜杠用于目录（某些客户端需要这个）
  // 但在内部处理时保持一致性
  const isDirectoryPath = path.endsWith('/') && normalized !== '/';
  if (!isDirectoryPath && normalized !== '/' && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  
  // 确保路径不为空
  if (normalized === '') return '/';
  
  return normalized;
}

// 辅助函数：获取父路径
function getParentPath(path) {
  if (path === '/') return null;
  const parts = path.split('/').filter(Boolean);
  if (parts.length === 0) return '/';
  return '/' + parts.slice(0, -1).join('/');
}

// 安全地连接路径部分，避免双斜杠
function joinPath(base, path) {
  if (!base) return `/${path}`;
  if (!path) return base;
  
  const baseClean = base.endsWith('/') ? base.slice(0, -1) : base;
  const pathClean = path.startsWith('/') ? path.slice(1) : path;
  
  const result = `${baseClean}/${pathClean}`;
  // 确保结果规范化，移除连续斜杠
  return result.replace(/\/+/g, '/');
}

// 格式化文件大小为人类可读格式
function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 辅助函数：确保目录存在
async function ensureDirectoryExists(env, path) {
  if (!path || path === '/') return;
  
  // 简化目录存储，只使用统一的目录标记方式
  const dirPath = `${path}_dir`;
  const dirExists = await env.WEBDAV_STORAGE.get(dirPath) !== null;
  
  if (!dirExists) {
    // 递归创建父目录
    const parentPath = getParentPath(path);
    if (parentPath) {
      await ensureDirectoryExists(env, parentPath);
    }
    
    // 只创建一个目录标记
    await env.WEBDAV_STORAGE.put(dirPath, JSON.stringify({
      type: 'directory',
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString()
    }));
  }
}

// 辅助函数：更新目录时间戳
async function updateDirectoryTimestamp(env, path) {
  if (!path) return;
  
  try {
    // 使用新的目录标记方式更新时间戳
    const dirPath = path === '/' ? '/_dir' : `${path}_dir`;
    const dirInfo = await env.WEBDAV_STORAGE.get(dirPath, 'json');
    
    if (dirInfo && dirInfo.type === 'directory') {
      dirInfo.modifiedAt = new Date().toISOString();
      await env.WEBDAV_STORAGE.put(dirPath, JSON.stringify(dirInfo));
    }
  } catch (error) {
    console.error('更新目录时间戳失败:', error);
  }
}

// 确保根目录存在
async function ensureRootDirectory(env) {
  try {
    const rootDirPath = '/_dir';
    const rootExists = await env.WEBDAV_STORAGE.get(rootDirPath) !== null;
    
    if (!rootExists) {
      // 只创建一个根目录标记
      await env.WEBDAV_STORAGE.put(rootDirPath, JSON.stringify({
        type: 'directory',
        createdAt: new Date().toISOString(),
        modifiedAt: new Date().toISOString()
      }));
    }
  } catch (error) {
    console.error('初始化根目录失败:', error);
    throw error;
  }
}

// 获取资源信息
async function getResourceInfo(env, path) {
  try {
    // 确保路径不为空
    if (!path || path === '') {
      console.error('getResourceInfo: 无效的空路径');
      return null;
    }
    
    // 检查是否是目录
    const dirPath = path === '/' ? '/_dir' : `${path}_dir`;
    const dirInfo = await env.WEBDAV_STORAGE.get(dirPath, 'json');
    if (dirInfo && dirInfo.type === 'directory') {
      return dirInfo;
    }
    
    // 检查是否是文件（尝试获取元数据）
    const metaPath = `${path}_meta`;
    const metaInfo = await env.WEBDAV_STORAGE.get(metaPath, 'json');
    if (metaInfo && metaInfo.type === 'file') {
      return metaInfo;
    }
    
    // 检查文件内容是否存在
    const contentExists = await env.WEBDAV_STORAGE.get(path) !== null;
    if (contentExists) {
      // 如果文件内容存在但元数据不存在，创建基本元数据
      const basicInfo = {
        type: 'file',
        modifiedAt: new Date().toISOString()
      };
      return basicInfo;
    }
    
    return null;
  } catch (error) {
    console.error('获取资源信息失败:', error);
    return null;
  }
}

// 列出目录子资源
async function listDirectoryChildren(env, path) {
  try {
    // 确保路径不为空
    if (!path || path === '') {
      console.error('listDirectoryChildren: 无效的空路径');
      return [];
    }
    
    // 规范化路径
    const normalizedPath = normalizePath(path);
    
    // 存储已处理的子资源名称，避免重复
    const processedChildren = new Set();
    const children = [];
    
    // 构建前缀
    const prefix = normalizedPath === '/' ? '' : `${normalizedPath}/`;
    
    // 列出所有匹配前缀的键
    const listResult = await env.WEBDAV_STORAGE.list({
      prefix: prefix,
      limit: 1000 // 设置合理的限制，避免一次性加载太多项
    });
    
    // 首先处理目录标记
    for (const key of listResult.keys) {
      // 跳过元数据、速率限制记录和非目录标记
      if (key.name.endsWith('_meta') || key.name.startsWith('rate_limit:') || !key.name.endsWith('_dir')) continue;
      
      let dirName;
      if (normalizedPath === '/') {
        // 根目录下的目录标记格式为：${dirname}_dir
        dirName = key.name.slice(0, -4); // 移除_dir后缀
      } else {
        // 子目录下的目录标记格式为：${path}/${dirname}_dir
        const relativePath = key.name.substring(prefix.length);
        const lastUnderscoreIndex = relativePath.lastIndexOf('_');
        dirName = relativePath.substring(0, lastUnderscoreIndex);
      }
      
      // 确保目录名有效且未被处理过，并且不是完整路径
      if (!dirName || processedChildren.has(dirName) || 
          (normalizedPath !== '/' && dirName.includes('/'))) continue;
      
      // 获取目录信息
      const dirInfo = await env.WEBDAV_STORAGE.get(key.name, 'json');
      if (dirInfo || true) { // 如果没有dirInfo也认为是目录，确保能显示目录
        processedChildren.add(dirName);
        children.push({
          name: dirName,
          type: 'directory',
          modifiedAt: dirInfo?.modifiedAt || new Date().toISOString(),
          size: 0, // 为目录设置大小为0，而不是undefined
          contentType: 'httpd/unix-directory'
        });
      }
    }
    
    // 然后处理文件
    for (const key of listResult.keys) {
      // 跳过元数据、目录标记、速率限制记录和已经处理过的资源
      if (key.name.endsWith('_meta') || key.name.endsWith('_dir') || 
          key.name.startsWith('rate_limit:') || processedChildren.has(key.name)) continue;
      
      // 对于根目录，检查是否为顶级文件
      if (normalizedPath === '/') {
        // 检查是否存在对应的目录标记
        const potentialDirMark = `${key.name}_dir`;
        const isDirectory = listResult.keys.some(k => k.name === potentialDirMark);
        
        if (!isDirectory) {
          // 确保不是子目录中的文件路径
          if (!key.name.includes('/')) {
            processedChildren.add(key.name);
            
            // 获取文件元数据
            let metaData;
            try {
              metaData = await env.WEBDAV_STORAGE.get(`${key.name}_meta`, 'json');
            } catch (e) {
              metaData = null;
            }
            
            // 只使用元数据中的大小信息，避免额外的KV访问
            const fileSize = metaData?.size || 0;
            
            children.push({
              name: key.name,
              type: 'file',
              modifiedAt: metaData?.modifiedAt || new Date().toISOString(),
              size: fileSize,
              contentType: metaData?.contentType
            });
          }
        }
      } else {
        // 子目录下的文件处理
        const relativePath = key.name.substring(prefix.length);
        
        // 只处理直接子文件（不包含子目录内的文件）
        if (!relativePath.includes('/')) {
          processedChildren.add(relativePath);
          
          // 获取文件元数据
          let metaData;
          try {
            metaData = await env.WEBDAV_STORAGE.get(`${key.name}_meta`, 'json');
          } catch (e) {
            metaData = null;
          }
          
          // 只使用元数据中的大小信息，避免额外的KV访问
          const fileSize = metaData?.size || 0;
          
          children.push({
            name: relativePath,
            type: 'file',
            modifiedAt: metaData?.modifiedAt || new Date().toISOString(),
            size: fileSize,
            contentType: metaData?.contentType
          });
        }
      }
    }
    
    // 按名称排序，目录在前，文件在后
    children.sort((a, b) => {
      if (a.type === 'directory' && b.type === 'file') return -1;
      if (a.type === 'file' && b.type === 'directory') return 1;
      return a.name.localeCompare(b.name);
    });
    
    return children;
  } catch (error) {
    console.error('列出目录子资源失败:', error);
    return [];
  }
}

// 获取内容类型
function getContentType(path) {
  const ext = path.split('.').pop().toLowerCase();
  const mimeTypes = {
    'txt': 'text/plain',
    'html': 'text/html',
    'js': 'application/javascript',
    'json': 'application/json',
    'css': 'text/css',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'pdf': 'application/pdf',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  };
  
  return mimeTypes[ext] || 'application/octet-stream';
}