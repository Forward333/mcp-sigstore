# MCP Base64 Auto-Decode

自动检测文本中的 Base64 编码内容，解码并替换回原文。非 Base64 部分原样保留。

## 工具

| 工具 | 功能 |
|------|------|
| `detect_base64` | 扫描文本，报告所有 base64 段的位置和预览 |
| `decode_base64` | 扫描 + 自动解码替换，返回处理后的完整文本 |

## 安装

```bash
pip install -e .
```

## 配置

```json
{
  "mcpServers": {
    "base64-autodecode": {
      "command": "python3",
      "args": ["-m", "mcp_content_integrity.server"]
    }
  }
}
```

## 示例

LLM 对话：
> 用户：这段配置里有 base64，帮我解开
> 
> LLM 调用 `decode_base64(text="key: aGVsbG8gd29ybGQ=)`
> → `key: hello world`
