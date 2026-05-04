# MCP-sigstore: Distribution Integrity for MCP Ecosystem

MCP Server 实现 MCP App 分发完整性验证——相当于为 MCP 生态做的 Sigstore 级别方案。

## 背景

当前 MCP App 从 GitHub 仓库到用户本地安装的整个分发链路上，四个环节均无完整性验证：
1. **GitHub → Market 注册**：Market 不验证仓库所有权
2. **GitHub → npm/PyPI 发布**：provenance 覆盖率极低
3. **npm/PyPI → 用户安装**：安装命令普遍无版本锁定
4. **Market 元数据 ↔ 实际代码**：无机器可验证的绑定

本 MCP Server 提供工具来自动化检测和验证这些链路。

## 工具列表

| 工具 | 描述 | 对应链路 |
|------|------|----------|
| `verify_github_ownership` | 验证 GitHub 仓库实际 owner 与 Market 声称的作者是否一致 | 链路 1 |
| `check_npm_provenance` | 检查 npm 包是否有 provenance attestation | 链路 2 |
| `check_version_locking` | 解析安装命令是否包含版本锁定 | 链路 3 |
| `scan_mcp_app` | 全链路完整性扫描——一次调用检查所有四个环节 | 全链路 |
| `generate_integrity_manifest` | 生成带签名的完整性清单 | Phase 2 L1 |
| `verify_integrity_manifest` | 验证签署的完整性清单 | Phase 2 L1 |

## 安装

```bash
pip install -e .
```

## 配置 MCP Client

```json
{
  "mcpServers": {
    "mcp-sigstore": {
      "command": "python3",
      "args": ["-m", "mcp_sigstore.server"],
      "env": {
        "GITHUB_TOKEN": "<optional, for higher rate limits>"
      }
    }
  }
}
```

## 与研究的关系

基于 Forward333/MCP_app 的 `01_distribution_integrity.md` 分析设计。
实现 Phase 2（完整性方案设计）中描述的 L1/L2/L3 验证层。
