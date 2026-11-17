# pairwise-secret-scan

密钥扫描一推上 CI，历史提交里全是误报：高熵检测把压缩文件和哈希 ID 当成密钥；Base64 只解一层，嵌套编码的 token 漏掉；私钥只匹配 BEGIN 头，PKCS#8 和 OpenSSH 格式没有覆盖；allowlist 按文件路径忽略，同文件里新加的密钥也被跳过；多行凭证只扫单行，YAML 块和 .env 续行断开；命中后没有做有效性验证，已吊销的旧 key 仍报高危。security/secret_scan.py 是核心，tests/test_secret_scan.py 15个红。要修的是：熵+上下文；递归解码；多私钥格式；行级 allowlist；多行聚合；吊销/有效性校验。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
