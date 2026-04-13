JEP Guard Python Extension with Test Runner
简介

这是 JEP Guard 的 Python 移植与扩展版本，实现了一个不依赖特定框架的智能体/CLI 主动防御核心。它通过拦截高危指令、请求人工确认并签发临时 Token 来提供“责任层”。该项目附带了一个完整的自动化 Test Runner 模拟器，无需真实部署即可在终端中测试整个攻防与日志记录生命周期。

功能包括：

高风险命令拦截：默认监控并拦截 rm, rmdir, mv, cp, format, dd, truncate 等危险操作。

用户交互确认机制：拦截后挂起进程，通过 CLI 终端提示用户选择（允许一次/拒绝/设置）。

临时令牌授权：用户允许后签发 5 分钟有效期的临时 Token，放入环境变量，实现短期免打扰放行。

隐私分级审计日志：自动记录操作日志，支持 minimal（仅命令）、normal（参数脱敏）、verbose（全量记录）三级隐私控制。

模拟 JEP 收据签名：内置 keygen 机制生成私钥，并利用 hashlib 和 secrets 生成不可抵赖的加密审计凭证。

完整的测试模拟器：内置 MockClawContext 和生命周期管理，一键演示安装、拦截、放行、导出、卸载全流程。

文件结构

安装与依赖

安装 Python 3.x（推荐 Python 3.7 及以上版本）。

纯标准库实现：本作完全基于 Python 内置标准库开发（os, json, hashlib, secrets, uuid），无需安装任何第三方依赖（pip install），开箱即用。

使用方法

运行测试模拟器：

运行后，程序将按照以下流程在终端与你进行交互式测试：

模拟安装：提示隐私警告，自动生成配置文件。

生成密钥：提示生成用于签署收据的模拟 Ed25519 密钥对。

测试安全命令：系统尝试执行 ls -la，自动静默放行并记录日志。

测试高危拦截：系统尝试执行 rm secret.txt，触发警告拦截，需手动输入 1 允许执行，系统将注入 Token。

测试令牌复用：系统再次执行 rm，验证 Token 有效期内自动放行机制。

导出日志：自动将脱敏后的审计日志导出为本地 JSON 文件。

模拟卸载：提示是否彻底清除日志与配置残留。

扩展与改写

本项目设计高度模块化，非常适合作为智能体防火墙的底层二次开发：

自定义风险库：直接修改 jep_guard.py 顶部的 HIGH_RISK_COMMANDS 列表，加入你需要拦截的特定 Agent 工具调用。

UI 交互层改写：重写 test_runner.py 中的 MockUI 类，将终端 input() 替换为真实的 Web 弹窗（WebSocket）、桌面 GUI（Tkinter/PyQt）或钉钉/企微的审批流接口。

强化密码学引擎：目前 generate_receipt 使用 secrets.token_hex 进行模拟，在生产环境中，可引入 PyNaCl 库替换为真实的 Ed25519 椭圆曲线签名。

持久化存储：重写 ConfigManager 和 log_action，将本地文件 I/O 改写为对接 MySQL、MongoDB 或 Redis 数据库。
